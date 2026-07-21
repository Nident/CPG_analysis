from __future__ import annotations

import json
import os
import sys
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, cast

import yaml

from sink_finder_pipe.graph import CPGGraph
from sink_finder_pipe.rules import SinkFinderRules
from utils.env_utils import env_optional_int, env_path, load_env


class ContextExpansionPipeline:
    def __init__(self, project_dir: Path) -> None:
        self.project_dir = project_dir
        load_env(os.getenv("CONTEXT_EXPANDER_ENV_FILE", str(project_dir / "config" / "context_expander.env")))
        self.cpg_path = self.project_path(env_path("CONTEXT_EXPANDER_CPG"))
        self.sources_path = self.project_path(env_path("CONTEXT_EXPANDER_SOURCES"))
        self.sink_paths_dir = self.project_path(env_path("CONTEXT_EXPANDER_SINK_PATHS"))
        self.output_dir = self.project_path(env_path("CONTEXT_EXPANDER_OUTPUT"))
        self.rules_path = self.project_path(env_path("CONTEXT_EXPANDER_RULES"))
        self.limit = env_optional_int("CONTEXT_EXPANDER_LIMIT")
        self.rules = self.read_yaml(self.rules_path)
        self.sink_rules = SinkFinderRules(self.project_path(Path(self.rules["sink_rules"])))

    def run(self) -> dict[str, Any]:
        graph = CPGGraph(self.cpg_path, self.sink_rules)
        sources = self.sources()
        if self.limit is not None:
            sources = sources[: self.limit]
        sink_records = {sink["nodeId"]: graph.sink_record(sink) for sink in graph.find_sink_candidates()}
        expander = ContextExpander(graph, self.rules, sink_records, self.sink_path_index())
        workers = self.int_value(self.rules["search"]["parallel_workers"], "search.parallel_workers")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(expander.analyze_source, source, index): (source, index) for index, source in enumerate(sources, start=1)}
            for done, future in enumerate(as_completed(futures), start=1):
                source, index = futures[future]
                try:
                    record = future.result()
                except Exception as error:
                    record = self.error_record(source, index, error)
                output_file = self.output_dir / self.source_filename(record)
                self.write_json(output_file, record)
                results.append({"index": index, "sourceNodeId": record.get("sourceNodeId"), "status": record["status"], "file": output_file.name})
                print(f"[{done}/{len(sources)}] saved {record['status']} sourceNodeId={record.get('sourceNodeId')} -> {output_file}", file=sys.stderr)

        summary = {
            "status": "ok",
            "sourcesFile": str(self.sources_path),
            "cpgFile": str(self.cpg_path),
            "sinkPathsDir": str(self.sink_paths_dir),
            "rulesFile": str(self.rules_path),
            "outputDir": str(self.output_dir),
            "sourceCount": len(sources),
            **self.rules["search"],
            "results": sorted(results, key=lambda item: item["index"]),
        }
        self.write_json(self.output_dir / self.rules["output"]["summary_file"], summary)
        return summary

    def sink_path_index(self) -> dict[int, dict[str, Any]]:
        index: dict[int, dict[str, Any]] = {}
        if not self.sink_paths_dir.exists():
            return index
        for path in sorted(self.sink_paths_dir.glob("*_ok.json")):
            data = self.read_json(path)
            source_id = data.get("sourceNodeId")
            if isinstance(source_id, int):
                index[source_id] = data
        return index

    def sources(self) -> list[dict[str, Any]]:
        data = self.read_json(self.sources_path)
        return [self.object_value(item, "candidateSource") for item in self.list_value(data["candidateSources"], "candidateSources")]

    def source_filename(self, record: dict[str, Any]) -> str:
        node_id = record.get("sourceNodeId")
        node_part = f"node_{node_id}" if isinstance(node_id, int) else "node_unknown"
        return self.rules["output"]["source_file"].format(index=record["index"], node_part=node_part, status=record["status"])

    @staticmethod
    def error_record(source: dict[str, Any], index: int, error: Exception) -> dict[str, Any]:
        return {"status": "error", "index": index, "sourceNodeId": source.get("nodeId") if isinstance(source.get("nodeId"), int) else None, "source": source, "error": {"type": type(error).__name__, "message": str(error)}}

    def project_path(self, path: Path) -> Path:
        return path if path.is_absolute() else self.project_dir / path

    @staticmethod
    def read_json(path: Path) -> dict[str, Any]:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError(f"{path}: expected JSON object")
        return cast(dict[str, Any], data)

    @staticmethod
    def read_yaml(path: Path) -> dict[str, Any]:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError(f"{path}: expected YAML object")
        return cast(dict[str, Any], data)

    @staticmethod
    def write_json(path: Path, data: Any) -> None:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def object_value(value: Any, name: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError(f"{name} must be an object")
        return cast(dict[str, Any], value)

    @staticmethod
    def list_value(value: Any, name: str) -> list[Any]:
        if not isinstance(value, list):
            raise TypeError(f"{name} must be a list")
        return value

    @staticmethod
    def int_value(value: Any, name: str) -> int:
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an int")
        return value


class ContextExpander:
    def __init__(self, graph: CPGGraph, rules: dict[str, Any], sink_records: dict[int, dict[str, Any]], sink_paths: dict[int, dict[str, Any]]) -> None:
        self.graph = graph
        self.rules = rules
        self.sink_records = sink_records
        self.sink_paths = sink_paths
        self.max_depth = rules["search"]["max_depth"]
        self.max_nodes = rules["search"]["max_nodes"]
        self.max_sinks = rules["search"]["max_sinks"]

    def analyze_source(self, source: dict[str, Any], index: int) -> dict[str, Any]:
        source_id = self.source_node_id(source)
        seeds = self.expansion_seeds(source)
        downstream = self.downstream_sink_paths(seeds)
        visited = {seed["node"]["nodeId"] for seed in seeds} | {step["node"]["nodeId"] for path in downstream for step in path["path"]}
        return {
            "status": "ok",
            "index": index,
            "sourceNodeId": source_id,
            "source": source,
            "expansionSeeds": seeds,
            "downstreamSinkPaths": downstream,
            "interestingFieldAccesses": self.interesting_field_accesses(visited),
            "structuredParseCalls": self.structured_parse_calls(visited),
            "functionContexts": self.function_contexts(seeds, downstream),
            "search": {**self.rules["search"], "edgeTypes": self.rules["forward_edges"]["edge_types"]},
        }

    def expansion_seeds(self, source: dict[str, Any]) -> list[dict[str, Any]]:
        seen: set[int] = set()
        seeds: list[dict[str, Any]] = []

        def add(node_id: int, role: str) -> None:
            if node_id in seen or node_id not in self.graph.nodes_by_id:
                return
            seen.add(node_id)
            seeds.append({"role": role, "node": self.graph.node_summary(node_id, self.rules["nodes"]["seed_max_code_chars"])})

        for rule in self.rules["source_seeds"]:
            kind = rule["type"]
            if kind == "source":
                add(self.source_node_id(source), rule["role"])
            elif kind == "object_field":
                value = source.get(rule["field"])
                if isinstance(value, dict) and isinstance(value.get(rule["node_id_key"]), int):
                    add(value[rule["node_id_key"]], rule["role"])
            elif kind == "list_field":
                for item in source.get(rule["field"], []) if isinstance(source.get(rule["field"], []), list) else []:
                    if isinstance(item, dict) and isinstance(item.get(rule["node_id_key"]), int):
                        add(item[rule["node_id_key"]], rule["role"])
            elif kind == "related_uses":
                self.add_related_use_seeds(source, rule, add)
            elif kind == "sink_path_evidence":
                self.add_sink_path_seeds(self.sink_paths.get(self.source_node_id(source)), rule, add)
            else:
                raise ValueError(f"unsupported context seed type: {kind}")
        return seeds

    @staticmethod
    def add_related_use_seeds(source: dict[str, Any], rule: dict[str, Any], add: Any) -> None:
        for item in source.get(rule["field"], []) if isinstance(source.get(rule["field"], []), list) else []:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get(rule["node_id_key"]), int):
                add(item[rule["node_id_key"]], rule["role"])
            for parent in item.get(rule["parent_field"], []) if isinstance(item.get(rule["parent_field"], []), list) else []:
                if isinstance(parent, dict) and isinstance(parent.get(rule["parent_node_id_key"]), int):
                    add(parent[rule["parent_node_id_key"]], rule["parent_role"])

    @staticmethod
    def add_sink_path_seeds(sink_paths: dict[str, Any] | None, rule: dict[str, Any], add: Any) -> None:
        if sink_paths is None:
            return
        for path in sink_paths.get("paths", []) if isinstance(sink_paths.get("paths", []), list) else []:
            if not isinstance(path, dict):
                continue
            sink = path.get("sink", {})
            if isinstance(sink, dict) and sink.get("kind") == rule["structured_sink_kind"] and isinstance(sink.get("nodeId"), int):
                add(sink["nodeId"], rule["structured_role"])
            evidence = path.get("evidence", {})
            if isinstance(evidence, dict):
                for node_id in evidence.get(rule["argument_ids_field"], []):
                    if isinstance(node_id, int):
                        add(node_id, rule["argument_role"])
                for node_id in evidence.get(rule["dependency_ids_field"], []):
                    if isinstance(node_id, int):
                        add(node_id, rule["dependency_role"])

    def downstream_sink_paths(self, seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        found: set[int] = set()
        best_depth: dict[int, int] = {}
        queue: deque[tuple[int, list[dict[str, Any]], int]] = deque()
        for seed in seeds:
            node_id = seed["node"]["nodeId"]
            queue.append((node_id, [{"edgeFromPrevious": None, "node": seed["node"]}], 0))
            best_depth[node_id] = 0
        while queue and len(best_depth) <= self.max_nodes and len(results) < self.max_sinks:
            node_id, path, depth = queue.popleft()
            if node_id in self.sink_records and node_id not in found:
                found.add(node_id)
                results.append({"sink": self.sink_records[node_id], "pathLength": len(path), "edgeTypeCounts": self.edge_counts(path), "path": path})
                if self.sink_records[node_id]["kind"] != "structured_parse":
                    continue
            if depth >= self.max_depth:
                continue
            for edge in self.forward_edges(node_id):
                target = edge["to"]
                next_depth = depth + 1
                if best_depth.get(target, 10**9) <= next_depth:
                    continue
                best_depth[target] = next_depth
                queue.append((target, path + [{"edgeFromPrevious": {"type": edge["type"], "direction": "forward"}, "node": self.graph.node_summary(target, self.rules["nodes"]["path_max_code_chars"])}], next_depth))
        return results

    def forward_edges(self, node_id: int) -> list[dict[str, Any]]:
        if self.external_declaration(node_id):
            return []
        config = self.rules["forward_edges"]
        edge_types = set(config["edge_types"])
        result: list[dict[str, Any]] = []
        for edge in self.graph.outgoing.get(node_id, []):
            if edge.get("type") not in edge_types:
                continue
            if edge.get("type") == "PDG" and self.edge_dependence(edge) != config["pdg_dependence"]:
                continue
            target = edge["endNode"]
            if isinstance(target, int) and target in self.graph.nodes_by_id:
                result.append({"to": target, "type": edge["type"]})
        return result

    def external_declaration(self, node_id: int) -> bool:
        config = self.rules["forward_edges"]["stop_external_declarations"]
        summary = self.graph.node_summary(node_id)
        return summary["artifact"] is None and not set(config["labels_any"]).isdisjoint(self.graph.node_labels(node_id))

    def interesting_field_accesses(self, node_ids: set[int]) -> list[dict[str, Any]]:
        config = self.rules["interesting_field_accesses"]
        result: list[dict[str, Any]] = []
        for node_id in sorted(node_ids):
            summary = self.graph.node_summary(node_id, config["max_code_chars"])
            code = summary["code"] or ""
            if not set(config["labels_any"]).isdisjoint(summary["labels"]) or any(token in code for token in config["code_contains_any"]):
                result.append(summary)
        return result[: config["limit"]]

    def structured_parse_calls(self, node_ids: set[int]) -> list[dict[str, Any]]:
        config = self.rules["structured_parse_calls"]
        result: list[dict[str, Any]] = []
        for node_id in sorted(node_ids):
            summary = self.graph.node_summary(node_id, config["max_code_chars"])
            haystack = f"{summary.get('code') or ''}\n{summary.get('fullName') or ''}".casefold()
            if any(token.casefold() in haystack for token in config["haystack_contains_any"]):
                result.append(summary)
        return result[: config["limit"]]

    def function_contexts(self, seeds: list[dict[str, Any]], downstream: list[dict[str, Any]]) -> list[dict[str, Any]]:
        config = self.rules["function_contexts"]
        result: list[dict[str, Any]] = []
        seen: set[int] = set()

        def add(node_id: int, role: str) -> None:
            function = self.graph.enclosing(node_id, config)
            if function is not None and function["nodeId"] not in seen:
                seen.add(function["nodeId"])
                result.append({"role": role, "node": function})

        for seed in seeds:
            add(seed["node"]["nodeId"], f"seed:{seed['role']}")
        for path in downstream:
            add(path["sink"]["nodeId"], f"sink:{path['sink']['kind']}")
        return result[: config["limit"]]

    @staticmethod
    def source_node_id(source: dict[str, Any]) -> int:
        node_id = source.get("nodeId")
        if not isinstance(node_id, int):
            raise TypeError("source.nodeId must be an int")
        return node_id

    @staticmethod
    def edge_dependence(edge: dict[str, Any]) -> str | None:
        props = edge.get("properties", {})
        value = props.get("dependence") if isinstance(props, dict) else None
        return value if isinstance(value, str) else None

    @staticmethod
    def edge_counts(path: list[dict[str, Any]]) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for step in path[1:]:
            edge = step["edgeFromPrevious"]
            counter[edge["type"]] += 1
        return dict(sorted(counter.items()))
