from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, cast

import yaml

from sink_finder_pipe.graph import CPGGraph
from sink_finder_pipe.rules import SinkFinderRules
from utils.env_utils import env_optional_int, env_path, load_env


class InterproceduralContextPipeline:
    def __init__(self, project_dir: Path) -> None:
        self.project_dir = project_dir
        load_env(os.getenv("INTERPROCEDURAL_CONTEXT_ENV_FILE", str(project_dir / "config" / "interprocedural_context.env")))
        self.cpg_path = self.project_path(env_path("INTERPROCEDURAL_CONTEXT_CPG"))
        self.sources_path = self.project_path(env_path("INTERPROCEDURAL_CONTEXT_SOURCES"))
        self.context_dir = self.project_path(env_path("INTERPROCEDURAL_CONTEXT_EXPANSION"))
        self.output_dir = self.project_path(env_path("INTERPROCEDURAL_CONTEXT_OUTPUT"))
        self.rules_path = self.project_path(env_path("INTERPROCEDURAL_CONTEXT_RULES"))
        self.limit = env_optional_int("INTERPROCEDURAL_CONTEXT_LIMIT")
        self.rules = self.read_yaml(self.rules_path)
        self.sink_rules = SinkFinderRules(self.project_path(Path(self.rules["sink_rules"])))

    def run(self) -> dict[str, Any]:
        graph = CPGGraph(self.cpg_path, self.sink_rules)
        sources = self.sources()
        if self.limit is not None:
            sources = sources[: self.limit]
        sink_records = {sink["nodeId"]: graph.sink_record(sink) for sink in graph.find_sink_candidates()}
        builder = InterproceduralContextBuilder(graph, self.rules, sink_records, self.context_index())
        workers = self.rules["search"]["parallel_workers"]

        self.output_dir.mkdir(parents=True, exist_ok=True)
        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(builder.analyze_source, source, index): (source, index) for index, source in enumerate(sources, start=1)}
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
            "contextExpansionDir": str(self.context_dir),
            "rulesFile": str(self.rules_path),
            "outputDir": str(self.output_dir),
            "sourceCount": len(sources),
            **self.rules["search"],
            "results": sorted(results, key=lambda item: item["index"]),
        }
        self.write_json(self.output_dir / self.rules["output"]["summary_file"], summary)
        return summary

    def context_index(self) -> dict[int, dict[str, Any]]:
        index: dict[int, dict[str, Any]] = {}
        if not self.context_dir.exists():
            return index
        for path in sorted(self.context_dir.glob("*_context_ok.json")):
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


class InterproceduralContextBuilder:
    def __init__(self, graph: CPGGraph, rules: dict[str, Any], sink_records: dict[int, dict[str, Any]], context_index: dict[int, dict[str, Any]]) -> None:
        self.graph = graph
        self.rules = rules
        self.sink_records = sink_records
        self.context_index = context_index
        self.max_depth = rules["search"]["max_depth"]
        self.max_paths = rules["search"]["max_paths"]
        self.max_nodes = rules["search"]["max_nodes"]
        self.max_same_name_uses = rules["search"]["max_same_name_uses"]
        self.index = FunctionIndex(graph, rules)

    def analyze_source(self, source: dict[str, Any], index: int) -> dict[str, Any]:
        seeds = self.seeds(source)
        paths = self.find_paths(seeds)
        return {
            "status": "ok",
            "index": index,
            "sourceNodeId": self.source_node_id(source),
            "source": source,
            "seeds": seeds,
            "paths": paths,
            "functions": self.function_summaries(paths),
            "search": {**self.rules["search"], "realEdgeTypes": self.rules["real_edges"]["edge_types"], "syntheticEdgeTypes": list(self.rules["synthetic_edges"].values())},
        }

    def seeds(self, source: dict[str, Any]) -> list[dict[str, Any]]:
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
            elif kind == "expansion_context":
                self.add_expansion_context_seeds(self.context_index.get(self.source_node_id(source)), rule, add)
            elif kind == "local_parse_calls":
                self.add_local_parse_call_seeds(self.source_node_id(source), rule["role"], add)
            else:
                raise ValueError(f"unsupported interprocedural seed type: {kind}")
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
    def add_expansion_context_seeds(context: dict[str, Any] | None, rule: dict[str, Any], add: Any) -> None:
        if context is None:
            return
        for field in rule["fields"]:
            for item in context.get(field, []) if isinstance(context.get(field, []), list) else []:
                if isinstance(item, dict) and isinstance(item.get("nodeId"), int):
                    add(item["nodeId"], rule["role"])
        for path in context.get(rule["downstream_sink_paths_field"], []) if isinstance(context.get(rule["downstream_sink_paths_field"], []), list) else []:
            sink = path.get("sink", {}) if isinstance(path, dict) else {}
            if isinstance(sink, dict) and isinstance(sink.get("nodeId"), int):
                add(sink["nodeId"], rule["role"])

    def add_local_parse_call_seeds(self, source_id: int, role: str, add: Any) -> None:
        function_id = self.index.function_by_node.get(source_id)
        if function_id is None:
            return
        source_line = self.graph.node_summary(source_id)["startLine"]
        for node_id, owner in self.index.function_by_node.items():
            if owner != function_id or not self.is_local_parse_call(node_id):
                continue
            node_line = self.graph.node_summary(node_id)["startLine"]
            if source_line is not None and node_line is not None and node_line < source_line:
                continue
            add(node_id, role)

    def find_paths(self, seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        found: set[int] = set()
        best_depth: dict[int, int] = {}
        queue: deque[tuple[int, list[dict[str, Any]], int]] = deque()
        for seed in seeds:
            node_id = seed["node"]["nodeId"]
            queue.append((node_id, [{"edgeFromPrevious": None, "node": seed["node"]}], 0))
            best_depth[node_id] = 0
        while queue and len(best_depth) <= self.max_nodes and len(results) < self.max_paths:
            node_id, path, depth = queue.popleft()
            if node_id in self.sink_records and node_id not in found:
                found.add(node_id)
                results.append({"sink": self.sink_records[node_id], "pathLength": len(path), "edgeTypeCounts": self.edge_counts(path), "syntheticEdgeCount": self.synthetic_edge_count(path), "path": path})
            if depth >= self.max_depth:
                continue
            for edge in self.forward_edges(node_id):
                target = edge["to"]
                next_depth = depth + 1
                if best_depth.get(target, 10**9) <= next_depth:
                    continue
                best_depth[target] = next_depth
                queue.append((target, path + [{"edgeFromPrevious": {"type": edge["type"], "direction": edge["direction"]}, "node": self.graph.node_summary(target, self.rules["nodes"]["path_max_code_chars"])}], next_depth))
        return results

    def forward_edges(self, node_id: int) -> list[dict[str, Any]]:
        edges = self.real_edges(node_id)
        synthetic = self.rules["synthetic_edges"]
        edges.extend(self.same_name_edges(node_id, synthetic["same_name_use"]))
        edges.extend(self.argument_to_call_edges(node_id, synthetic["argument_to_call"]))
        edges.extend(self.call_argument_to_parameter_edges(node_id, synthetic["call_argument_to_parameter"]))
        edges.extend(self.return_to_call_assignment_edges(node_id, synthetic["return_to_call_assignment"]))
        edges.extend(self.call_to_assignment_edges(node_id, synthetic["call_to_assignment"]))
        return self.dedupe(edges)

    def real_edges(self, node_id: int) -> list[dict[str, Any]]:
        config = self.rules["real_edges"]
        edge_types = set(config["edge_types"])
        result: list[dict[str, Any]] = []
        for edge in self.graph.outgoing.get(node_id, []):
            if edge.get("type") not in edge_types:
                continue
            if edge.get("type") == "PDG" and self.edge_dependence(edge) != config["pdg_dependence"]:
                continue
            target = edge["endNode"]
            if isinstance(target, int) and target in self.graph.nodes_by_id:
                result.append({"to": target, "type": edge["type"], "direction": "forward"})
        return result

    def same_name_edges(self, node_id: int, edge_type: str) -> list[dict[str, Any]]:
        summary = self.graph.node_summary(node_id)
        name = summary["name"]
        function_id = self.index.function_by_node.get(node_id)
        if not name or function_id is None:
            return []
        node_line = summary["startLine"] if summary["startLine"] is not None else -1
        result: list[dict[str, Any]] = []
        for target in self.index.references_by_function_and_name.get((function_id, name), []):
            if target == node_id:
                continue
            target_line = self.graph.node_summary(target)["startLine"]
            if node_line >= 0 and target_line is not None and target_line < node_line:
                continue
            result.append({"to": target, "type": edge_type, "direction": "synthetic"})
            if len(result) >= self.max_same_name_uses:
                break
        return result

    def argument_to_call_edges(self, node_id: int, edge_type: str) -> list[dict[str, Any]]:
        parent = self.index.call_parent_by_argument.get(node_id)
        return [{"to": parent[0], "type": edge_type, "direction": "synthetic"}] if parent is not None else []

    def call_argument_to_parameter_edges(self, node_id: int, edge_type: str) -> list[dict[str, Any]]:
        parent = self.index.call_parent_by_argument.get(node_id)
        if parent is None:
            return []
        call_id, index = parent
        function_id = self.index.invoked_function_by_call.get(call_id)
        params = self.index.params_by_function.get(function_id, []) if function_id is not None else []
        return [{"to": params[index], "type": edge_type, "direction": "synthetic"}] if 0 <= index < len(params) else []

    def return_to_call_assignment_edges(self, node_id: int, edge_type: str) -> list[dict[str, Any]]:
        function_id = self.index.function_by_node.get(node_id)
        if function_id is None:
            return []
        if node_id not in self.index.returns_by_function.get(function_id, []) and "Return" not in self.graph.node_labels(node_id):
            return []
        return [{"to": assignment["lhs"], "type": edge_type, "direction": "synthetic"} for call_id in self.index.callsites_by_function.get(function_id, []) for assignment in self.index.assignments_by_rhs.get(call_id, [])]

    def call_to_assignment_edges(self, node_id: int, edge_type: str) -> list[dict[str, Any]]:
        return [{"to": assignment["lhs"], "type": edge_type, "direction": "synthetic"} for assignment in self.index.assignments_by_rhs.get(node_id, [])]

    def function_summaries(self, paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
        config = self.rules["function_summaries"]
        function_ids = {self.index.function_by_node[step["node"]["nodeId"]] for path in paths for step in path["path"] if step["node"]["nodeId"] in self.index.function_by_node}
        result: list[dict[str, Any]] = []
        for function_id in sorted(function_ids, key=self.index.node_sort_key):
            result.append(
                {
                    "node": self.graph.node_summary(function_id, config["function_max_code_chars"]),
                    "parameters": [self.graph.node_summary(node_id, config["node_max_code_chars"]) for node_id in self.index.params_by_function.get(function_id, [])],
                    "returnNodes": [self.graph.node_summary(node_id, config["node_max_code_chars"]) for node_id in self.index.returns_by_function.get(function_id, [])],
                    "callSites": [self.graph.node_summary(node_id, config["node_max_code_chars"]) for node_id in self.index.callsites_by_function.get(function_id, [])[: config["callsites_limit"]]],
                }
            )
        return result[: config["limit"]]

    def is_local_parse_call(self, node_id: int) -> bool:
        summary = self.graph.node_summary(node_id)
        if "Call" not in summary["labels"]:
            return False
        code = (summary["code"] or "").strip().casefold()
        return any(code.startswith(item.casefold()) for item in self.rules["local_parse_calls"]["haystack_startswith_any"])

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
            counter[step["edgeFromPrevious"]["type"]] += 1
        return dict(sorted(counter.items()))

    @staticmethod
    def synthetic_edge_count(path: list[dict[str, Any]]) -> int:
        return sum(1 for step in path[1:] if step["edgeFromPrevious"]["direction"] == "synthetic")

    @staticmethod
    def dedupe(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[int, str]] = set()
        result: list[dict[str, Any]] = []
        for edge in edges:
            key = (edge["to"], edge["type"])
            if key not in seen:
                seen.add(key)
                result.append(edge)
        return result


class FunctionIndex:
    def __init__(self, graph: CPGGraph, rules: dict[str, Any]) -> None:
        self.graph = graph
        self.config = rules["function_index"]
        self.function_ids = {node_id for node_id in graph.nodes_by_id if not set(self.config["function_labels_any"]).isdisjoint(graph.node_labels(node_id))}
        self.function_by_node = self.build_function_by_node()
        self.params_by_function = self.build_params_by_function()
        self.returns_by_function = self.build_returns_by_function()
        self.invoked_function_by_call, self.callsites_by_function = self.build_callsite_indexes()
        self.assignments_by_rhs = self.build_assignments_by_rhs()
        self.call_parent_by_argument = self.build_call_parent_by_argument()
        self.references_by_function_and_name = self.build_references_by_function_and_name()

    def build_params_by_function(self) -> dict[int, list[int]]:
        result: dict[int, list[int]] = {}
        for function_id in self.function_ids:
            params = [edge["endNode"] for edge_type in self.config["parameter_edges"] for edge in self.graph.outgoing_by_type(function_id, edge_type) if isinstance(edge.get("endNode"), int)]
            result[function_id] = sorted(params, key=self.node_sort_key)
        return result

    def build_returns_by_function(self) -> dict[int, list[int]]:
        result: dict[int, list[int]] = defaultdict(list)
        labels = set(self.config["return_labels_any"])
        for node_id in self.graph.nodes_by_id:
            function_id = self.function_by_node.get(node_id)
            if function_id is not None and not labels.isdisjoint(self.graph.node_labels(node_id)):
                result[function_id].append(node_id)
        return {key: sorted(value, key=self.node_sort_key) for key, value in result.items()}

    def build_callsite_indexes(self) -> tuple[dict[int, int], dict[int, list[int]]]:
        invoked: dict[int, int] = {}
        callsites: dict[int, list[int]] = defaultdict(list)
        for edge in self.graph.edges:
            if edge.get("type") != self.config["invoke_edge"] or not isinstance(edge.get("startNode"), int) or not isinstance(edge.get("endNode"), int):
                continue
            call_id = edge["startNode"]
            function_id = edge["endNode"]
            if function_id in self.function_ids:
                invoked[call_id] = function_id
                callsites[function_id].append(call_id)
        return invoked, {key: sorted(value, key=self.node_sort_key) for key, value in callsites.items()}

    def build_assignments_by_rhs(self) -> dict[int, list[dict[str, int]]]:
        result: dict[int, list[dict[str, int]]] = defaultdict(list)
        rhs_edge = self.config["assignment"]["rhs_edge"]
        lhs_edge = self.config["assignment"]["lhs_edge"]
        for edge in self.graph.edges:
            if edge.get("type") != rhs_edge or not isinstance(edge.get("startNode"), int) or not isinstance(edge.get("endNode"), int):
                continue
            assign_id = edge["startNode"]
            rhs_id = edge["endNode"]
            for lhs in self.graph.outgoing_by_type(assign_id, lhs_edge):
                if isinstance(lhs.get("endNode"), int):
                    result[rhs_id].append({"assign": assign_id, "lhs": lhs["endNode"], "rhs": rhs_id})
        return result

    def build_call_parent_by_argument(self) -> dict[int, tuple[int, int]]:
        result: dict[int, tuple[int, int]] = {}
        for edge in self.graph.edges:
            if edge.get("type") not in self.config["argument_edges"] or not isinstance(edge.get("startNode"), int) or not isinstance(edge.get("endNode"), int):
                continue
            call_id = edge["startNode"]
            arg_id = edge["endNode"]
            if "Call" in self.graph.node_labels(call_id):
                result.setdefault(arg_id, (call_id, self.graph.edge_index(edge)))
        return result

    def build_function_by_node(self) -> dict[int, int]:
        functions = [self.graph.node_summary(function_id) for function_id in self.function_ids]
        result: dict[int, int] = {}
        for node_id in self.graph.nodes_by_id:
            node = self.graph.node_summary(node_id)
            artifact = node["artifact"]
            line = node["startLine"]
            if artifact is None or line is None or line < 0:
                continue
            best_id: int | None = None
            best_span: int | None = None
            for function in functions:
                if function["artifact"] != artifact:
                    continue
                start = function["startLine"]
                end = function["endLine"]
                if start is None or end is None or not start <= line <= end:
                    continue
                span = end - start
                if best_span is None or span < best_span:
                    best_id = function["nodeId"]
                    best_span = span
            if best_id is not None:
                result[node_id] = best_id
        return result

    def build_references_by_function_and_name(self) -> dict[tuple[int, str], list[int]]:
        result: dict[tuple[int, str], list[int]] = defaultdict(list)
        labels = set(self.config["reference_labels_any"])
        for node_id, function_id in self.function_by_node.items():
            if labels.isdisjoint(self.graph.node_labels(node_id)):
                continue
            name = self.graph.node_summary(node_id)["name"]
            if name:
                result[(function_id, name)].append(node_id)
        return {key: sorted(value, key=self.node_sort_key) for key, value in result.items()}

    def node_sort_key(self, node_id: int) -> tuple[str, int, int]:
        node = self.graph.node_summary(node_id)
        return (node["artifact"] or "", node["startLine"] if node["startLine"] is not None else 10**9, node_id)


def main() -> int:
    summary = InterproceduralContextPipeline(Path(__file__).resolve().parents[1]).run()
    print(f"interprocedural context: sources={summary['sourceCount']} output={summary['outputDir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
