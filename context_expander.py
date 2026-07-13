#!/usr/bin/env python3
"""Expand CPG context after source-to-sink triage."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

from env_utils import env_int, env_optional_int, env_optional_path, env_path, load_env
from sink_path_finder import (
    CPGGraph,
    CandidateSource,
    NodeSummary,
    PathEdge,
    SinkRecord,
    classify_sink,
    load_candidate_sources,
    require_int,
    sink_record,
    write_pretty_json,
)


DATA_EDGE_TYPES: set[str] = {
    "DFG",
    "PDG",
    "EOG",
    "ARGUMENTS",
    "OPERATOR_ARGUMENTS",
    "RETURN_VALUE",
    "RETURN_VALUES",
    "LHS",
    "RHS",
    "VALUE",
    "KEY",
    "BASE",
    "OPERATOR_BASE",
    "RECEIVER",
}

FIELD_LABELS: set[str] = {
    "MemberAccess",
    "Subscription",
    "SubscriptExpression",
}

SeedRole = Literal[
    "source",
    "assigned_to",
    "source_dataflow",
    "related_use",
    "related_use_parent",
    "path_sink_argument",
    "path_sink_data_dependency",
    "structured_parse_call",
]


class ExpansionSeed(TypedDict):
    role: SeedRole
    node: NodeSummary


class ExpansionStep(TypedDict):
    edgeFromPrevious: PathEdge | None
    node: NodeSummary


class DownstreamSinkPath(TypedDict):
    sink: SinkRecord
    pathLength: int
    edgeTypeCounts: dict[str, int]
    path: list[ExpansionStep]


class FunctionContext(TypedDict):
    role: str
    node: NodeSummary


class ContextExpansionResult(TypedDict):
    status: Literal["ok"]
    index: int
    sourceNodeId: int
    source: CandidateSource
    expansionSeeds: list[ExpansionSeed]
    downstreamSinkPaths: list[DownstreamSinkPath]
    interestingFieldAccesses: list[NodeSummary]
    structuredParseCalls: list[NodeSummary]
    functionContexts: list[FunctionContext]
    search: dict[str, Any]


class ContextExpansionError(TypedDict):
    status: Literal["error"]
    index: int
    sourceNodeId: int | None
    source: CandidateSource
    error: dict[str, str]


ContextExpansionOutput = ContextExpansionResult | ContextExpansionError


@dataclass(frozen=True)
class ExpansionEdge:
    to_node: int
    edge_type: str
    direction: Literal["forward"]


class ContextExpander:
    def __init__(
        self,
        graph: CPGGraph,
        sink_records: dict[int, SinkRecord],
        sink_paths_by_source: dict[int, dict[str, Any]],
        max_depth: int,
        max_nodes: int,
        max_sinks: int,
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if max_nodes < 1:
            raise ValueError("max_nodes must be >= 1")
        if max_sinks < 1:
            raise ValueError("max_sinks must be >= 1")
        self.graph = graph
        self.sink_records = sink_records
        self.sink_paths_by_source = sink_paths_by_source
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.max_sinks = max_sinks

    def analyze_source(self, source: CandidateSource, index: int) -> ContextExpansionResult:
        source_node_id = require_int(source["nodeId"], "source.nodeId")
        seeds = self.expansion_seeds(source)
        downstream_paths = self.downstream_sink_paths(seeds)
        visited_ids = node_ids_from_paths(downstream_paths)
        visited_ids.update(seed["node"]["nodeId"] for seed in seeds)
        return {
            "status": "ok",
            "index": index,
            "sourceNodeId": source_node_id,
            "source": source,
            "expansionSeeds": seeds,
            "downstreamSinkPaths": downstream_paths,
            "interestingFieldAccesses": self.interesting_field_accesses(visited_ids),
            "structuredParseCalls": self.structured_parse_calls(visited_ids),
            "functionContexts": self.function_contexts(seeds, downstream_paths),
            "search": {
                "maxDepth": self.max_depth,
                "maxNodes": self.max_nodes,
                "maxSinks": self.max_sinks,
                "edgeTypes": sorted(DATA_EDGE_TYPES),
            },
        }

    def expansion_seeds(self, source: CandidateSource) -> list[ExpansionSeed]:
        source_node_id = require_int(source["nodeId"], "source.nodeId")
        seeds: list[ExpansionSeed] = []
        seen: set[int] = set()

        def add(node_id: int, role: SeedRole) -> None:
            if node_id in seen or node_id not in self.graph.nodes_by_id:
                return
            seen.add(node_id)
            seeds.append({"role": role, "node": self.graph.node_summary(node_id, max_code_chars=1600)})

        add(source_node_id, "source")
        assigned = source.get("assignedTo")
        if isinstance(assigned, dict) and isinstance(assigned.get("nodeId"), int):
            add(assigned["nodeId"], "assigned_to")
        for item in source.get("dataflow", []):
            if isinstance(item, dict) and isinstance(item.get("nodeId"), int):
                add(item["nodeId"], "source_dataflow")
        for related_use in source.get("relatedUses", []):
            if not isinstance(related_use, dict):
                continue
            if isinstance(related_use.get("nodeId"), int):
                add(related_use["nodeId"], "related_use")
            parents = related_use.get("parents", [])
            if isinstance(parents, list):
                for parent in parents:
                    if isinstance(parent, dict) and isinstance(parent.get("nodeId"), int):
                        add(parent["nodeId"], "related_use_parent")

        sink_path_record = self.sink_paths_by_source.get(source_node_id)
        if sink_path_record is not None:
            self.add_sink_path_seeds(sink_path_record, add)
        return seeds

    def add_sink_path_seeds(
        self,
        sink_path_record: dict[str, Any],
        add: Any,
    ) -> None:
        for path in sink_path_record.get("paths", []):
            if not isinstance(path, dict):
                continue
            sink = path.get("sink", {})
            if isinstance(sink, dict) and sink.get("kind") == "structured_parse":
                node_id = sink.get("nodeId")
                if isinstance(node_id, int):
                    add(node_id, "structured_parse_call")
            evidence = path.get("evidence", {})
            if isinstance(evidence, dict):
                for node_id in evidence.get("sinkArgumentNodeIdsInPath", []):
                    if isinstance(node_id, int):
                        add(node_id, "path_sink_argument")
                for node_id in evidence.get("sinkDataDependencyNodeIdsInPath", []):
                    if isinstance(node_id, int):
                        add(node_id, "path_sink_data_dependency")

    def downstream_sink_paths(self, seeds: list[ExpansionSeed]) -> list[DownstreamSinkPath]:
        results: list[DownstreamSinkPath] = []
        found_sinks: set[int] = set()
        queue: deque[tuple[int, list[ExpansionStep], int]] = deque()
        best_depth: dict[int, int] = {}

        for seed in seeds:
            seed_id = seed["node"]["nodeId"]
            queue.append((seed_id, [{"edgeFromPrevious": None, "node": seed["node"]}], 0))
            best_depth[seed_id] = 0

        while queue and len(best_depth) <= self.max_nodes and len(results) < self.max_sinks:
            current_id, path, depth = queue.popleft()
            if current_id in self.sink_records and current_id not in found_sinks:
                found_sinks.add(current_id)
                results.append(
                    {
                        "sink": self.sink_records[current_id],
                        "pathLength": len(path),
                        "edgeTypeCounts": edge_type_counts(path),
                        "path": path,
                    }
                )
                if self.sink_records[current_id]["kind"] != "structured_parse":
                    continue

            if depth >= self.max_depth:
                continue

            for edge in self.forward_edges(current_id):
                next_depth = depth + 1
                known_depth = best_depth.get(edge.to_node)
                if known_depth is not None and known_depth <= next_depth:
                    continue
                best_depth[edge.to_node] = next_depth
                queue.append(
                    (
                        edge.to_node,
                        path
                        + [
                            {
                                "edgeFromPrevious": {
                                    "type": edge.edge_type,
                                    "direction": edge.direction,
                                },
                                "node": self.graph.node_summary(edge.to_node, max_code_chars=1600),
                            }
                        ],
                        next_depth,
                    )
                )

        return results

    def forward_edges(self, node_id: int) -> list[ExpansionEdge]:
        if self.is_external_declaration(node_id):
            return []

        edges: list[ExpansionEdge] = []
        for edge in self.graph.outgoing_edges.get(node_id, []):
            edge_type = str(edge.get("type"))
            if edge_type not in DATA_EDGE_TYPES:
                continue
            if edge_type == "PDG" and edge_dependence(edge) != "DATA":
                continue
            end_node = require_int(edge["endNode"], "edge.endNode")
            if end_node not in self.graph.nodes_by_id:
                continue
            edges.append(ExpansionEdge(end_node, edge_type, "forward"))
        return edges

    def is_external_declaration(self, node_id: int) -> bool:
        summary = self.graph.node_summary(node_id)
        labels = self.graph.node_labels(node_id)
        return summary["artifact"] is None and bool(labels & {"Function", "Method"})

    def interesting_field_accesses(self, node_ids: set[int]) -> list[NodeSummary]:
        results: list[NodeSummary] = []
        for node_id in sorted(node_ids):
            labels = self.graph.node_labels(node_id)
            code = self.graph.node_summary(node_id)["code"] or ""
            if labels & FIELD_LABELS or "[" in code or "." in code:
                results.append(self.graph.node_summary(node_id, max_code_chars=1000))
        return results[:80]

    def structured_parse_calls(self, node_ids: set[int]) -> list[NodeSummary]:
        results: list[NodeSummary] = []
        for node_id in sorted(node_ids):
            summary = self.graph.node_summary(node_id, max_code_chars=1000)
            code = (summary["code"] or "").lower()
            full_name = (summary["fullName"] or "").lower()
            if any(token in f"{code}\n{full_name}" for token in ("json.load", "json.loads", "yaml.safe_load", "common_config.parse")):
                results.append(summary)
        return results[:40]

    def function_contexts(
        self,
        seeds: list[ExpansionSeed],
        downstream_paths: list[DownstreamSinkPath],
    ) -> list[FunctionContext]:
        contexts: list[FunctionContext] = []
        seen: set[int] = set()

        def add(node_id: int, role: str) -> None:
            function = self.graph.enclosing_with_label(
                node_id,
                {"Function", "Method"},
                max_code_chars=5000,
            )
            if function is None or function["nodeId"] in seen:
                return
            seen.add(function["nodeId"])
            contexts.append({"role": role, "node": function})

        for seed in seeds:
            add(seed["node"]["nodeId"], f"seed:{seed['role']}")
        for path in downstream_paths:
            add(path["sink"]["nodeId"], f"sink:{path['sink']['kind']}")
        return contexts[:30]


def edge_dependence(edge: dict[str, Any]) -> str | None:
    properties = edge.get("properties", {})
    if not isinstance(properties, dict):
        return None
    value = properties.get("dependence")
    return value if isinstance(value, str) else None


def edge_type_counts(path: list[ExpansionStep]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for step in path[1:]:
        edge = step["edgeFromPrevious"]
        if edge is not None:
            counter[edge["type"]] += 1
    return dict(sorted(counter.items()))


def node_ids_from_paths(paths: list[DownstreamSinkPath]) -> set[int]:
    node_ids: set[int] = set()
    for path in paths:
        for step in path["path"]:
            node_ids.add(step["node"]["nodeId"])
    return node_ids


def build_sink_records(graph: CPGGraph) -> dict[int, SinkRecord]:
    records: dict[int, SinkRecord] = {}
    for node in graph.nodes:
        labels = node.get("labels", [])
        if not isinstance(labels, list) or "Call" not in labels:
            continue
        for sink in classify_sink(node):
            records[sink.node_id] = sink_record(graph, sink)
    return records


def load_sink_path_index(path: Path | None) -> dict[int, dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    if not path.is_dir():
        raise ValueError(f"{path}: sink paths path must be a directory")
    index: dict[int, dict[str, Any]] = {}
    for item in sorted(path.glob("*_ok.json")):
        data = load_json_object(item)
        source_node_id = data.get("sourceNodeId")
        if isinstance(source_node_id, int):
            index[source_node_id] = data
    return index


def load_json_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path}: expected JSON object")
    return cast(dict[str, Any], data)


def build_error_record(source: CandidateSource, index: int, error: Exception) -> ContextExpansionError:
    node_id = source.get("nodeId")
    return {
        "status": "error",
        "index": index,
        "sourceNodeId": node_id if isinstance(node_id, int) else None,
        "source": source,
        "error": {
            "type": type(error).__name__,
            "message": str(error),
        },
    }


def output_filename(source: CandidateSource, index: int, status: str) -> str:
    node_id = source.get("nodeId")
    node_part = f"node_{node_id}" if isinstance(node_id, int) else "node_unknown"
    return f"{index:06d}_{node_part}_context_{status}.json"


def default_output_dir(sources_path: Path) -> Path:
    if not sources_path.name.endswith(".sources.json"):
        raise ValueError(f"{sources_path}: sources filename must end with .sources.json")
    return sources_path.parent.parent / "outputs" / f"{sources_path.name.removesuffix('.sources.json')}_context_expansion"


def analyze_sources_to_dir(
    sources_path: Path,
    cpg_path: Path,
    sink_paths_dir: Path | None,
    output_dir: Path,
    max_depth: int,
    max_nodes: int,
    max_sinks: int,
    parallel_workers: int,
    limit: int | None,
) -> None:
    if parallel_workers < 1:
        raise ValueError("parallel_workers must be >= 1")

    graph = CPGGraph.from_json(cpg_path)
    sources = load_candidate_sources(sources_path)
    if limit is not None:
        sources = sources[:limit]

    expander = ContextExpander(
        graph=graph,
        sink_records=build_sink_records(graph),
        sink_paths_by_source=load_sink_path_index(sink_paths_dir),
        max_depth=max_depth,
        max_nodes=max_nodes,
        max_sinks=max_sinks,
    )

    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"{output_dir}: output path must be a directory")
    output_dir.mkdir(parents=True, exist_ok=True)

    summaries: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
        futures = {
            executor.submit(expander.analyze_source, source, index): (index, source)
            for index, source in enumerate(sources, start=1)
        }
        completed = 0
        for future in as_completed(futures):
            index, source = futures[future]
            try:
                record: ContextExpansionOutput = future.result()
            except Exception as error:
                record = build_error_record(source, index, error)
            output_file = output_dir / output_filename(source, index, record["status"])
            write_pretty_json(output_file, record)
            completed += 1
            summaries.append(
                {
                    "index": index,
                    "sourceNodeId": record["sourceNodeId"],
                    "status": record["status"],
                    "file": output_file.name,
                }
            )
            print(
                f"[{completed}/{len(sources)}] saved {record['status']} "
                f"sourceNodeId={record['sourceNodeId']} -> {output_file}",
                file=sys.stderr,
            )

    write_pretty_json(
        output_dir / "summary.json",
        {
            "status": "ok",
            "sourcesFile": str(sources_path),
            "cpgFile": str(cpg_path),
            "sinkPathsDir": str(sink_paths_dir) if sink_paths_dir is not None else None,
            "outputDir": str(output_dir),
            "sourceCount": len(sources),
            "maxDepth": max_depth,
            "maxNodes": max_nodes,
            "maxSinks": max_sinks,
            "parallelWorkers": parallel_workers,
            "results": sorted(summaries, key=lambda item: item["index"]),
        },
    )


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    env_file = os.getenv(
        "CONTEXT_EXPANDER_ENV_FILE",
        str(base_dir / "config" / "context_expander.env"),
    )
    load_env(env_file)

    sources_path = env_path("CONTEXT_EXPANDER_SOURCES")
    output_dir = env_optional_path("CONTEXT_EXPANDER_OUTPUT")
    if output_dir is None:
        output_dir = default_output_dir(sources_path)

    analyze_sources_to_dir(
        sources_path=sources_path,
        cpg_path=env_path("CONTEXT_EXPANDER_CPG"),
        sink_paths_dir=env_optional_path("CONTEXT_EXPANDER_SINK_PATHS_DIR"),
        output_dir=output_dir,
        max_depth=env_int("CONTEXT_EXPANDER_MAX_DEPTH"),
        max_nodes=env_int("CONTEXT_EXPANDER_MAX_NODES"),
        max_sinks=env_int("CONTEXT_EXPANDER_MAX_SINKS"),
        parallel_workers=env_int("CONTEXT_EXPANDER_PARALLEL_WORKERS"),
        limit=env_optional_int("CONTEXT_EXPANDER_LIMIT"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
