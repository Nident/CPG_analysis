#!/usr/bin/env python3
"""Build synthetic interprocedural source propagation context."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

from env_utils import env_int, env_optional_int, env_optional_path, env_path, load_env
from sink_path_finder import (
    CPGGraph,
    CandidateSource,
    NodeSummary,
    SinkRecord,
    classify_sink,
    load_candidate_sources,
    require_int,
    sink_record,
    write_pretty_json,
)


REAL_EDGE_TYPES: set[str] = {
    "DFG",
    "PDG",
    "EOG",
    "RETURN_VALUE",
    "RETURN_VALUES",
    "ARGUMENTS",
    "OPERATOR_ARGUMENTS",
    "LHS",
    "RHS",
    "VALUE",
    "KEY",
}

SYNTHETIC_EDGE_TYPES: set[str] = {
    "SYN_SAME_NAME_USE",
    "SYN_ARG_TO_CALL",
    "SYN_CALL_ARG_TO_PARAM",
    "SYN_RETURN_TO_CALL_ASSIGN",
    "SYN_CALL_TO_ASSIGN",
}

SeedRole = Literal[
    "source",
    "assigned_to",
    "source_dataflow",
    "related_use",
    "related_use_parent",
    "context_seed",
    "local_parse_call",
]


class SyntheticEdge(TypedDict):
    type: str
    direction: Literal["forward", "synthetic"]


class InterproceduralStep(TypedDict):
    edgeFromPrevious: SyntheticEdge | None
    node: NodeSummary


class InterproceduralSeed(TypedDict):
    role: SeedRole
    node: NodeSummary


class InterproceduralPath(TypedDict):
    sink: SinkRecord
    pathLength: int
    edgeTypeCounts: dict[str, int]
    syntheticEdgeCount: int
    path: list[InterproceduralStep]


class FunctionSummary(TypedDict):
    node: NodeSummary
    parameters: list[NodeSummary]
    returnNodes: list[NodeSummary]
    callSites: list[NodeSummary]


class InterproceduralResult(TypedDict):
    status: Literal["ok"]
    index: int
    sourceNodeId: int
    source: CandidateSource
    seeds: list[InterproceduralSeed]
    paths: list[InterproceduralPath]
    functions: list[FunctionSummary]
    search: dict[str, Any]


class InterproceduralError(TypedDict):
    status: Literal["error"]
    index: int
    sourceNodeId: int | None
    source: CandidateSource
    error: dict[str, str]


InterproceduralOutput = InterproceduralResult | InterproceduralError


@dataclass(frozen=True)
class TraversalEdge:
    to_node: int
    edge_type: str
    direction: Literal["forward", "synthetic"]


@dataclass(frozen=True)
class Assignment:
    assign_node_id: int
    lhs_node_id: int
    rhs_node_id: int


@dataclass(frozen=True)
class FunctionIndex:
    function_ids: set[int]
    params_by_function: dict[int, list[int]]
    returns_by_function: dict[int, list[int]]
    callsites_by_function: dict[int, list[int]]
    function_by_node: dict[int, int]
    references_by_function_and_name: dict[tuple[int, str], list[int]]
    assignments_by_rhs: dict[int, list[Assignment]]
    call_parent_by_argument: dict[int, tuple[int, int]]
    invoked_function_by_call: dict[int, int]


class InterproceduralContextBuilder:
    def __init__(
        self,
        graph: CPGGraph,
        sink_records: dict[int, SinkRecord],
        context_by_source: dict[int, dict[str, Any]],
        max_depth: int,
        max_paths: int,
        max_nodes: int,
        max_same_name_uses: int,
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if max_paths < 1:
            raise ValueError("max_paths must be >= 1")
        if max_nodes < 1:
            raise ValueError("max_nodes must be >= 1")
        if max_same_name_uses < 1:
            raise ValueError("max_same_name_uses must be >= 1")
        self.graph = graph
        self.sink_records = sink_records
        self.context_by_source = context_by_source
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_nodes = max_nodes
        self.max_same_name_uses = max_same_name_uses
        self.index = build_function_index(graph)

    def analyze_source(self, source: CandidateSource, index: int) -> InterproceduralResult:
        source_node_id = require_int(source["nodeId"], "source.nodeId")
        seeds = self.seeds(source)
        paths = self.find_paths(seeds)
        return {
            "status": "ok",
            "index": index,
            "sourceNodeId": source_node_id,
            "source": source,
            "seeds": seeds,
            "paths": paths,
            "functions": self.function_summaries(paths),
            "search": {
                "maxDepth": self.max_depth,
                "maxPaths": self.max_paths,
                "maxNodes": self.max_nodes,
                "maxSameNameUses": self.max_same_name_uses,
                "realEdgeTypes": sorted(REAL_EDGE_TYPES),
                "syntheticEdgeTypes": sorted(SYNTHETIC_EDGE_TYPES),
            },
        }

    def seeds(self, source: CandidateSource) -> list[InterproceduralSeed]:
        source_node_id = require_int(source["nodeId"], "source.nodeId")
        seeds: list[InterproceduralSeed] = []
        seen: set[int] = set()

        def add(node_id: int, role: SeedRole) -> None:
            if node_id in seen or node_id not in self.graph.nodes_by_id:
                return
            seen.add(node_id)
            seeds.append(
                {
                    "role": role,
                    "node": self.graph.node_summary(node_id, max_code_chars=1600),
                }
            )

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

        context = self.context_by_source.get(source_node_id)
        if context is not None:
            self.add_context_seeds(context, add)
        self.add_local_parse_call_seeds(source_node_id, add)
        return seeds

    def add_context_seeds(self, context: dict[str, Any], add: Any) -> None:
        for key in ("structuredParseCalls", "interestingFieldAccesses"):
            values = context.get(key, [])
            if not isinstance(values, list):
                continue
            for item in values:
                if isinstance(item, dict) and isinstance(item.get("nodeId"), int):
                    add(item["nodeId"], "context_seed")
        for path in context.get("downstreamSinkPaths", []):
            if not isinstance(path, dict):
                continue
            sink = path.get("sink", {})
            if isinstance(sink, dict) and isinstance(sink.get("nodeId"), int):
                add(sink["nodeId"], "context_seed")

    def add_local_parse_call_seeds(self, source_node_id: int, add: Any) -> None:
        function_id = self.index.function_by_node.get(source_node_id)
        if function_id is None:
            return
        source_line = self.graph.node_summary(source_node_id)["startLine"]
        for node_id, owner_function_id in self.index.function_by_node.items():
            if owner_function_id != function_id:
                continue
            node = self.graph.node_summary(node_id)
            if not is_structured_parse_call(node):
                continue
            node_line = node["startLine"]
            if (
                source_line is not None
                and node_line is not None
                and source_line >= 0
                and node_line >= 0
                and node_line < source_line
            ):
                continue
            add(node_id, "local_parse_call")

    def find_paths(self, seeds: list[InterproceduralSeed]) -> list[InterproceduralPath]:
        results: list[InterproceduralPath] = []
        found_sinks: set[int] = set()
        queue: deque[tuple[int, list[InterproceduralStep], int]] = deque()
        best_depth: dict[int, int] = {}

        for seed in seeds:
            seed_id = seed["node"]["nodeId"]
            queue.append((seed_id, [{"edgeFromPrevious": None, "node": seed["node"]}], 0))
            best_depth[seed_id] = 0

        while queue and len(best_depth) <= self.max_nodes and len(results) < self.max_paths:
            current_id, path, depth = queue.popleft()
            if current_id in self.sink_records and current_id not in found_sinks:
                found_sinks.add(current_id)
                results.append(
                    {
                        "sink": self.sink_records[current_id],
                        "pathLength": len(path),
                        "edgeTypeCounts": edge_type_counts(path),
                        "syntheticEdgeCount": synthetic_edge_count(path),
                        "path": path,
                    }
                )

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

    def forward_edges(self, node_id: int) -> list[TraversalEdge]:
        edges: list[TraversalEdge] = []
        edges.extend(self.real_forward_edges(node_id))
        edges.extend(self.same_name_use_edges(node_id))
        edges.extend(self.argument_to_call_edges(node_id))
        edges.extend(self.call_argument_to_parameter_edges(node_id))
        edges.extend(self.return_to_call_assignment_edges(node_id))
        edges.extend(self.call_to_assignment_edges(node_id))
        return dedupe_edges(edges)

    def real_forward_edges(self, node_id: int) -> list[TraversalEdge]:
        edges: list[TraversalEdge] = []
        for edge in self.graph.outgoing_edges.get(node_id, []):
            edge_type = str(edge.get("type"))
            if edge_type not in REAL_EDGE_TYPES:
                continue
            if edge_type == "PDG" and edge_dependence(edge) != "DATA":
                continue
            end_node = require_int(edge["endNode"], "edge.endNode")
            if end_node in self.graph.nodes_by_id:
                edges.append(TraversalEdge(end_node, edge_type, "forward"))
        return edges

    def same_name_use_edges(self, node_id: int) -> list[TraversalEdge]:
        summary = self.graph.node_summary(node_id)
        name = summary["name"]
        if not name:
            return []
        function_id = self.index.function_by_node.get(node_id)
        if function_id is None:
            return []
        candidates = self.index.references_by_function_and_name.get((function_id, name), [])
        node_line = summary["startLine"] if summary["startLine"] is not None else -1
        edges: list[TraversalEdge] = []
        for target_id in candidates:
            if target_id == node_id:
                continue
            target = self.graph.node_summary(target_id)
            target_line = target["startLine"] if target["startLine"] is not None else -1
            if node_line >= 0 and target_line >= 0 and target_line < node_line:
                continue
            edges.append(TraversalEdge(target_id, "SYN_SAME_NAME_USE", "synthetic"))
            if len(edges) >= self.max_same_name_uses:
                break
        return edges

    def argument_to_call_edges(self, node_id: int) -> list[TraversalEdge]:
        parent = self.index.call_parent_by_argument.get(node_id)
        if parent is None:
            return []
        call_id, _ = parent
        return [TraversalEdge(call_id, "SYN_ARG_TO_CALL", "synthetic")]

    def call_argument_to_parameter_edges(self, node_id: int) -> list[TraversalEdge]:
        parent = self.index.call_parent_by_argument.get(node_id)
        if parent is None:
            return []
        call_id, index = parent
        function_id = self.index.invoked_function_by_call.get(call_id)
        if function_id is None:
            return []
        params = self.index.params_by_function.get(function_id, [])
        if index < 0 or index >= len(params):
            return []
        return [TraversalEdge(params[index], "SYN_CALL_ARG_TO_PARAM", "synthetic")]

    def return_to_call_assignment_edges(self, node_id: int) -> list[TraversalEdge]:
        function_id = self.index.function_by_node.get(node_id)
        if function_id is None:
            return []
        if node_id not in set(self.index.returns_by_function.get(function_id, [])):
            labels = self.graph.node_labels(node_id)
            if "Return" not in labels:
                return []
        edges: list[TraversalEdge] = []
        for call_id in self.index.callsites_by_function.get(function_id, []):
            for assignment in self.index.assignments_by_rhs.get(call_id, []):
                edges.append(
                    TraversalEdge(
                        assignment.lhs_node_id,
                        "SYN_RETURN_TO_CALL_ASSIGN",
                        "synthetic",
                    )
                )
        return edges

    def call_to_assignment_edges(self, node_id: int) -> list[TraversalEdge]:
        return [
            TraversalEdge(assignment.lhs_node_id, "SYN_CALL_TO_ASSIGN", "synthetic")
            for assignment in self.index.assignments_by_rhs.get(node_id, [])
        ]

    def function_summaries(self, paths: list[InterproceduralPath]) -> list[FunctionSummary]:
        function_ids: set[int] = set()
        for path in paths:
            for step in path["path"]:
                function_id = self.index.function_by_node.get(step["node"]["nodeId"])
                if function_id is not None:
                    function_ids.add(function_id)
        summaries: list[FunctionSummary] = []
        for function_id in sorted(function_ids):
            summaries.append(
                {
                    "node": self.graph.node_summary(function_id, max_code_chars=5000),
                    "parameters": [
                        self.graph.node_summary(node_id, max_code_chars=1000)
                        for node_id in self.index.params_by_function.get(function_id, [])
                    ],
                    "returnNodes": [
                        self.graph.node_summary(node_id, max_code_chars=1000)
                        for node_id in self.index.returns_by_function.get(function_id, [])
                    ],
                    "callSites": [
                        self.graph.node_summary(node_id, max_code_chars=1000)
                        for node_id in self.index.callsites_by_function.get(function_id, [])[:20]
                    ],
                }
            )
        return summaries[:40]


def build_function_index(graph: CPGGraph) -> FunctionIndex:
    function_ids = {
        node_id
        for node_id in graph.nodes_by_id
        if graph.node_labels(node_id) & {"Function", "Method"}
    }
    params_by_function = build_params_by_function(graph, function_ids)
    returns_by_function = build_returns_by_function(graph)
    invoked_function_by_call, callsites_by_function = build_callsite_indexes(graph)
    assignments_by_rhs = build_assignments_by_rhs(graph)
    call_parent_by_argument = build_call_parent_by_argument(graph)
    function_by_node = build_function_by_node(graph, function_ids)
    references_by_function_and_name = build_references_by_function_and_name(graph, function_by_node)
    return FunctionIndex(
        function_ids=function_ids,
        params_by_function=params_by_function,
        returns_by_function=returns_by_function,
        callsites_by_function=callsites_by_function,
        function_by_node=function_by_node,
        references_by_function_and_name=references_by_function_and_name,
        assignments_by_rhs=assignments_by_rhs,
        call_parent_by_argument=call_parent_by_argument,
        invoked_function_by_call=invoked_function_by_call,
    )


def build_params_by_function(graph: CPGGraph, function_ids: set[int]) -> dict[int, list[int]]:
    result: dict[int, list[int]] = {}
    for function_id in function_ids:
        params = [
            require_int(edge["endNode"], "edge.endNode")
            for edge in graph.outgoing_by_type(function_id, "PARAMETERS")
        ]
        result[function_id] = sorted(params, key=lambda node_id: node_sort_key(graph, node_id))
    return result


def build_returns_by_function(graph: CPGGraph) -> dict[int, list[int]]:
    result: dict[int, list[int]] = defaultdict(list)
    for node_id in graph.nodes_by_id:
        if "Return" not in graph.node_labels(node_id):
            continue
        function = graph.enclosing_with_label(node_id, {"Function", "Method"})
        if function is not None:
            result[function["nodeId"]].append(node_id)
    return {key: sorted(value, key=lambda node_id: node_sort_key(graph, node_id)) for key, value in result.items()}


def build_callsite_indexes(graph: CPGGraph) -> tuple[dict[int, int], dict[int, list[int]]]:
    invoked_function_by_call: dict[int, int] = {}
    callsites_by_function: dict[int, list[int]] = defaultdict(list)
    for edge in graph.edges:
        if edge.get("type") != "INVOKES":
            continue
        call_id = require_int(edge["startNode"], "edge.startNode")
        function_id = require_int(edge["endNode"], "edge.endNode")
        if function_id not in graph.nodes_by_id:
            continue
        if not graph.node_labels(function_id) & {"Function", "Method"}:
            continue
        invoked_function_by_call[call_id] = function_id
        callsites_by_function[function_id].append(call_id)
    return invoked_function_by_call, {
        key: sorted(value, key=lambda node_id: node_sort_key(graph, node_id))
        for key, value in callsites_by_function.items()
    }


def build_assignments_by_rhs(graph: CPGGraph) -> dict[int, list[Assignment]]:
    result: dict[int, list[Assignment]] = defaultdict(list)
    for edge in graph.edges:
        if edge.get("type") != "RHS":
            continue
        assign_id = require_int(edge["startNode"], "edge.startNode")
        rhs_id = require_int(edge["endNode"], "edge.endNode")
        lhs_edges = graph.outgoing_by_type(assign_id, "LHS")
        for lhs_edge in lhs_edges:
            lhs_id = require_int(lhs_edge["endNode"], "edge.endNode")
            result[rhs_id].append(Assignment(assign_id, lhs_id, rhs_id))
    return result


def build_call_parent_by_argument(graph: CPGGraph) -> dict[int, tuple[int, int]]:
    result: dict[int, tuple[int, int]] = {}
    for edge in graph.edges:
        if edge.get("type") not in {"ARGUMENTS", "OPERATOR_ARGUMENTS"}:
            continue
        call_id = require_int(edge["startNode"], "edge.startNode")
        argument_id = require_int(edge["endNode"], "edge.endNode")
        if "Call" not in graph.node_labels(call_id):
            continue
        result.setdefault(argument_id, (call_id, edge_index(edge)))
    return result


def build_function_by_node(graph: CPGGraph, function_ids: set[int]) -> dict[int, int]:
    functions = [
        graph.node_summary(function_id)
        for function_id in function_ids
    ]
    result: dict[int, int] = {}
    for node_id in graph.nodes_by_id:
        node = graph.node_summary(node_id)
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
            if start is None or end is None or start < 0 or end < 0:
                continue
            if start <= line <= end:
                span = end - start
                if best_span is None or span < best_span:
                    best_id = function["nodeId"]
                    best_span = span
        if best_id is not None:
            result[node_id] = best_id
    return result


def build_references_by_function_and_name(
    graph: CPGGraph,
    function_by_node: dict[int, int],
) -> dict[tuple[int, str], list[int]]:
    result: dict[tuple[int, str], list[int]] = defaultdict(list)
    for node_id, function_id in function_by_node.items():
        labels = graph.node_labels(node_id)
        if not labels & {"Reference", "Parameter"}:
            continue
        name = graph.node_summary(node_id)["name"]
        if not name:
            continue
        result[(function_id, name)].append(node_id)
    return {
        key: sorted(value, key=lambda node_id: node_sort_key(graph, node_id))
        for key, value in result.items()
    }


def build_sink_records(graph: CPGGraph) -> dict[int, SinkRecord]:
    records: dict[int, SinkRecord] = {}
    for node in graph.nodes:
        labels = node.get("labels", [])
        if not isinstance(labels, list) or "Call" not in labels:
            continue
        for sink in classify_sink(node):
            records[sink.node_id] = sink_record(graph, sink)
    return records


def dedupe_edges(edges: list[TraversalEdge]) -> list[TraversalEdge]:
    seen: set[tuple[int, str]] = set()
    deduped: list[TraversalEdge] = []
    for edge in edges:
        key = (edge.to_node, edge.edge_type)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(edge)
    return deduped


def edge_dependence(edge: dict[str, Any]) -> str | None:
    properties = edge.get("properties", {})
    if not isinstance(properties, dict):
        return None
    value = properties.get("dependence")
    return value if isinstance(value, str) else None


def edge_index(edge: dict[str, Any]) -> int:
    properties = edge.get("properties", {})
    if not isinstance(properties, dict):
        return 0
    index = properties.get("index")
    return index if isinstance(index, int) else 0


def node_sort_key(graph: CPGGraph, node_id: int) -> tuple[str, int, int]:
    node = graph.node_summary(node_id)
    return (
        node["artifact"] or "",
        node["startLine"] if node["startLine"] is not None else 10**9,
        node_id,
    )


def is_structured_parse_call(node: NodeSummary) -> bool:
    labels = set(node["labels"])
    if "Call" not in labels:
        return False
    code = (node["code"] or "").strip()
    return code.startswith(
        (
            "json.load(",
            "json.loads(",
            "yaml.safe_load(",
            "yaml.load(",
            "toml.load(",
            "toml.loads(",
            "pickle.load(",
            "pickle.loads(",
            "common_config.parse(",
        )
    )


def edge_type_counts(path: list[InterproceduralStep]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for step in path[1:]:
        edge = step["edgeFromPrevious"]
        if edge is not None:
            counter[edge["type"]] += 1
    return dict(sorted(counter.items()))


def synthetic_edge_count(path: list[InterproceduralStep]) -> int:
    return sum(
        1
        for step in path[1:]
        if step["edgeFromPrevious"] is not None
        and step["edgeFromPrevious"]["type"].startswith("SYN_")
    )


def load_context_index(path: Path | None) -> dict[int, dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    if not path.is_dir():
        raise ValueError(f"{path}: context expansion path must be a directory")
    index: dict[int, dict[str, Any]] = {}
    for item in sorted(path.glob("*_context_ok.json")):
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


def build_error_record(source: CandidateSource, index: int, error: Exception) -> InterproceduralError:
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
    return f"{index:06d}_{node_part}_interprocedural_{status}.json"


def default_output_dir(sources_path: Path) -> Path:
    if not sources_path.name.endswith(".sources.json"):
        raise ValueError(f"{sources_path}: sources filename must end with .sources.json")
    return sources_path.parent.parent / "outputs" / f"{sources_path.name.removesuffix('.sources.json')}_interprocedural_context"


def analyze_sources_to_dir(
    sources_path: Path,
    cpg_path: Path,
    context_expansion_dir: Path | None,
    output_dir: Path,
    max_depth: int,
    max_paths: int,
    max_nodes: int,
    max_same_name_uses: int,
    parallel_workers: int,
    limit: int | None,
) -> None:
    if parallel_workers < 1:
        raise ValueError("parallel_workers must be >= 1")

    graph = CPGGraph.from_json(cpg_path)
    sources = load_candidate_sources(sources_path)
    if limit is not None:
        sources = sources[:limit]

    builder = InterproceduralContextBuilder(
        graph=graph,
        sink_records=build_sink_records(graph),
        context_by_source=load_context_index(context_expansion_dir),
        max_depth=max_depth,
        max_paths=max_paths,
        max_nodes=max_nodes,
        max_same_name_uses=max_same_name_uses,
    )

    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"{output_dir}: output path must be a directory")
    output_dir.mkdir(parents=True, exist_ok=True)

    summaries: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
        futures = {
            executor.submit(builder.analyze_source, source, index): (index, source)
            for index, source in enumerate(sources, start=1)
        }
        completed = 0
        for future in as_completed(futures):
            index, source = futures[future]
            try:
                record: InterproceduralOutput = future.result()
            except Exception as error:
                record = build_error_record(source, index, error)
            output_file = output_dir / output_filename(source, index, record["status"])
            write_pretty_json(output_file, record)
            summaries.append(
                {
                    "index": index,
                    "sourceNodeId": record["sourceNodeId"],
                    "status": record["status"],
                    "file": output_file.name,
                }
            )
            completed += 1
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
            "contextExpansionDir": str(context_expansion_dir) if context_expansion_dir is not None else None,
            "outputDir": str(output_dir),
            "sourceCount": len(sources),
            "maxDepth": max_depth,
            "maxPaths": max_paths,
            "maxNodes": max_nodes,
            "maxSameNameUses": max_same_name_uses,
            "parallelWorkers": parallel_workers,
            "results": sorted(summaries, key=lambda item: item["index"]),
        },
    )


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    env_file = os.getenv(
        "INTERPROCEDURAL_CONTEXT_ENV_FILE",
        str(base_dir / "config" / "interprocedural_context.env"),
    )
    load_env(env_file)

    sources_path = env_path("INTERPROCEDURAL_CONTEXT_SOURCES")
    output_dir = env_optional_path("INTERPROCEDURAL_CONTEXT_OUTPUT")
    if output_dir is None:
        output_dir = default_output_dir(sources_path)

    analyze_sources_to_dir(
        sources_path=sources_path,
        cpg_path=env_path("INTERPROCEDURAL_CONTEXT_CPG"),
        context_expansion_dir=env_optional_path("INTERPROCEDURAL_CONTEXT_EXPANSION_DIR"),
        output_dir=output_dir,
        max_depth=env_int("INTERPROCEDURAL_CONTEXT_MAX_DEPTH"),
        max_paths=env_int("INTERPROCEDURAL_CONTEXT_MAX_PATHS"),
        max_nodes=env_int("INTERPROCEDURAL_CONTEXT_MAX_NODES"),
        max_same_name_uses=env_int("INTERPROCEDURAL_CONTEXT_MAX_SAME_NAME_USES"),
        parallel_workers=env_int("INTERPROCEDURAL_CONTEXT_PARALLEL_WORKERS"),
        limit=env_optional_int("INTERPROCEDURAL_CONTEXT_LIMIT"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
