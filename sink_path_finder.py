#!/usr/bin/env python3
"""Find sink candidates and source-to-sink paths in a CPG JSON export."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast


DIRECTED_TRAVERSAL_EDGES: set[str] = {
    "DFG",
    "PDG",
    "EOG",
    "CDG",
    "INVOKES",
}

STRUCTURAL_TRAVERSAL_EDGES: set[str] = {
    "ARGUMENTS",
    "OPERATOR_ARGUMENTS",
    "AST",
    "BASE",
    "OPERATOR_BASE",
    "LHS",
    "RHS",
    "VALUE",
    "KEY",
    "RECEIVER",
    "CONDITION",
    "BRANCHED_BY",
}

TraversalDirection = Literal["forward", "reverse", "synthetic"]
SinkSeverity = Literal["low", "medium", "high"]


class CandidateSource(TypedDict, total=False):
    nodeId: int
    language: str
    ruleId: str
    kind: str
    detail: str | None
    confidence: str
    reason: str
    artifact: str
    startLine: int
    endLine: int
    labels: list[str]
    name: str
    fullName: str
    code: str
    assignedTo: dict[str, Any] | None
    enclosingFunction: dict[str, Any]
    dataflow: list[dict[str, Any]]
    relatedUses: list[dict[str, Any]]


class NodeSummary(TypedDict):
    nodeId: int
    labels: list[str]
    artifact: str | None
    startLine: int | None
    endLine: int | None
    name: str | None
    fullName: str | None
    code: str | None


class PathEdge(TypedDict):
    type: str
    direction: TraversalDirection


class PathStep(TypedDict):
    role: str
    edgeFromPrevious: PathEdge | None
    node: NodeSummary


class SinkRecord(TypedDict):
    nodeId: int
    kind: str
    ruleId: str
    severity: SinkSeverity
    evidence: str
    node: NodeSummary


class SinkPathRecord(TypedDict):
    sink: SinkRecord
    pathLength: int
    path: list[PathStep]


class SourceSinkResult(TypedDict):
    status: Literal["ok"]
    index: int
    sourceNodeId: int
    source: CandidateSource
    seedNodes: list[PathStep]
    reachableSinkCount: int
    paths: list[SinkPathRecord]
    search: dict[str, Any]


class SourceSinkError(TypedDict):
    status: Literal["error"]
    index: int
    sourceNodeId: int | None
    source: CandidateSource
    error: dict[str, str]


SourceSinkOutput = SourceSinkResult | SourceSinkError


@dataclass(frozen=True)
class TraversalEdge:
    to_node: int
    edge_type: str
    direction: TraversalDirection


@dataclass(frozen=True)
class SinkCandidate:
    node_id: int
    kind: str
    rule_id: str
    severity: SinkSeverity
    evidence: str


class CPGGraph:
    def __init__(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
        self.nodes = nodes
        self.edges = edges
        self.nodes_by_id = {require_int(node["id"], "node.id"): node for node in nodes}
        self.adjacency = self._build_adjacency(edges)

    @classmethod
    def from_json(cls, path: Path) -> CPGGraph:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError(f"{path}: expected CPG JSON object")
        nodes = data["nodes"]
        edges = data["edges"]
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise TypeError(f"{path}: nodes and edges must be lists")
        return cls(cast(list[dict[str, Any]], nodes), cast(list[dict[str, Any]], edges))

    def _build_adjacency(self, edges: list[dict[str, Any]]) -> dict[int, list[TraversalEdge]]:
        adjacency: dict[int, list[TraversalEdge]] = defaultdict(list)
        for edge in edges:
            edge_type = require_str(edge["type"], "edge.type")
            start = require_int(edge["startNode"], "edge.startNode")
            end = require_int(edge["endNode"], "edge.endNode")
            if start not in self.nodes_by_id or end not in self.nodes_by_id:
                continue
            if edge_type in DIRECTED_TRAVERSAL_EDGES:
                adjacency[start].append(TraversalEdge(end, edge_type, "forward"))
            if edge_type in STRUCTURAL_TRAVERSAL_EDGES:
                adjacency[start].append(TraversalEdge(end, edge_type, "forward"))
                adjacency[end].append(TraversalEdge(start, edge_type, "reverse"))
        return adjacency

    def node_summary(self, node_id: int) -> NodeSummary:
        node = self.nodes_by_id[node_id]
        properties = node.get("properties", {})
        if not isinstance(properties, dict):
            raise TypeError(f"node {node_id}: properties must be an object")
        labels = node.get("labels", [])
        if not isinstance(labels, list):
            raise TypeError(f"node {node_id}: labels must be a list")
        return {
            "nodeId": node_id,
            "labels": cast(list[str], labels),
            "artifact": optional_str(properties.get("artifact")),
            "startLine": optional_int(properties.get("startLine")),
            "endLine": optional_int(properties.get("endLine")),
            "name": optional_str(properties.get("name")),
            "fullName": optional_str(properties.get("fullName")),
            "code": optional_str(properties.get("code")),
        }

    def find_sink_candidates(self) -> list[SinkCandidate]:
        sinks: list[SinkCandidate] = []
        for node in self.nodes:
            labels = node.get("labels", [])
            if not isinstance(labels, list) or "Call" not in labels:
                continue
            sinks.extend(classify_sink(node))
        return sinks


class SinkPathFinder:
    def __init__(
        self,
        graph: CPGGraph,
        sink_candidates: list[SinkCandidate],
        max_depth: int,
        max_paths_per_source: int,
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if max_paths_per_source < 1:
            raise ValueError("max_paths_per_source must be >= 1")
        self.graph = graph
        self.sink_candidates = sink_candidates
        self.sinks_by_id = {sink.node_id: sink for sink in sink_candidates}
        self.max_depth = max_depth
        self.max_paths_per_source = max_paths_per_source

    def analyze_source(self, source: CandidateSource, index: int) -> SourceSinkResult:
        source_node_id = require_int(source["nodeId"], "source.nodeId")
        seed_paths = self._seed_paths(source)
        paths = self._find_paths(seed_paths)
        return {
            "status": "ok",
            "index": index,
            "sourceNodeId": source_node_id,
            "source": source,
            "seedNodes": [steps[-1] for steps in seed_paths],
            "reachableSinkCount": len(paths),
            "paths": paths,
            "search": {
                "maxDepth": self.max_depth,
                "maxPathsPerSource": self.max_paths_per_source,
                "sinkCandidateCount": len(self.sink_candidates),
                "directedTraversalEdges": sorted(DIRECTED_TRAVERSAL_EDGES),
                "structuralTraversalEdges": sorted(STRUCTURAL_TRAVERSAL_EDGES),
            },
        }

    def _seed_paths(self, source: CandidateSource) -> list[list[PathStep]]:
        source_node_id = require_int(source["nodeId"], "source.nodeId")
        paths: dict[int, list[PathStep]] = {
            source_node_id: [
                {
                    "role": "source",
                    "edgeFromPrevious": None,
                    "node": self.graph.node_summary(source_node_id),
                }
            ]
        }

        def add_seed(node_id: int, role: str, edge_type: str) -> None:
            if node_id in paths:
                return
            paths[node_id] = [
                paths[source_node_id][0],
                {
                    "role": role,
                    "edgeFromPrevious": {"type": edge_type, "direction": "synthetic"},
                    "node": self.graph.node_summary(node_id),
                },
            ]

        assigned = source.get("assignedTo")
        if isinstance(assigned, dict) and isinstance(assigned.get("nodeId"), int):
            add_seed(assigned["nodeId"], "assigned_to", "SOURCE_ASSIGNED_TO")

        for item in source.get("dataflow", []):
            if isinstance(item, dict) and isinstance(item.get("nodeId"), int):
                add_seed(item["nodeId"], "source_dataflow", "SOURCE_DATAFLOW_SUMMARY")

        for related_use in source.get("relatedUses", []):
            if not isinstance(related_use, dict):
                continue
            if isinstance(related_use.get("nodeId"), int):
                add_seed(related_use["nodeId"], "related_use", "SOURCE_RELATED_USE")
            parents = related_use.get("parents", [])
            if isinstance(parents, list):
                for parent in parents:
                    if isinstance(parent, dict) and isinstance(parent.get("nodeId"), int):
                        add_seed(
                            parent["nodeId"],
                            "related_use_parent",
                            f"SOURCE_RELATED_USE_PARENT:{parent.get('relation', 'UNKNOWN')}",
                        )

        return list(paths.values())

    def _find_paths(self, seed_paths: list[list[PathStep]]) -> list[SinkPathRecord]:
        results: list[SinkPathRecord] = []
        found_sinks: set[int] = set()
        queue: deque[tuple[int, list[PathStep], int]] = deque()
        best_depth: dict[int, int] = {}

        for seed_path in seed_paths:
            seed_id = seed_path[-1]["node"]["nodeId"]
            queue.append((seed_id, seed_path, 0))
            best_depth[seed_id] = 0

        while queue and len(results) < self.max_paths_per_source:
            current_id, path, depth = queue.popleft()
            if current_id in self.sinks_by_id and current_id not in found_sinks:
                found_sinks.add(current_id)
                sink = self.sinks_by_id[current_id]
                results.append(
                    {
                        "sink": sink_record(self.graph, sink),
                        "pathLength": len(path),
                        "path": path,
                    }
                )
                continue

            if depth >= self.max_depth:
                continue

            for edge in self.graph.adjacency.get(current_id, []):
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
                                "role": "graph_node",
                                "edgeFromPrevious": {
                                    "type": edge.edge_type,
                                    "direction": edge.direction,
                                },
                                "node": self.graph.node_summary(edge.to_node),
                            }
                        ],
                        next_depth,
                    )
                )

        return results


def classify_sink(node: dict[str, Any]) -> list[SinkCandidate]:
    node_id = require_int(node["id"], "node.id")
    properties = node.get("properties", {})
    if not isinstance(properties, dict):
        raise TypeError(f"node {node_id}: properties must be an object")

    name = str(properties.get("name", ""))
    full_name = str(properties.get("fullName", ""))
    code = str(properties.get("code", ""))
    haystack = f"{name}\n{full_name}\n{code}".lower()
    sinks: list[SinkCandidate] = []

    def add(kind: str, rule_id: str, severity: SinkSeverity, evidence: str) -> None:
        sinks.append(SinkCandidate(node_id, kind, rule_id, severity, evidence))

    if re.search(r"\bos\.system\s*\(|\bos\.popen\s*\(", code) or (
        "subprocess." in code
        and any(token in haystack for token in ("popen", "call", "run", "check_output", "check_call"))
    ):
        add("command_execution", "python-command-execution-call", "high", code)

    if re.search(r"\beval\s*\(|\bexec\s*\(", code) or "exec_module" in haystack:
        add("code_execution", "python-dynamic-code-execution", "high", code)

    if name == "open" or re.search(r"\bopen\s*\(", code):
        if re.search(r"""['"][wax+][^'"]*['"]""", code):
            add("filesystem_write", "python-open-write", "medium", code)
        else:
            add("filesystem_read", "python-open-read", "medium", code)

    if any(token in haystack for token in ("copyfile", "copytree", "copy2", "rmtree", "remove", "move", "copystat")):
        add("filesystem_mutation", "python-filesystem-mutation", "medium", code)

    if re.search(r"\.write\s*\(", code) or ".write" in name.lower():
        add("filesystem_write", "python-write-call", "medium", code)

    if "requests." in code and any(method in haystack for method in ("get", "post", "put", "delete", "patch")):
        add("network_request", "python-network-request", "medium", code)

    if any(token in haystack for token in ("pickle.load", "pickle.loads", "yaml.load", "json.load")):
        add("structured_parse", "python-structured-data-load", "medium", code)

    if any(token in haystack for token in ("jinja2.environment", "filesystemloader", "dictloader", "get_template", ".render")):
        add("template_rendering", "python-template-rendering", "medium", code)

    if any(token in haystack for token in ("tarfile.open", "extractall", ".extract(")):
        add("archive_operation", "python-archive-operation", "medium", code)

    if re.search(r"\.execute\s*\(|\.executemany\s*\(", code):
        add("sql_execution", "python-sql-execution", "high", code)

    return sinks


def sink_record(graph: CPGGraph, sink: SinkCandidate) -> SinkRecord:
    return {
        "nodeId": sink.node_id,
        "kind": sink.kind,
        "ruleId": sink.rule_id,
        "severity": sink.severity,
        "evidence": sink.evidence,
        "node": graph.node_summary(sink.node_id),
    }


def load_candidate_sources(path: Path) -> list[CandidateSource]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path}: expected top-level sources object")
    candidate_sources = data["candidateSources"]
    if not isinstance(candidate_sources, list):
        raise TypeError(f"{path}: candidateSources must be a list")
    for item in candidate_sources:
        if not isinstance(item, dict):
            raise TypeError(f"{path}: every candidate source must be an object")
    return cast(list[CandidateSource], candidate_sources)


def output_dir_for_sources(sources_path: str | Path) -> Path:
    path = Path(sources_path)
    if not path.name.endswith(".sources.json"):
        raise ValueError(f"{path}: sources filename must end with .sources.json")
    return path.parent.parent / "outputs" / f"{path.name.removesuffix('.sources.json')}_sink_paths"


def write_pretty_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def source_output_filename(source: CandidateSource, index: int, status: str) -> str:
    node_id = source.get("nodeId")
    node_part = f"node_{node_id}" if isinstance(node_id, int) else "node_unknown"
    return f"{index:06d}_{node_part}_{status}.json"


def analyze_sources_to_dir(
    sources_path: Path,
    cpg_path: Path,
    output_dir: Path,
    max_depth: int,
    max_paths_per_source: int,
    parallel_workers: int,
) -> None:
    if parallel_workers < 1:
        raise ValueError("parallel_workers must be >= 1")

    graph = CPGGraph.from_json(cpg_path)
    sources = load_candidate_sources(sources_path)
    sink_candidates = graph.find_sink_candidates()
    finder = SinkPathFinder(graph, sink_candidates, max_depth, max_paths_per_source)

    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"{output_dir}: output path must be a directory")
    output_dir.mkdir(parents=True, exist_ok=True)
    write_pretty_json(
        output_dir / "sink_candidates.json",
        [sink_record(graph, sink) for sink in sink_candidates],
    )

    source_summaries: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
        futures = {
            executor.submit(finder.analyze_source, source, index): (index, source)
            for index, source in enumerate(sources, start=1)
        }
        completed = 0
        for future in as_completed(futures):
            index, source = futures[future]
            try:
                result: SourceSinkOutput = future.result()
            except Exception as error:
                result = {
                    "status": "error",
                    "index": index,
                    "sourceNodeId": source.get("nodeId") if isinstance(source.get("nodeId"), int) else None,
                    "source": source,
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                }

            output_file = output_dir / source_output_filename(source, index, result["status"])
            write_pretty_json(output_file, result)
            source_summaries.append(
                {
                    "index": index,
                    "sourceNodeId": result.get("sourceNodeId"),
                    "status": result["status"],
                    "reachableSinkCount": result.get("reachableSinkCount", 0),
                    "file": output_file.name,
                }
            )
            completed += 1
            print(
                f"[{completed}/{len(sources)}] saved {result['status']} "
                f"sourceNodeId={result.get('sourceNodeId')} -> {output_file}",
                file=sys.stderr,
            )

    write_pretty_json(
        output_dir / "summary.json",
        {
            "status": "ok",
            "sourcesFile": str(sources_path),
            "cpgFile": str(cpg_path),
            "outputDir": str(output_dir),
            "sourceCount": len(sources),
            "sinkCandidateCount": len(sink_candidates),
            "maxDepth": max_depth,
            "maxPathsPerSource": max_paths_per_source,
            "parallelWorkers": parallel_workers,
            "sources": sorted(source_summaries, key=lambda item: item["index"]),
        },
    )


def require_int(value: Any, field: str) -> int:
    if not isinstance(value, int):
        raise TypeError(f"{field} must be int")
    return value


def require_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be str")
    return value


def optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        return None
    return value


def optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    return value


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    default_sources = base_dir / "data" / "openstack__kolla__2a4a8fce31c1.sources.json"
    default_cpg = base_dir / "data" / "openstack__kolla__2a4a8fce31c1.json"

    parser = argparse.ArgumentParser(description="Find source-to-sink paths in CPG JSON.")
    parser.add_argument("--sources", default=default_sources, help="Path to *.sources.json.")
    parser.add_argument("--cpg", default=default_cpg, help="Path to full CPG JSON.")
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory for per-source sink path JSON files.",
    )
    parser.add_argument("--max-depth", type=int, default=8, help="Max graph traversal depth.")
    parser.add_argument(
        "--parallel-workers",
        type=int,
        default=4,
        help="Number of source path extraction workers.",
    )
    parser.add_argument(
        "--max-paths-per-source",
        type=int,
        default=25,
        help="Max reachable sink paths saved for each source.",
    )
    args = parser.parse_args()

    sources_path = Path(args.sources)
    output_dir = Path(args.output) if args.output is not None else output_dir_for_sources(sources_path)
    analyze_sources_to_dir(
        sources_path=sources_path,
        cpg_path=Path(args.cpg),
        output_dir=output_dir,
        max_depth=args.max_depth,
        max_paths_per_source=args.max_paths_per_source,
        parallel_workers=args.parallel_workers,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
