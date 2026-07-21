from __future__ import annotations

from collections import Counter, deque
from typing import Any

from sink_finder_pipe.graph import CPGGraph
from sink_finder_pipe.rules import SinkFinderRules


class SinkPathSearch:
    def __init__(self, graph: CPGGraph, rules: SinkFinderRules, sinks: list[dict[str, Any]]) -> None:
        self.graph = graph
        self.rules = rules
        self.sinks = sinks
        self.sinks_by_id = {sink["nodeId"]: sink for sink in sinks}
        self.max_depth = self.int_setting(rules.search()["max_depth"], "search.max_depth")
        self.max_paths = self.int_setting(rules.search()["max_paths_per_source"], "search.max_paths_per_source")

    def analyze_source(self, source: dict[str, Any], index: int) -> dict[str, Any]:
        seeds = self.seed_paths(source)
        paths = self.find_paths(seeds)
        return {
            "status": "ok",
            "index": index,
            "sourceNodeId": self.source_node_id(source),
            "source": source,
            "seedNodes": [path[-1] for path in seeds],
            "reachableSinkCount": len(paths),
            "paths": paths,
            "search": {
                "maxDepth": self.max_depth,
                "maxPathsPerSource": self.max_paths,
                "sinkCandidateCount": len(self.sinks),
                "rulesFile": str(self.rules.path),
                "directedTraversalEdges": self.rules.traversal()["directed_edges"],
                "structuralTraversalEdges": self.rules.traversal()["structural_edges"],
            },
        }

    def seed_paths(self, source: dict[str, Any]) -> list[list[dict[str, Any]]]:
        source_node_id = self.source_node_id(source)
        paths: dict[int, list[dict[str, Any]]] = {
            source_node_id: [self.path_step("source", None, source_node_id)]
        }

        def add_seed(node_id: int, role: str, edge_type: str, previous_node_id: int | None = None) -> None:
            if node_id in paths:
                return
            base = paths.get(previous_node_id) if previous_node_id is not None else paths[source_node_id]
            if base is None:
                return
            paths[node_id] = base + [self.path_step(role, {"type": edge_type, "direction": "synthetic"}, node_id)]

        for seed in self.rules.source_seeds():
            kind = seed["type"]
            if kind == "object_field":
                item = source.get(seed["field"])
                if isinstance(item, dict) and isinstance(item.get(seed["node_id_key"]), int):
                    add_seed(item[seed["node_id_key"]], seed["role"], seed["edge_type"])
            elif kind == "list_field":
                items = source.get(seed["field"], [])
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict) and isinstance(item.get(seed["node_id_key"]), int):
                            add_seed(item[seed["node_id_key"]], seed["role"], seed["edge_type"])
            elif kind == "related_uses":
                self.add_related_use_seeds(source, seed, add_seed)
            else:
                raise ValueError(f"unsupported source seed type: {kind}")
        return list(paths.values())

    def add_related_use_seeds(self, source: dict[str, Any], seed: dict[str, Any], add_seed: Any) -> None:
        items = source.get(seed["field"], [])
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            related_id = item.get(seed["node_id_key"])
            if isinstance(related_id, int):
                add_seed(related_id, seed["role"], seed["edge_type"])
            parents = item.get(seed["parent_field"], [])
            if not isinstance(parents, list):
                continue
            for parent in parents:
                if not isinstance(parent, dict) or not isinstance(parent.get(seed["parent_node_id_key"]), int):
                    continue
                relation = parent.get("relation", "UNKNOWN")
                edge_type = f"{seed['parent_edge_type_prefix']}:{relation}"
                add_seed(parent[seed["parent_node_id_key"]], seed["parent_role"], edge_type, related_id if isinstance(related_id, int) else None)

    def find_paths(self, seeds: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        found_sinks: set[int] = set()
        queue: deque[tuple[int, list[dict[str, Any]], int]] = deque()
        best_depth: dict[int, int] = {}
        for seed in seeds:
            node_id = seed[-1]["node"]["nodeId"]
            queue.append((node_id, seed, 0))
            best_depth[node_id] = 0

        while queue and len(results) < self.max_paths:
            node_id, path, depth = queue.popleft()
            if node_id in self.sinks_by_id and node_id not in found_sinks:
                found_sinks.add(node_id)
                sink = self.sinks_by_id[node_id]
                results.append(
                    {
                        "sink": self.graph.sink_record(sink),
                        "pathLength": len(path),
                        "evidence": self.path_evidence(path, node_id),
                        "path": path,
                    }
                )
                continue
            if depth >= self.max_depth:
                continue
            for edge in self.graph.adjacency.get(node_id, []):
                next_depth = depth + 1
                target_id = edge["to"]
                if best_depth.get(target_id, 10**9) <= next_depth:
                    continue
                best_depth[target_id] = next_depth
                queue.append((target_id, path + [self.path_step("graph_node", {"type": edge["type"], "direction": edge["direction"]}, target_id)], next_depth))
        return results

    def path_evidence(self, path: list[dict[str, Any]], sink_node_id: int) -> dict[str, Any]:
        edge_types: Counter[str] = Counter()
        edge_directions: Counter[str] = Counter()
        for step in path[1:]:
            edge = step["edgeFromPrevious"]
            edge_types[edge["type"]] += 1
            edge_directions[f"{edge['direction']}:{edge['type']}"] += 1

        path_node_ids = {step["node"]["nodeId"] for step in path}
        sink_argument_ids = {arg["node"]["nodeId"] for arg in self.graph.sink_arguments(sink_node_id)}
        sink_dependency_ids = {
            node["nodeId"]
            for node in self.graph.incoming_dependencies(sink_node_id, self.rules.context()["incoming_data_dependencies"])
        }
        argument_hits = sorted(path_node_ids & sink_argument_ids)
        dependency_hits = sorted(path_node_ids & sink_dependency_ids)
        has_source_summary = any(edge_type.startswith("SOURCE_") for edge_type in edge_types)
        direct_arg = bool(argument_hits) and (edge_types["DFG"] > 0 or has_source_summary)
        direct_call = bool(dependency_hits) and (edge_types["DFG"] > 0 or has_source_summary)
        structural = set(self.rules.traversal()["structural_edges"])
        return {
            "pathQuality": self.path_quality(edge_types, direct_arg, direct_call),
            "edgeTypeCounts": dict(sorted(edge_types.items())),
            "edgeDirectionCounts": dict(sorted(edge_directions.items())),
            "hasDirectDataflowToSinkArgument": direct_arg,
            "hasDirectDataflowToSinkCall": direct_call,
            "hasControlOnlyFlow": edge_types["CDG"] > 0 and edge_types["DFG"] == 0,
            "structuralStepCount": sum(edge_types[edge_type] for edge_type in structural),
            "crossArtifactJumpCount": self.cross_artifact_jumps(path),
            "sinkArgumentNodeIdsInPath": argument_hits,
            "sinkDataDependencyNodeIdsInPath": dependency_hits,
        }

    @staticmethod
    def path_quality(edge_types: Counter[str], direct_arg: bool, direct_call: bool) -> str:
        if direct_arg:
            return "dataflow_to_sink_argument"
        if direct_call:
            return "dataflow_to_sink_call"
        if edge_types["DFG"] > 0 or edge_types["PDG"] > 0:
            return "mixed"
        if edge_types["CDG"] > 0:
            return "control_only"
        return "structural_only"

    @staticmethod
    def cross_artifact_jumps(path: list[dict[str, Any]]) -> int:
        jumps = 0
        previous: str | None = None
        for step in path:
            artifact = step["node"].get("artifact")
            if artifact is not None and previous is not None and artifact != previous:
                jumps += 1
            if artifact is not None:
                previous = artifact
        return jumps

    def path_step(self, role: str, edge: dict[str, str] | None, node_id: int) -> dict[str, Any]:
        return {"role": role, "edgeFromPrevious": edge, "node": self.graph.node_summary(node_id)}

    @staticmethod
    def source_node_id(source: dict[str, Any]) -> int:
        node_id = source.get("nodeId")
        if not isinstance(node_id, int):
            raise TypeError("source.nodeId must be an int")
        return node_id

    @staticmethod
    def int_setting(value: Any, name: str) -> int:
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an int")
        return value
