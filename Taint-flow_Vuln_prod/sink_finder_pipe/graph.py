from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

from sink_finder_pipe.rules import SinkFinderRules


class CPGGraph:
    def __init__(self, path: Path, rules: SinkFinderRules) -> None:
        self.rules = rules
        data = self.read_json(path)
        self.nodes = [self.object_value(node, "node") for node in self.list_value(data["nodes"], "nodes")]
        self.edges = [self.object_value(edge, "edge") for edge in self.list_value(data["edges"], "edges")]
        self.nodes_by_id = {self.node_id(node): node for node in self.nodes}
        self.outgoing = self.index_edges("startNode")
        self.incoming = self.index_edges("endNode")
        self.adjacency = self.build_adjacency()

    def find_sink_candidates(self) -> list[dict[str, Any]]:
        sinks: list[dict[str, Any]] = []
        for node in self.nodes:
            sinks.extend(self.rules.classify_sink(node))
        return sinks

    def sink_record(self, sink: dict[str, Any]) -> dict[str, Any]:
        return {
            **sink,
            "node": self.node_summary(sink["nodeId"], self.context_int("sink_node_max_code_chars")),
            "context": self.sink_context(sink["nodeId"]),
        }

    def sink_context(self, node_id: int) -> dict[str, Any]:
        context = self.rules.context()
        return {
            "enclosingFunction": self.enclosing(node_id, context["enclosing_function"]),
            "enclosingNamespace": self.enclosing(node_id, context["enclosing_namespace"]),
            "base": self.first_connected_summary(node_id, self.string_list(context["base_edges"], "base_edges")),
            "receiver": self.first_connected_summary(node_id, self.string_list(context["receiver_edges"], "receiver_edges")),
            "arguments": self.sink_arguments(node_id),
            "incomingDataDependencies": self.incoming_dependencies(node_id, context["incoming_data_dependencies"]),
            "incomingControlDependencies": self.incoming_dependencies(node_id, context["incoming_control_dependencies"]),
            "parentStatements": self.parent_statements(node_id),
        }

    def sink_arguments(self, node_id: int) -> list[dict[str, Any]]:
        context = self.rules.context()
        roles = self.object_value(context["argument_roles"], "argument_roles")
        edges: list[dict[str, Any]] = []
        for edge_type in self.string_list(context["argument_edges"], "argument_edges"):
            edges.extend(self.outgoing_by_type(node_id, edge_type))
        args: list[dict[str, Any]] = []
        seen: set[int] = set()
        for edge in sorted(edges, key=self.edge_index):
            target_id = self.int_value(edge["endNode"], "edge.endNode")
            if target_id in seen:
                continue
            seen.add(target_id)
            index = self.edge_index(edge)
            args.append(
                {
                    "index": index,
                    "role": roles.get(str(index), f"argument_{index}"),
                    "node": self.node_summary(target_id, self.dependency_max_code_chars("incoming_data_dependencies")),
                    "incomingDataDependencies": self.incoming_dependencies(target_id, context["incoming_data_dependencies"]),
                }
            )
        return args

    def incoming_dependencies(self, node_id: int, config: dict[str, Any]) -> list[dict[str, Any]]:
        edge_types = set(self.string_list(config["edge_types"], "dependency.edge_types"))
        dependence = config.get("dependence")
        limit = self.int_value(config["limit"], "dependency.limit")
        max_code = self.int_value(config["max_code_chars"], "dependency.max_code_chars")
        result: list[dict[str, Any]] = []
        seen: set[int] = set()
        for edge in self.incoming.get(node_id, []):
            if edge.get("type") not in edge_types:
                continue
            properties = self.object_value(edge.get("properties", {}), "edge.properties")
            if dependence is not None and properties.get("dependence") != dependence:
                continue
            start_id = self.int_value(edge["startNode"], "edge.startNode")
            if start_id in seen or start_id not in self.nodes_by_id:
                continue
            seen.add(start_id)
            result.append(self.node_summary(start_id, max_code))
            if len(result) >= limit:
                break
        return result

    def parent_statements(self, node_id: int) -> list[dict[str, Any]]:
        config = self.object_value(self.rules.context()["parent_statements"], "parent_statements")
        labels = set(self.string_list(config["labels_any"], "parent labels"))
        limit = self.int_value(config["limit"], "parent limit")
        max_code = self.int_value(config["max_code_chars"], "parent max code")
        result: list[dict[str, Any]] = []
        for ancestor_id in self.ancestors(node_id, self.int_value(config["max_depth"], "parent max depth")):
            if not labels.isdisjoint(self.node_labels(ancestor_id)):
                result.append(self.node_summary(ancestor_id, max_code))
                if len(result) >= limit:
                    break
        return result

    def enclosing(self, node_id: int, config: dict[str, Any]) -> dict[str, Any] | None:
        labels = set(self.string_list(config["labels_any"], "enclosing labels"))
        for ancestor_id in self.ancestors(node_id, self.int_value(config["max_depth"], "enclosing max_depth")):
            if not labels.isdisjoint(self.node_labels(ancestor_id)):
                return self.node_summary(ancestor_id, self.int_value(config["max_code_chars"], "enclosing max_code_chars"))
        return None

    def ancestors(self, node_id: int, max_depth: int) -> list[int]:
        result: list[int] = []
        current = node_id
        seen: set[int] = set()
        for _ in range(max_depth):
            parent = self.ast_parent(current)
            if parent is None or parent in seen:
                break
            seen.add(parent)
            result.append(parent)
            current = parent
        return result

    def ast_parent(self, node_id: int) -> int | None:
        edges = self.incoming_by_type(node_id, "AST")
        return self.int_value(edges[0]["startNode"], "edge.startNode") if edges else None

    def first_connected_summary(self, node_id: int, edge_types: list[str]) -> dict[str, Any] | None:
        for edge_type in edge_types:
            edges = self.outgoing_by_type(node_id, edge_type)
            if edges:
                return self.node_summary(self.int_value(sorted(edges, key=self.edge_index)[0]["endNode"], "edge.endNode"))
        return None

    def node_summary(self, node_id: int, max_code_chars: int | None = None) -> dict[str, Any]:
        node = self.nodes_by_id[node_id]
        props = self.object_value(node.get("properties", {}), "node.properties")
        code = self.text_or_none(props.get("code"), "node.code")
        if code is not None and max_code_chars is not None and len(code) > max_code_chars:
            code = code[:max_code_chars] + "\n...<truncated>"
        return {
            "nodeId": node_id,
            "labels": self.labels(node),
            "artifact": self.text_or_none(props.get("artifact"), "artifact"),
            "startLine": self.int_or_none(props.get("startLine"), "startLine"),
            "endLine": self.int_or_none(props.get("endLine"), "endLine"),
            "name": self.text_or_none(props.get("name"), "name"),
            "fullName": self.text_or_none(props.get("fullName"), "fullName"),
            "code": code,
        }

    def build_adjacency(self) -> dict[int, list[dict[str, Any]]]:
        traversal = self.rules.traversal()
        directed = set(self.string_list(traversal["directed_edges"], "directed_edges"))
        structural = set(self.string_list(traversal["structural_edges"], "structural_edges"))
        adjacency: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for edge in self.edges:
            edge_type = self.str_value(edge["type"], "edge.type")
            start = self.int_value(edge["startNode"], "edge.startNode")
            end = self.int_value(edge["endNode"], "edge.endNode")
            if start not in self.nodes_by_id or end not in self.nodes_by_id:
                continue
            if edge_type in directed:
                adjacency[start].append({"to": end, "type": edge_type, "direction": "forward"})
            if edge_type in structural:
                adjacency[start].append({"to": end, "type": edge_type, "direction": "forward"})
                adjacency[end].append({"to": start, "type": edge_type, "direction": "reverse"})
        return adjacency

    def index_edges(self, endpoint: str) -> dict[int, list[dict[str, Any]]]:
        result: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for edge in self.edges:
            result[self.int_value(edge[endpoint], f"edge.{endpoint}")].append(edge)
        return result

    def outgoing_by_type(self, node_id: int, edge_type: str) -> list[dict[str, Any]]:
        return [edge for edge in self.outgoing.get(node_id, []) if edge.get("type") == edge_type]

    def incoming_by_type(self, node_id: int, edge_type: str) -> list[dict[str, Any]]:
        return [edge for edge in self.incoming.get(node_id, []) if edge.get("type") == edge_type]

    def node_labels(self, node_id: int) -> set[str]:
        return set(self.labels(self.nodes_by_id[node_id]))

    def labels(self, node: dict[str, Any]) -> list[str]:
        return self.string_list(node.get("labels", []), "node.labels")

    def node_id(self, node: dict[str, Any]) -> int:
        return self.int_value(node["id"], "node.id")

    def context_int(self, key: str) -> int:
        return self.int_value(self.rules.context()[key], f"context.{key}")

    def dependency_max_code_chars(self, key: str) -> int:
        config = self.object_value(self.rules.context()[key], key)
        return self.int_value(config["max_code_chars"], f"{key}.max_code_chars")

    @staticmethod
    def edge_index(edge: dict[str, Any]) -> int:
        properties = edge.get("properties", {})
        if isinstance(properties, dict):
            for key in ("index", "argumentIndex", "order"):
                value = properties.get(key)
                if isinstance(value, int):
                    return value
        return 10**9

    @staticmethod
    def read_json(path: Path) -> dict[str, Any]:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError(f"{path}: expected JSON object")
        return cast(dict[str, Any], data)

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
    def string_list(value: Any, name: str) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise TypeError(f"{name} must be a list of strings")
        return cast(list[str], value)

    @staticmethod
    def int_value(value: Any, name: str) -> int:
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an int")
        return value

    @staticmethod
    def str_value(value: Any, name: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        return value

    @staticmethod
    def text_or_none(value: Any, name: str) -> str | None:
        if value is None or isinstance(value, str):
            return value
        raise TypeError(f"{name} must be a string or null")

    @staticmethod
    def int_or_none(value: Any, name: str) -> int | None:
        if value is None or isinstance(value, int):
            return value
        raise TypeError(f"{name} must be an int or null")
