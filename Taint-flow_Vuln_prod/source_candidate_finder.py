#!/usr/bin/env python3
"""YAML-driven source candidate finder for Fraunhofer CPG JSON exports."""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, cast

import yaml

from utils.env_utils import env_optional_int, env_path, env_str, load_env


class SourceCandidateFinder:
    def __init__(self, project_dir: Path) -> None:
        self.project_dir = project_dir
        load_env(os.getenv("SOURCE_CANDIDATE_ENV_FILE", str(project_dir / "config" / "source_candidate_finder.env")))
        self.cpg_path = self.project_path(env_path("SOURCE_CANDIDATE_CPG"))
        self.output_path = self.project_path(env_path("SOURCE_CANDIDATE_OUTPUT"))
        self.rules_path = self.project_path(env_path("SOURCE_CANDIDATE_RULES"))
        self.language = env_str("SOURCE_CANDIDATE_LANGUAGE")
        self.include_low_confidence = self.env_bool("SOURCE_CANDIDATE_INCLUDE_LOW_CONFIDENCE")
        self.dfg_depth = env_optional_int("SOURCE_CANDIDATE_DFG_DEPTH")
        self.rules = self.read_yaml(self.rules_path)

    def run(self) -> dict[str, Any]:
        cpg = self.read_json(self.cpg_path)
        languages = self.selected_languages(cpg)
        candidates = self.find_candidates(cpg, languages)
        payload = {
            "sourceFile": str(self.cpg_path),
            "rulesFile": str(self.rules_path),
            "languages": sorted(languages),
            "candidateSourceCount": len(candidates),
            "candidateSources": candidates,
        }
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return payload

    def selected_languages(self, cpg: dict[str, Any]) -> set[str]:
        configured = set(self.language_rules())
        if self.language == "all":
            return configured
        if self.language != "auto":
            if self.language not in configured:
                raise ValueError(f"unknown language {self.language!r}; configured={sorted(configured)}")
            return {self.language}
        return self.detect_languages(cpg) or configured

    def detect_languages(self, cpg: dict[str, Any]) -> set[str]:
        detected: set[str] = set()
        for node in self.list_value(cpg["nodes"], "nodes"):
            node = self.object_value(node, "node")
            labels = " ".join(self.labels(node)).casefold()
            name = (self.text_prop(node, "name") or "").casefold()
            artifact = self.text_prop(node, "artifact") or ""
            for language, config in self.language_rules().items():
                detection = self.object_value(config.get("detection", {}), f"{language}.detection")
                keywords = self.string_list(detection.get("language_label_keywords", []), f"{language}.keywords")
                extensions = self.string_list(detection.get("artifact_extensions", []), f"{language}.extensions")
                if any(keyword.casefold() in labels or keyword.casefold() in name for keyword in keywords):
                    detected.add(language)
                if any(artifact.endswith(extension) for extension in extensions):
                    detected.add(language)
        return detected

    def find_candidates(self, cpg: dict[str, Any], languages: set[str]) -> list[dict[str, Any]]:
        nodes = [self.object_value(node, "node") for node in self.list_value(cpg["nodes"], "nodes")]
        edges = [self.object_value(edge, "edge") for edge in self.list_value(cpg["edges"], "edges")]
        nodes_by_id = {self.node_id(node): node for node in nodes}
        incoming, outgoing, edges_by_type = self.index_edges(edges)
        functions = self.function_nodes(nodes)
        dfg_depth = self.dfg_depth if self.dfg_depth is not None else self.int_value(self.cpg()["dataflow"]["max_depth_default"], "max_depth_default")
        if dfg_depth < 0:
            raise ValueError("SOURCE_CANDIDATE_DFG_DEPTH must be >= 0")

        candidates: list[dict[str, Any]] = []
        for node in nodes:
            for match in self.source_matches(node, languages):
                assigned = self.assignment_lhs(node, nodes_by_id, incoming, edges_by_type)
                candidate = {
                    "nodeId": self.node_id(node),
                    "language": match["language"],
                    "ruleId": match["id"],
                    "kind": match["kind"],
                    "confidence": match["confidence"],
                    "reason": match["reason"],
                    "artifact": self.text_prop(node, "artifact"),
                    "startLine": self.int_prop(node, "startLine"),
                    "endLine": self.int_prop(node, "endLine"),
                    "labels": self.labels(node),
                    "name": self.text_prop(node, "name"),
                    "fullName": self.text_prop(node, "fullName"),
                    "code": self.text_prop(node, "code"),
                    "assignedTo": assigned,
                    "enclosingFunction": self.enclosing_function(node, functions),
                    "dataflow": self.dataflow(self.node_id(node), nodes_by_id, outgoing, dfg_depth),
                }
                if match.get("detail") is not None:
                    candidate["detail"] = match["detail"]
                candidates.append(candidate)

        return sorted(
            candidates,
            key=lambda item: (
                item.get("artifact") or "",
                item.get("startLine") if item.get("startLine") is not None else 10**9,
                item["nodeId"],
                item["kind"],
            ),
        )

    def source_matches(self, node: dict[str, Any], languages: set[str]) -> list[dict[str, Any]]:
        code = self.text_prop(node, "code")
        if not code:
            return []
        if self.cpg().get("skip_multiline_code") is True and "\n" in code:
            return []
        allowed = set(self.string_list(self.cpg().get("source_node_labels_any", []), "source_node_labels_any"))
        if allowed and allowed.isdisjoint(self.labels(node)):
            return []

        matches: list[dict[str, Any]] = []
        for language in sorted(languages):
            for rule in self.list_value(self.language_rules()[language].get("rules", []), f"{language}.rules"):
                rule = self.object_value(rule, f"{language}.rule")
                if rule.get("low_confidence") is True and not self.include_low_confidence:
                    continue
                if not self.rule_matches(self.object_value(rule["conditions"], f"{rule['id']}.conditions"), node):
                    continue
                matches.append(
                    {
                        "language": language,
                        "id": self.str_value(rule["id"], "id"),
                        "kind": self.str_value(rule["kind"], "kind"),
                        "confidence": self.str_value(rule["confidence"], "confidence"),
                        "reason": self.str_value(rule["reason"], "reason"),
                        "detail": rule.get("detail"),
                    }
                )
        return matches

    def rule_matches(self, condition: dict[str, Any], node: dict[str, Any]) -> bool:
        code = self.text_prop(node, "code") or ""
        name = self.text_prop(node, "name") or ""
        full_name = self.text_prop(node, "fullName") or ""
        for key, value in condition.items():
            if key == "all" and not all(self.rule_matches(item, node) for item in self.condition_items(value, key)):
                return False
            if key == "any" and not any(self.rule_matches(item, node) for item in self.condition_items(value, key)):
                return False
            if key == "node_labels_any" and set(self.string_list(value, key)).isdisjoint(self.labels(node)):
                return False
            if key == "code_regex" and re.search(self.str_value(value, key), code) is None:
                return False
            if key == "code_regex_match" and re.match(self.str_value(value, key), code) is None:
                return False
            if key == "name_equals_any" and name not in self.string_list(value, key):
                return False
            if key == "name_prefix_any" and not any(name.startswith(item) for item in self.string_list(value, key)):
                return False
            if key == "name_suffix_any" and not any(name.endswith(item) for item in self.string_list(value, key)):
                return False
            if key == "full_name_contains_any" and not any(item in full_name for item in self.string_list(value, key)):
                return False
            if key not in {
                "all",
                "any",
                "node_labels_any",
                "code_regex",
                "code_regex_match",
                "name_equals_any",
                "name_prefix_any",
                "name_suffix_any",
                "full_name_contains_any",
            }:
                raise ValueError(f"unsupported rule condition: {key}")
        return True

    def assignment_lhs(
        self,
        node: dict[str, Any],
        nodes_by_id: dict[int, dict[str, Any]],
        incoming: dict[int, list[dict[str, Any]]],
        edges_by_type: dict[str, dict[int, list[dict[str, Any]]]],
    ) -> dict[str, Any] | None:
        rhs_edge = self.str_value(self.cpg()["assignment"]["rhs_edge"], "rhs_edge")
        lhs_edge = self.str_value(self.cpg()["assignment"]["lhs_edge"], "lhs_edge")
        for edge in incoming.get(self.node_id(node), []):
            if self.str_value(edge["type"], "edge.type") != rhs_edge:
                continue
            lhs_edges = edges_by_type[lhs_edge].get(self.int_value(edge["startNode"], "edge.startNode"), [])
            if not lhs_edges:
                return None
            lhs = nodes_by_id.get(self.int_value(lhs_edges[0]["endNode"], "edge.endNode"))
            if lhs is None:
                return None
            return {
                "nodeId": self.node_id(lhs),
                "name": self.text_prop(lhs, "name"),
                "code": self.text_prop(lhs, "code"),
                "line": self.int_prop(lhs, "startLine"),
            }
        return None

    def enclosing_function(self, node: dict[str, Any], functions: list[dict[str, Any]]) -> dict[str, Any] | None:
        artifact = self.text_prop(node, "artifact")
        line = self.int_prop(node, "startLine")
        if artifact is None or line is None or line < 0:
            return None

        best: dict[str, Any] | None = None
        best_span: int | None = None
        for function in functions:
            if self.text_prop(function, "artifact") != artifact:
                continue
            start = self.int_prop(function, "startLine")
            end = self.int_prop(function, "endLine")
            if start is None or end is None or start < 0 or end < 0 or not start <= line <= end:
                continue
            span = end - start
            if best is None or best_span is None or span < best_span:
                best = function
                best_span = span

        if best is None:
            return None
        return {
            "nodeId": self.node_id(best),
            "name": self.text_prop(best, "name"),
            "fullName": self.text_prop(best, "fullName"),
            "startLine": self.int_prop(best, "startLine"),
            "endLine": self.int_prop(best, "endLine"),
        }

    def dataflow(
        self,
        start_node_id: int,
        nodes_by_id: dict[int, dict[str, Any]],
        outgoing: dict[int, list[dict[str, Any]]],
        max_depth: int,
    ) -> list[dict[str, Any]]:
        if max_depth == 0:
            return []
        edge_rules = [self.object_value(edge, "dataflow edge") for edge in self.list_value(self.cpg()["dataflow"]["edges"], "dataflow.edges")]
        result: list[dict[str, Any]] = []
        queue: deque[tuple[int, int]] = deque([(start_node_id, 0)])
        seen = {start_node_id}
        while queue:
            node_id, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in outgoing.get(node_id, []):
                if not any(self.edge_matches(edge, edge_rule) for edge_rule in edge_rules):
                    continue
                target_id = self.int_value(edge["endNode"], "edge.endNode")
                if target_id in seen:
                    continue
                seen.add(target_id)
                target = nodes_by_id.get(target_id)
                if target is None:
                    continue
                result.append(
                    {
                        "depth": depth + 1,
                        "edgeType": self.str_value(edge["type"], "edge.type"),
                        "nodeId": target_id,
                        "labels": self.labels(target),
                        "name": self.text_prop(target, "name"),
                        "code": self.text_prop(target, "code"),
                        "line": self.int_prop(target, "startLine"),
                    }
                )
                queue.append((target_id, depth + 1))
        return result

    def edge_matches(self, edge: dict[str, Any], rule: dict[str, Any]) -> bool:
        if self.str_value(edge["type"], "edge.type") != self.str_value(rule["type"], "edge_rule.type"):
            return False
        filters = self.object_value(rule.get("property_filters", {}), "edge_rule.property_filters")
        properties = self.object_value(edge.get("properties", {}), "edge.properties")
        return all(properties.get(key) == value for key, value in filters.items())

    def index_edges(
        self,
        edges: list[dict[str, Any]],
    ) -> tuple[dict[int, list[dict[str, Any]]], dict[int, list[dict[str, Any]]], dict[str, dict[int, list[dict[str, Any]]]]]:
        incoming: dict[int, list[dict[str, Any]]] = defaultdict(list)
        outgoing: dict[int, list[dict[str, Any]]] = defaultdict(list)
        by_type: dict[str, dict[int, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
        for edge in edges:
            start = self.int_value(edge["startNode"], "edge.startNode")
            end = self.int_value(edge["endNode"], "edge.endNode")
            edge_type = self.str_value(edge["type"], "edge.type")
            incoming[end].append(edge)
            outgoing[start].append(edge)
            by_type[edge_type][start].append(edge)
        return incoming, outgoing, by_type

    def function_nodes(self, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        function_labels = set(self.string_list(self.cpg().get("function_labels_any", []), "function_labels_any"))
        return [node for node in nodes if not function_labels.isdisjoint(self.labels(node))]

    def cpg(self) -> dict[str, Any]:
        return self.object_value(self.rules["cpg"], "cpg")

    def language_rules(self) -> dict[str, Any]:
        return self.object_value(self.rules["languages"], "languages")

    def condition_items(self, value: Any, key: str) -> list[dict[str, Any]]:
        return [self.object_value(item, f"{key} item") for item in self.list_value(value, key)]

    def node_id(self, node: dict[str, Any]) -> int:
        return self.int_value(node["id"], "node.id")

    def labels(self, node: dict[str, Any]) -> list[str]:
        return self.string_list(node.get("labels", []), "node.labels")

    def text_prop(self, node: dict[str, Any], key: str) -> str | None:
        value = self.object_value(node.get("properties", {}), "node.properties").get(key)
        if value is None or isinstance(value, str):
            return value
        raise TypeError(f"node {self.node_id(node)} property {key} must be string or null")

    def int_prop(self, node: dict[str, Any], key: str) -> int | None:
        value = self.object_value(node.get("properties", {}), "node.properties").get(key)
        if value is None or isinstance(value, int):
            return value
        raise TypeError(f"node {self.node_id(node)} property {key} must be int or null")

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
            raise TypeError(f"{path}: expected YAML mapping")
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
    def str_value(value: Any, name: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        return value

    @staticmethod
    def int_value(value: Any, name: str) -> int:
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an int")
        return value

    @staticmethod
    def env_bool(name: str) -> bool:
        value = env_str(name).casefold()
        if value not in {"true", "false"}:
            raise ValueError(f"{name} must be true or false")
        return value == "true"


def main() -> int:
    payload = SourceCandidateFinder(Path(__file__).resolve().parent).run()
    print(f"candidate sources: {payload['candidateSourceCount']}")
    for item in payload["candidateSources"][:20]:
        print(f"- {item['language']}:{item['kind']} {item.get('artifact')}:{item.get('startLine')} {item.get('code')}")
    if payload["candidateSourceCount"] > 20:
        print(f"... {payload['candidateSourceCount'] - 20} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
