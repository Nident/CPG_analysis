from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import yaml


class SinkFinderRules:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = self.read_yaml(path)
        if self.data.get("version") != 1:
            raise ValueError(f"{path}: unsupported rules version {self.data.get('version')!r}")

    def classify_sink(self, node: dict[str, Any]) -> list[dict[str, Any]]:
        labels = self.labels(node)
        if "Call" not in labels:
            return []
        props = self.object_value(node.get("properties", {}), "node.properties")
        fields = {
            "name": self.optional_text(props.get("name"), "name"),
            "fullName": self.optional_text(props.get("fullName"), "fullName"),
            "code": self.optional_text(props.get("code"), "code"),
        }
        return [
            {
                "nodeId": self.int_value(node["id"], "node.id"),
                "kind": rule["kind"],
                "ruleId": rule["id"],
                "severity": rule["severity"],
                "evidence": fields[self.str_value(rule["evidence"], "rule.evidence")],
            }
            for rule in self.sinks()
            if self.conditions_match(self.object_value(rule["conditions"], f"{rule['id']}.conditions"), labels, fields)
        ]

    def conditions_match(self, condition: dict[str, Any], labels: list[str], fields: dict[str, str]) -> bool:
        haystack = f"{fields['name']}\n{fields['fullName']}\n{fields['code']}"
        for key, value in condition.items():
            if key == "all" and not all(self.conditions_match(item, labels, fields) for item in self.condition_items(value, key)):
                return False
            if key == "any" and not any(self.conditions_match(item, labels, fields) for item in self.condition_items(value, key)):
                return False
            if key == "node_labels_any" and set(self.string_list(value, key)).isdisjoint(labels):
                return False
            if key == "name_equals_any" and fields["name"] not in self.string_list(value, key):
                return False
            if key == "name_contains_any" and not self.contains_any(fields["name"], value, key):
                return False
            if key == "full_name_contains_any" and not self.contains_any(fields["fullName"], value, key):
                return False
            if key == "haystack_contains_any" and not self.contains_any(haystack, value, key):
                return False
            if key == "haystack_contains_all" and not self.contains_all(haystack, value, key):
                return False
            if key == "code_contains_any" and not self.contains_any(fields["code"], value, key):
                return False
            if key == "code_contains_all" and not self.contains_all(fields["code"], value, key):
                return False
            if key == "code_regex" and re.search(self.str_value(value, key), fields["code"]) is None:
                return False
            if key == "code_regex_any" and not any(re.search(pattern, fields["code"]) for pattern in self.string_list(value, key)):
                return False
            if key == "not_code_regex" and re.search(self.str_value(value, key), fields["code"]) is not None:
                return False
            if key == "not_code_regex_any" and any(re.search(pattern, fields["code"]) for pattern in self.string_list(value, key)):
                return False
            if key not in {
                "all",
                "any",
                "node_labels_any",
                "name_equals_any",
                "name_contains_any",
                "full_name_contains_any",
                "haystack_contains_any",
                "haystack_contains_all",
                "code_contains_any",
                "code_contains_all",
                "code_regex",
                "code_regex_any",
                "not_code_regex",
                "not_code_regex_any",
            }:
                raise ValueError(f"unsupported sink condition: {key}")
        return True

    def contains_any(self, text: str, value: Any, key: str) -> bool:
        target = text.casefold()
        return any(item.casefold() in target for item in self.string_list(value, key))

    def contains_all(self, text: str, value: Any, key: str) -> bool:
        target = text.casefold()
        return all(item.casefold() in target for item in self.string_list(value, key))

    def search(self) -> dict[str, Any]:
        return self.object_value(self.data["search"], "search")

    def output(self) -> dict[str, Any]:
        return self.object_value(self.data["output"], "output")

    def traversal(self) -> dict[str, Any]:
        return self.object_value(self.data["traversal"], "traversal")

    def context(self) -> dict[str, Any]:
        return self.object_value(self.data["context"], "context")

    def source_seeds(self) -> list[dict[str, Any]]:
        return [self.object_value(item, "source_seed") for item in self.list_value(self.data["source_seeds"], "source_seeds")]

    def sinks(self) -> list[dict[str, Any]]:
        return [self.object_value(item, "sink") for item in self.list_value(self.data["sinks"], "sinks")]

    def labels(self, node: dict[str, Any]) -> list[str]:
        return self.string_list(node.get("labels", []), "node.labels")

    def condition_items(self, value: Any, key: str) -> list[dict[str, Any]]:
        return [self.object_value(item, f"{key} item") for item in self.list_value(value, key)]

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
    def optional_text(value: Any, name: str) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string or null")
        return value
