from __future__ import annotations

import copy
import json
from typing import Any, cast


class PayloadBuilder:
    def __init__(self, rules: dict[str, Any]) -> None:
        self.rules = rules
        self.defaults = self.object_value(rules.get("defaults", {}), "defaults")
        self.profiles = self.object_value(rules.get("profiles", {}), "profiles")

    def build(self, profile_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        profile = self.profile(profile_name)
        result = self.select_paths(payload, self.string_list(profile.get("include_paths", []), "include_paths"))
        for path in self.string_list(profile.get("exclude_paths", []), "exclude_paths"):
            self.delete_path(result, self.parts(path))
        for path, limit in self.int_mapping(profile.get("list_limits", {}), "list_limits").items():
            self.limit_list_path(result, self.parts(path), limit)
        for key, limit in self.int_mapping(profile.get("text_key_limits", {}), "text_key_limits").items():
            self.limit_text_key(result, key, limit)
        for path, limit in self.int_mapping(profile.get("text_path_limits", {}), "text_path_limits").items():
            self.limit_text_path(result, self.parts(path), limit)
        return result

    def dumps(self, profile_name: str, payload: dict[str, Any]) -> str:
        profile = self.profile(profile_name)
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        max_chars = profile.get("max_json_chars")
        if max_chars is None:
            return text
        if not isinstance(max_chars, int):
            raise TypeError(f"profiles.{profile_name}.max_json_chars must be int or null")
        return text if len(text) <= max_chars else text[:max_chars]

    def profile(self, name: str) -> dict[str, Any]:
        raw = self.profiles.get(name, {})
        if not isinstance(raw, dict):
            raise TypeError(f"profiles.{name} must be object")
        return {**self.defaults, **raw}

    def select_paths(self, payload: dict[str, Any], include_paths: list[str]) -> dict[str, Any]:
        if not include_paths:
            return copy.deepcopy(payload)
        result: dict[str, Any] = {}
        for path in include_paths:
            parts = self.parts(path)
            value = self.pick(payload, parts)
            if value is not None:
                self.set_path(result, parts, copy.deepcopy(value))
        return result

    @staticmethod
    def parts(path: str) -> list[str]:
        return [part for part in path.split(".") if part]

    def pick(self, value: Any, parts: list[str]) -> Any:
        current = value
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def set_path(self, target: dict[str, Any], parts: list[str], value: Any) -> None:
        if not parts:
            raise ValueError("include path must not be empty")
        current = target
        for part in parts[:-1]:
            existing = current.setdefault(part, {})
            if not isinstance(existing, dict):
                raise TypeError(f"payload path conflict at {part}")
            current = existing
        current[parts[-1]] = value

    def delete_path(self, value: Any, parts: list[str]) -> None:
        if not parts:
            return
        if isinstance(value, list):
            for item in value:
                self.delete_path(item, parts)
            return
        if not isinstance(value, dict):
            return
        if len(parts) == 1:
            value.pop(parts[0], None)
            return
        self.delete_path(value.get(parts[0]), parts[1:])

    def limit_list_path(self, value: Any, parts: list[str], limit: int) -> None:
        target = self.pick(value, parts)
        if isinstance(target, list):
            del target[limit:]

    def limit_text_path(self, value: Any, parts: list[str], limit: int) -> None:
        if not parts:
            return
        parent = self.pick(value, parts[:-1])
        if isinstance(parent, dict) and isinstance(parent.get(parts[-1]), str):
            parent[parts[-1]] = self.truncate(parent[parts[-1]], limit)

    def limit_text_key(self, value: Any, key: str, limit: int) -> None:
        if isinstance(value, dict):
            for item_key, item_value in value.items():
                if item_key == key and isinstance(item_value, str):
                    value[item_key] = self.truncate(item_value, limit)
                else:
                    self.limit_text_key(item_value, key, limit)
        elif isinstance(value, list):
            for item in value:
                self.limit_text_key(item, key, limit)

    @staticmethod
    def truncate(value: str, limit: int) -> str:
        return value if len(value) <= limit else value[:limit] + "\n...<truncated>"

    @staticmethod
    def object_value(value: Any, name: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError(f"{name} must be object")
        return cast(dict[str, Any], value)

    @staticmethod
    def string_list(value: Any, name: str) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise TypeError(f"{name} must be list[str]")
        return cast(list[str], value)

    @staticmethod
    def int_mapping(value: Any, name: str) -> dict[str, int]:
        if not isinstance(value, dict) or not all(isinstance(key, str) and isinstance(item, int) for key, item in value.items()):
            raise TypeError(f"{name} must be object[str, int]")
        return cast(dict[str, int], value)
