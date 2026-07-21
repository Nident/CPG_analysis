from __future__ import annotations

from pathlib import Path
from typing import Any


class SemanticContextBuilder:
    def __init__(self, rules: dict[str, Any]) -> None:
        self.rules = rules
        self.kind = self.text(rules["context_kind"], "context_kind")
        self.sink_kinds = set(self.string_list(rules["sink_kinds"], "sink_kinds"))
        self.limits = self.object_value(rules["limits"], "limits")
        self.signal_rules = self.object_value(rules["signals"], "signals")

    def build(
        self,
        source_path_record: dict[str, Any],
        source_analysis: dict[str, Any] | None,
        expanded_context: dict[str, Any] | None,
        interprocedural_context: dict[str, Any] | None,
        external_context_index: dict[int, dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        paths = self.candidate_paths(source_path_record)
        if not paths:
            return None
        text = self.truncate(self.text_blob([[path for _, path in paths], source_path_record.get("source"), source_analysis, expanded_context, interprocedural_context]))
        sink_ids = sorted({path["sink"]["nodeId"] for _, path in paths})
        context = {
            "contextKind": self.kind,
            "sourceNodeId": source_path_record.get("sourceNodeId"),
            "candidatePathCount": len(paths),
            "matchedSinkNodeIds": sink_ids,
            "candidatePaths": [self.path_context(index, path) for index, path in paths[: self.limit("max_paths")]],
            "sinkGroups": self.sink_groups(paths),
            "flowEvidence": self.flow_evidence(source_analysis, expanded_context, interprocedural_context),
            "signals": self.signals(text),
        }
        external = self.external_contexts(sink_ids, external_context_index or {})
        if external:
            context["externalContexts"] = external[: self.limit("max_external_contexts")]
        return context

    def candidate_paths(self, record: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
        paths = record.get("paths", [])
        if not isinstance(paths, list):
            return []
        return [
            (index, path)
            for index, path in enumerate(paths)
            if isinstance(path, dict)
            and isinstance(path.get("sink"), dict)
            and path["sink"].get("kind") in self.sink_kinds
            and isinstance(path["sink"].get("nodeId"), int)
        ]

    def path_context(self, index: int, path: dict[str, Any]) -> dict[str, Any]:
        sink = self.object_value(path["sink"], "path.sink")
        evidence = self.object_value(path.get("evidence", {}), "path.evidence")
        return {
            "pathIndex": index,
            "sinkNodeId": sink.get("nodeId"),
            "sinkKind": sink.get("kind"),
            "sinkRuleId": sink.get("ruleId"),
            "sinkEvidence": sink.get("evidence"),
            "pathQuality": {key: evidence.get(key) for key in self.string_list(self.rules["path_quality_fields"], "path_quality_fields")},
            "dangerousArguments": self.dangerous_arguments(sink),
            "sinkFunction": self.function_summary(sink),
        }

    def sink_groups(self, paths: list[tuple[int, dict[str, Any]]]) -> list[dict[str, Any]]:
        groups: dict[tuple[Any, Any, Any], dict[str, Any]] = {}
        for _, path in paths:
            sink = self.object_value(path["sink"], "path.sink")
            function = self.function_summary(sink)
            key = (function.get("artifact"), function.get("fullName"), function.get("startLine"))
            group = groups.setdefault(
                key,
                {"function": function, "sinkNodeIds": [], "sinkEvidence": [], "signals": self.signals(self.text_blob(function))},
            )
            group["sinkNodeIds"].append(sink.get("nodeId"))
            if sink.get("evidence") not in group["sinkEvidence"]:
                group["sinkEvidence"].append(sink.get("evidence"))
        return list(groups.values())[: self.limit("max_groups")]

    def dangerous_arguments(self, sink: dict[str, Any]) -> list[dict[str, Any]]:
        roles = set(self.string_list(self.rules["dangerous_argument_roles"], "dangerous_argument_roles"))
        context = self.object_value(sink.get("context", {}), "sink.context")
        arguments = context.get("arguments", [])
        if not isinstance(arguments, list):
            return []
        return [arg for arg in arguments if isinstance(arg, dict) and arg.get("role") in roles]

    @staticmethod
    def function_summary(sink: dict[str, Any]) -> dict[str, Any]:
        context = sink.get("context", {})
        function = context.get("enclosingFunction") if isinstance(context, dict) else None
        node = sink.get("node")
        return function if isinstance(function, dict) else node if isinstance(node, dict) else {}

    def external_contexts(self, sink_ids: list[int], index: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
        contexts: list[dict[str, Any]] = []
        seen: set[tuple[int, ...]] = set()
        for sink_id in sink_ids:
            entry = index.get(sink_id)
            if entry is None:
                continue
            data = self.object_value(entry.get("data", {}), "external_context.data")
            key = tuple(item for item in data.get("sinkNodeIds", []) if isinstance(item, int))
            if key in seen:
                continue
            seen.add(key)
            contexts.append({"path": entry.get("path"), "data": data})
        return contexts

    def flow_evidence(
        self,
        source_analysis: dict[str, Any] | None,
        expanded_context: dict[str, Any] | None,
        interprocedural_context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "sourceRiskSummary": self.pick(source_analysis, ["analysis", "source_summary"]),
            "sourceTrustBoundary": self.pick(source_analysis, ["analysis", "trust_boundary"]),
            "expandedDownstreamSinkPathCount": len(self.pick(expanded_context, ["downstreamSinkPaths"]) or []),
            "interproceduralPathCount": len(self.pick(interprocedural_context, ["paths"]) or []),
        }

    def signals(self, text: str) -> dict[str, list[dict[str, str]]]:
        return {name: self.signal_matches(rules, text) for name, rules in self.signal_rules.items() if isinstance(rules, list)}

    def signal_matches(self, rules: list[Any], text: str) -> list[dict[str, str]]:
        target = text.casefold()
        matches: list[dict[str, str]] = []
        for raw_rule in rules:
            rule = self.object_value(raw_rule, "signal")
            matched = [token for token in self.signal_tokens(rule) if token.casefold() in target]
            if matched:
                matches.append({"id": self.text(rule["id"], "signal.id"), "description": self.text(rule["description"], "signal.description"), "matched": ", ".join(matched)})
            if len(matches) >= self.limit("max_signal_matches"):
                break
        return matches

    @staticmethod
    def signal_tokens(rule: dict[str, Any]) -> list[str]:
        if isinstance(rule.get("contains"), str):
            return [rule["contains"]]
        return [item for item in rule.get("contains_any", []) if isinstance(item, str)]

    def text_blob(self, value: Any) -> str:
        if isinstance(value, dict):
            return "\n".join(self.text_blob(item) for item in value.values())
        if isinstance(value, list | tuple):
            return "\n".join(self.text_blob(item) for item in value)
        return value if isinstance(value, str) else ""

    def truncate(self, value: str) -> str:
        max_chars = self.limit("max_code_chars")
        return value if len(value) <= max_chars else value[:max_chars]

    @staticmethod
    def pick(value: dict[str, Any] | None, path: list[str]) -> Any:
        current: Any = value
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    def limit(self, name: str) -> int:
        value = self.limits[name]
        if not isinstance(value, int):
            raise TypeError(f"limits.{name} must be int")
        return value

    @staticmethod
    def object_value(value: Any, name: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError(f"{name} must be object")
        return value

    @staticmethod
    def string_list(value: Any, name: str) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise TypeError(f"{name} must be list[str]")
        return value

    @staticmethod
    def text(value: Any, name: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{name} must be str")
        return value


class SemanticContextRegistry:
    def __init__(self, project_dir: Path, config: dict[str, Any], read_yaml: Any) -> None:
        self.builders = [
            SemanticContextBuilder(read_yaml(project_dir / Path(self.text(item["rules"], "context.rules"))))
            for item in self.list_value(config["contexts"], "contexts")
            if isinstance(item, dict) and item.get("enabled", True)
        ]

    def build_all(
        self,
        source_path_record: dict[str, Any],
        source_analysis: dict[str, Any] | None,
        expanded_context: dict[str, Any] | None,
        interprocedural_context: dict[str, Any] | None,
        external_indexes: dict[str, dict[int, dict[str, Any]]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for builder in self.builders:
            context = builder.build(source_path_record, source_analysis, expanded_context, interprocedural_context, external_indexes.get(builder.kind))
            if context is not None:
                result[builder.kind] = context
        return result

    @staticmethod
    def list_value(value: Any, name: str) -> list[Any]:
        if not isinstance(value, list):
            raise TypeError(f"{name} must be list")
        return value

    @staticmethod
    def text(value: Any, name: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{name} must be str")
        return value
