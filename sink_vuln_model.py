#!/usr/bin/env python3
"""LLM verifier for source-to-sink path vulnerability analysis."""

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field

from env_utils import env_int, env_optional_int, env_optional_path, env_path, env_str, load_env
from model import ModelClient


Confidence = Literal["low", "medium", "high"]
AttackerControl = Literal["none", "partial", "full", "unknown"]


class SourceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attacker_control: AttackerControl
    trust_boundary: str
    relevant_previous_hypotheses: list[str]


class PathAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path_index: int
    sink_node_id: int
    sink_kind: str
    vulnerability_probability: float = Field(
        ge=0.0,
        le=1.0,
        description="Probability from 0.0 to 1.0 that this specific path is exploitable.",
    )
    source_reaches_sink: bool
    attacker_controls_sink_argument: AttackerControl
    sanitizers_or_guards: list[str]
    blocking_conditions: list[str]
    evidence: list[str]
    reasoning: str


class InterestingPath(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path_index: int
    why: str


class SinkVulnerabilityAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_probability: float = Field(
        ge=0.0,
        le=1.0,
        description="Overall probability from 0.0 to 1.0 that this source/path bundle contains a vulnerability.",
    )
    summary: str
    source_assessment: SourceAssessment
    path_assessments: list[PathAssessment]
    most_interesting_paths: list[InterestingPath]
    follow_up_checks: list[str]


class AnalysisRecord(TypedDict):
    status: Literal["ok"]
    sourceNodeId: int | None
    inputFile: str
    previousSourceAnalysisFile: str | None
    contextExpansionFile: str | None
    interproceduralContextFile: str | None
    analysis: dict[str, Any]


class ErrorRecord(TypedDict):
    status: Literal["error"]
    sourceNodeId: int | None
    inputFile: str
    previousSourceAnalysisFile: str | None
    contextExpansionFile: str | None
    interproceduralContextFile: str | None
    error: dict[str, str]


OutputRecord = AnalysisRecord | ErrorRecord


@dataclass(frozen=True)
class ModelConfig:
    base_url: str
    api_key: str
    model: str
    temperature: float
    max_tokens: int
    timeout: int
    prompt_file: Path
    parallel_workers: int

    @classmethod
    def from_yaml(cls, path: Path, model_name: str) -> ModelConfig:
        data = load_model_mapping(path, model_name)
        required = {
            "base_url",
            "api_key",
            "model",
            "temperature",
            "max_tokens",
            "timeout",
            "max_source_chars",
            "prompt_file",
            "parallel_workers",
        }
        assert_exact_keys(data, required, path)
        prompt_file = Path(require_type(data, "prompt_file", str, path))
        if not prompt_file.is_absolute():
            prompt_file = path.parent / prompt_file
        return cls(
            base_url=require_type(data, "base_url", str, path),
            api_key=require_type(data, "api_key", str, path),
            model=require_type(data, "model", str, path),
            temperature=require_number(data, "temperature", path),
            max_tokens=require_type(data, "max_tokens", int, path),
            timeout=require_type(data, "timeout", int, path),
            prompt_file=prompt_file,
            parallel_workers=require_type(data, "parallel_workers", int, path),
        )


@dataclass(frozen=True)
class PromptConfig:
    system_prompt: str
    user_prompt: str

    @classmethod
    def from_yaml(cls, path: Path) -> PromptConfig:
        data = load_yaml_mapping(path)
        assert_exact_keys(data, {"system_prompt", "user_prompt"}, path)
        return cls(
            system_prompt=require_type(data, "system_prompt", str, path),
            user_prompt=require_type(data, "user_prompt", str, path),
        )


class SinkVulnModel:
    """Loads path bundles, attaches previous source reasoning, and runs LLM verification."""

    def __init__(
        self,
        model_config_path: str | Path,
        model_name: str,
        prompt_path: str | Path | None,
        source_analysis_dir: str | Path | None,
        context_expansion_dir: str | Path | None,
        interprocedural_context_dir: str | Path | None,
        max_paths: int,
        max_node_code_chars: int,
    ) -> None:
        if max_paths < 1:
            raise ValueError("max_paths must be >= 1")
        if max_node_code_chars < 1:
            raise ValueError("max_node_code_chars must be >= 1")

        self.model_config = ModelConfig.from_yaml(Path(model_config_path), model_name)
        resolved_prompt_path = Path(prompt_path) if prompt_path is not None else self.model_config.prompt_file
        self.prompt_config = PromptConfig.from_yaml(resolved_prompt_path)
        self.source_analysis_index = load_source_analysis_index(
            Path(source_analysis_dir) if source_analysis_dir is not None else None
        )
        self.context_expansion_index = load_context_expansion_index(
            Path(context_expansion_dir) if context_expansion_dir is not None else None
        )
        self.interprocedural_context_index = load_interprocedural_context_index(
            Path(interprocedural_context_dir) if interprocedural_context_dir is not None else None
        )
        self.max_paths = max_paths
        self.max_node_code_chars = max_node_code_chars
        self.model_client = ModelClient[SinkVulnerabilityAnalysis](
            base_url=self.model_config.base_url,
            api_key=self.model_config.api_key,
            model=self.model_config.model,
            temperature=self.model_config.temperature,
            max_tokens=self.model_config.max_tokens,
            timeout=self.model_config.timeout,
            system_prompt=self.prompt_config.system_prompt,
            user_prompt=self.prompt_config.user_prompt,
            response_schema=SinkVulnerabilityAnalysis,
        )

    def analyze_file(self, path_file: Path, prompt_output_path: Path) -> OutputRecord:
        path_record = load_json_object(path_file)
        source_node_id = optional_int(path_record.get("sourceNodeId"))
        previous_entry = (
            self.source_analysis_index.get(source_node_id)
            if source_node_id is not None
            else None
        )
        previous_analysis = previous_entry.data if previous_entry is not None else None
        context_entry = (
            self.context_expansion_index.get(source_node_id)
            if source_node_id is not None
            else None
        )
        expanded_context = context_entry.data if context_entry is not None else None
        interprocedural_entry = (
            self.interprocedural_context_index.get(source_node_id)
            if source_node_id is not None
            else None
        )
        interprocedural_context = (
            interprocedural_entry.data if interprocedural_entry is not None else None
        )
        payload = {
            "source_path_record": compact_path_record(
                path_record,
                max_paths=self.max_paths,
                max_node_code_chars=self.max_node_code_chars,
            ),
            "previous_source_analysis": previous_analysis,
            "expanded_context": compact_context_record(
                expanded_context,
                max_node_code_chars=self.max_node_code_chars,
            ),
            "interprocedural_context": compact_context_record(
                interprocedural_context,
                max_node_code_chars=self.max_node_code_chars,
            ),
        }
        payload_json = json.dumps(payload, ensure_ascii=False, indent=2)
        analysis = self.model_client.request(payload_json, prompt_output_path=prompt_output_path)
        return {
            "status": "ok",
            "sourceNodeId": source_node_id,
            "inputFile": str(path_file),
            "previousSourceAnalysisFile": (
                str(previous_entry.path) if previous_entry is not None else None
            ),
            "contextExpansionFile": (
                str(context_entry.path) if context_entry is not None else None
            ),
            "interproceduralContextFile": (
                str(interprocedural_entry.path) if interprocedural_entry is not None else None
            ),
            "analysis": analysis.model_dump(),
        }

    def analyze_dir(
        self,
        sink_paths_dir: str | Path,
        output_dir: str | Path,
        parallel_workers: int | None,
        limit: int | None,
    ) -> None:
        input_dir = Path(sink_paths_dir)
        files = discover_path_files(input_dir)
        if limit is not None:
            files = files[:limit]

        output = Path(output_dir)
        if output.exists() and not output.is_dir():
            raise ValueError(f"{output}: output path must be a directory")
        output.mkdir(parents=True, exist_ok=True)

        workers = parallel_workers if parallel_workers is not None else self.model_config.parallel_workers
        if workers < 1:
            raise ValueError("parallel_workers must be >= 1")

        summaries: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    self.analyze_file,
                    path_file,
                    output / prompt_filename(path_file),
                ): path_file
                for path_file in files
            }
            completed = 0
            for future in as_completed(futures):
                input_file = futures[future]
                try:
                    record: OutputRecord = future.result()
                except Exception as error:
                    source_node_id = source_node_id_from_file(input_file)
                    previous_entry = (
                        self.source_analysis_index.get(source_node_id)
                        if source_node_id is not None
                        else None
                    )
                    context_entry = (
                        self.context_expansion_index.get(source_node_id)
                        if source_node_id is not None
                        else None
                    )
                    interprocedural_entry = (
                        self.interprocedural_context_index.get(source_node_id)
                        if source_node_id is not None
                        else None
                    )
                    record = {
                        "status": "error",
                        "sourceNodeId": source_node_id,
                        "inputFile": str(input_file),
                        "previousSourceAnalysisFile": (
                            str(previous_entry.path) if previous_entry is not None else None
                        ),
                        "contextExpansionFile": (
                            str(context_entry.path) if context_entry is not None else None
                        ),
                        "interproceduralContextFile": (
                            str(interprocedural_entry.path) if interprocedural_entry is not None else None
                        ),
                        "error": {
                            "type": type(error).__name__,
                            "message": str(error),
                        },
                    }

                completed += 1
                output_file = output / output_filename(input_file, record["status"])
                write_pretty_json(output_file, record)
                summaries.append(
                    {
                        "inputFile": str(input_file),
                        "outputFile": output_file.name,
                        "sourceNodeId": record["sourceNodeId"],
                        "status": record["status"],
                    }
                )
                print(
                    f"[{completed}/{len(files)}] saved {record['status']} "
                    f"sourceNodeId={record['sourceNodeId']} -> {output_file}",
                    file=sys.stderr,
                )

        write_pretty_json(
            output / "summary.json",
            {
                "status": "ok",
                "sinkPathsDir": str(input_dir),
                "outputDir": str(output),
                "sourceAnalysisDir": source_analysis_dir_string(self.source_analysis_index),
                "contextExpansionDir": context_expansion_dir_string(self.context_expansion_index),
                "interproceduralContextDir": interprocedural_context_dir_string(
                    self.interprocedural_context_index
                ),
                "fileCount": len(files),
                "parallelWorkers": workers,
                "maxPaths": self.max_paths,
                "maxNodeCodeChars": self.max_node_code_chars,
                "results": sorted(summaries, key=lambda item: item["inputFile"]),
            },
        )


@dataclass(frozen=True)
class SourceAnalysisEntry:
    path: Path
    data: dict[str, Any]


@dataclass(frozen=True)
class ContextExpansionEntry:
    path: Path
    data: dict[str, Any]


@dataclass(frozen=True)
class InterproceduralContextEntry:
    path: Path
    data: dict[str, Any]


def discover_path_files(input_dir: Path) -> list[Path]:
    if not input_dir.is_dir():
        raise ValueError(f"{input_dir}: sink paths input must be a directory")
    return sorted(
        path
        for path in input_dir.glob("*_ok.json")
        if path.name != "summary.json" and path.name != "sink_candidates.json"
    )


def compact_path_record(
    data: dict[str, Any],
    max_paths: int,
    max_node_code_chars: int,
) -> dict[str, Any]:
    compacted = deep_compact(data, max_node_code_chars)
    paths = compacted.get("paths")
    if isinstance(paths, list):
        compacted["paths"] = paths[:max_paths]
        compacted["omittedPathCount"] = max(0, len(paths) - max_paths)
    return compacted


def compact_context_record(
    data: dict[str, Any] | None,
    max_node_code_chars: int,
) -> dict[str, Any] | None:
    if data is None:
        return None
    return deep_compact(data, max_node_code_chars)


def deep_compact(value: Any, max_node_code_chars: int) -> Any:
    if isinstance(value, dict):
        return {
            key: compact_string(val, max_node_code_chars)
            if key == "code" and isinstance(val, str)
            else deep_compact(val, max_node_code_chars)
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [deep_compact(item, max_node_code_chars) for item in value]
    return value


def compact_string(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n...<truncated>"


def load_source_analysis_index(source_analysis_dir: Path | None) -> dict[int, SourceAnalysisEntry]:
    if source_analysis_dir is None or not source_analysis_dir.exists():
        return {}
    if not source_analysis_dir.is_dir():
        raise ValueError(f"{source_analysis_dir}: source analysis path must be a directory")

    index: dict[int, SourceAnalysisEntry] = {}
    for path in sorted(source_analysis_dir.glob("*_ok.json")):
        data = load_json_object(path)
        node_id = optional_int(data.get("nodeId"))
        if node_id is None:
            node_id = optional_int(data.get("sourceNodeId"))
        if node_id is not None:
            index[node_id] = SourceAnalysisEntry(path, data)
    return index


def load_context_expansion_index(context_expansion_dir: Path | None) -> dict[int, ContextExpansionEntry]:
    if context_expansion_dir is None or not context_expansion_dir.exists():
        return {}
    if not context_expansion_dir.is_dir():
        raise ValueError(f"{context_expansion_dir}: context expansion path must be a directory")

    index: dict[int, ContextExpansionEntry] = {}
    for path in sorted(context_expansion_dir.glob("*_context_ok.json")):
        data = load_json_object(path)
        node_id = optional_int(data.get("sourceNodeId"))
        if node_id is not None:
            index[node_id] = ContextExpansionEntry(path, data)
    return index


def load_interprocedural_context_index(
    interprocedural_context_dir: Path | None,
) -> dict[int, InterproceduralContextEntry]:
    if interprocedural_context_dir is None or not interprocedural_context_dir.exists():
        return {}
    if not interprocedural_context_dir.is_dir():
        raise ValueError(f"{interprocedural_context_dir}: interprocedural context path must be a directory")

    index: dict[int, InterproceduralContextEntry] = {}
    for path in sorted(interprocedural_context_dir.glob("*_interprocedural_ok.json")):
        data = load_json_object(path)
        node_id = optional_int(data.get("sourceNodeId"))
        if node_id is not None:
            index[node_id] = InterproceduralContextEntry(path, data)
    return index


def source_analysis_dir_string(index: dict[int, SourceAnalysisEntry]) -> str | None:
    if not index:
        return None
    first = next(iter(index.values()))
    return str(first.path.parent)


def context_expansion_dir_string(index: dict[int, ContextExpansionEntry]) -> str | None:
    if not index:
        return None
    first = next(iter(index.values()))
    return str(first.path.parent)


def interprocedural_context_dir_string(index: dict[int, InterproceduralContextEntry]) -> str | None:
    if not index:
        return None
    first = next(iter(index.values()))
    return str(first.path.parent)


def source_node_id_from_file(path: Path) -> int | None:
    data = load_json_object(path)
    return optional_int(data.get("sourceNodeId"))


def output_filename(input_file: Path, status: str) -> str:
    name = input_file.name
    if name.endswith("_ok.json"):
        name = name.removesuffix("_ok.json")
    else:
        name = input_file.stem
    return f"{name}_{status}.json"


def prompt_filename(input_file: Path) -> str:
    name = input_file.name
    if name.endswith("_ok.json"):
        name = name.removesuffix("_ok.json")
    else:
        name = input_file.stem
    return f"{name}_prompt.yaml"


def load_json_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path}: expected JSON object")
    return cast(dict[str, Any], data)


def write_pretty_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path}: expected YAML mapping")
    return cast(dict[str, Any], data)


def load_model_mapping(path: Path, model_name: str) -> dict[str, Any]:
    data = load_yaml_mapping(path)
    assert_exact_keys(data, {"api_key", "models"}, path)
    api_key = require_type(data, "api_key", str, path)
    models = data["models"]
    if not isinstance(models, dict):
        raise TypeError(f"{path}: models must be a mapping")
    if model_name not in models:
        raise ValueError(f"{path}: model profile not found: {model_name}")
    model_data = models[model_name]
    if not isinstance(model_data, dict):
        raise TypeError(f"{path}: models.{model_name} must be a mapping")
    return {"api_key": api_key, **cast(dict[str, Any], model_data)}


def assert_exact_keys(data: dict[str, Any], expected: set[str], path: Path) -> None:
    actual = set(data)
    missing = expected - actual
    extra = actual - expected
    if missing or extra:
        raise ValueError(f"{path}: missing={sorted(missing)} extra={sorted(extra)}")


def require_type(
    data: dict[str, Any],
    key: str,
    expected_type: type[str] | type[int],
    path: Path,
) -> Any:
    value = data[key]
    if not isinstance(value, expected_type):
        raise TypeError(f"{path}: {key} must be {expected_type.__name__}")
    return value


def require_number(data: dict[str, Any], key: str, path: Path) -> float:
    value = data[key]
    if not isinstance(value, int | float):
        raise TypeError(f"{path}: {key} must be int or float")
    return float(value)


def optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def default_sink_paths_dir(base_dir: Path) -> Path:
    return base_dir / "outputs" / "openstack__kolla__2a4a8fce31c1_sink_paths"


def default_source_analysis_dir(sink_paths_dir: Path) -> Path:
    name = sink_paths_dir.name
    if name.endswith("_sink_paths"):
        return sink_paths_dir.parent / name.removesuffix("_sink_paths")
    return sink_paths_dir.parent / "source_model_analysis"


def default_context_expansion_dir(sink_paths_dir: Path) -> Path | None:
    name = sink_paths_dir.name
    if name.endswith("_sink_paths"):
        path = sink_paths_dir.parent / f"{name.removesuffix('_sink_paths')}_context_expansion"
        return path if path.exists() else None
    return None


def default_interprocedural_context_dir(sink_paths_dir: Path) -> Path | None:
    name = sink_paths_dir.name
    if name.endswith("_sink_paths"):
        path = sink_paths_dir.parent / f"{name.removesuffix('_sink_paths')}_interprocedural_context"
        return path if path.exists() else None
    return None


def default_output_dir(sink_paths_dir: Path) -> Path:
    name = sink_paths_dir.name
    if name.endswith("_sink_paths"):
        name = name.removesuffix("_sink_paths")
    return sink_paths_dir.parent / f"{name}_sink_vuln_analysis"


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    env_file = os.getenv(
        "SINK_VULN_ENV_FILE",
        str(base_dir / "config" / "sink_vuln_model.env"),
    )
    load_env(env_file)

    sink_paths_dir = env_path("SINK_VULN_SINK_PATHS_DIR")
    source_analysis_dir = env_optional_path("SINK_VULN_SOURCE_ANALYSIS_DIR")
    if source_analysis_dir is None:
        source_analysis_dir = default_source_analysis_dir(sink_paths_dir)
    context_expansion_dir = env_optional_path("SINK_VULN_CONTEXT_EXPANSION_DIR")
    if context_expansion_dir is None:
        context_expansion_dir = default_context_expansion_dir(sink_paths_dir)
    interprocedural_context_dir = env_optional_path("SINK_VULN_INTERPROCEDURAL_CONTEXT_DIR")
    if interprocedural_context_dir is None:
        interprocedural_context_dir = default_interprocedural_context_dir(sink_paths_dir)
    output_dir = env_optional_path("SINK_VULN_OUTPUT")
    if output_dir is None:
        output_dir = default_output_dir(sink_paths_dir)

    model = SinkVulnModel(
        model_config_path=env_path("SINK_VULN_MODEL_CONFIG"),
        model_name=env_str("SINK_VULN_MODEL_NAME"),
        prompt_path=env_optional_path("SINK_VULN_PROMPT"),
        source_analysis_dir=source_analysis_dir,
        context_expansion_dir=context_expansion_dir,
        interprocedural_context_dir=interprocedural_context_dir,
        max_paths=env_int("SINK_VULN_MAX_PATHS"),
        max_node_code_chars=env_int("SINK_VULN_MAX_NODE_CODE_CHARS"),
    )
    model.analyze_dir(
        sink_paths_dir=sink_paths_dir,
        output_dir=output_dir,
        parallel_workers=env_optional_int("SINK_VULN_PARALLEL_WORKERS"),
        limit=env_optional_int("SINK_VULN_LIMIT"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
