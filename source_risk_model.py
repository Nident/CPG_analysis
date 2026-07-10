#!/usr/bin/env python3
"""Strict orchestrator for CPG candidate-source risk triage."""

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

from env_utils import env_optional_int, env_optional_path, env_path, env_str, load_env
from model import ModelClient


Priority = Literal["low", "medium", "high"]


class RiskHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Stable short id, for example H1.")
    title: str = Field(description="Short hypothesis title.")
    sink_classes_to_check: list[str] = Field(
        description="Sink classes that can confirm or reject the hypothesis."
    )
    expected_taint_shape: str = Field(
        description="How the source value would need to reach a sink."
    )
    verification_steps: list[str] = Field(
        description="Concrete checks for the next sink/data-flow analysis stage."
    )


class SourceRiskAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_summary: str = Field(description="One sentence describing the source.")
    vulnerability_probability: float = Field(
        ge=0.0,
        le=1.0,
        description="Probability from 0.0 to 1.0 that this source can participate in a vulnerability.",
    )
    trust_boundary: str = Field(description="Who or what controls this input.")
    attacker_control: Literal["none", "partial", "full", "unknown"] = Field(
        description="Estimated attacker control over the source."
    )
    possible_vulnerability_classes: list[str] = Field(
        description="Potential bug classes, for example command injection or path traversal."
    )
    hypotheses: list[RiskHypothesis] = Field(
        description="Hypotheses to verify later with sink and data-flow evidence."
    )
    arguments_for_vulnerability: list[str] = Field(
        description="Evidence that makes exploitation plausible."
    )
    arguments_against_vulnerability: list[str] = Field(
        description="Evidence that may make this benign or low risk."
    )
    missing_evidence: list[str] = Field(
        description="Specific evidence still needed before claiming a vulnerability."
    )
    priority: Priority = Field(description="Triage priority for sink collection.")


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
    code: str
    assignedTo: dict[str, Any]
    enclosingFunction: dict[str, Any]
    dataflow: list[dict[str, Any]]
    relatedUses: list[dict[str, Any]]


class SourceAnalysisRecord(TypedDict):
    status: Literal["ok"]
    index: int
    nodeId: int | None
    artifact: str | None
    startLine: int | None
    endLine: int | None
    kind: str | None
    ruleId: str | None
    analysis: dict[str, Any]


class SourceErrorRecord(TypedDict):
    status: Literal["error"]
    index: int
    nodeId: int | None
    artifact: str | None
    startLine: int | None
    endLine: int | None
    kind: str | None
    ruleId: str | None
    error: dict[str, str]


SourceResultRecord = SourceAnalysisRecord | SourceErrorRecord


@dataclass(frozen=True)
class ModelConfig:
    base_url: str
    api_key: str
    model: str
    temperature: float
    max_tokens: int
    timeout: int
    max_source_chars: int
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
            max_source_chars=require_type(data, "max_source_chars", int, path),
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


class SourceRiskModel:
    """Loads configs and sources, prepares payloads, runs model calls, writes results."""

    def __init__(self, config_path: str | Path, model_name: str) -> None:
        self.config = ModelConfig.from_yaml(Path(config_path), model_name)
        self.prompts = PromptConfig.from_yaml(self.config.prompt_file)
        self.model_client = ModelClient[SourceRiskAnalysis](
            base_url=self.config.base_url,
            api_key=self.config.api_key,
            model=self.config.model,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            timeout=self.config.timeout,
            system_prompt=self.prompts.system_prompt,
            user_prompt=self.prompts.user_prompt,
            response_schema=SourceRiskAnalysis,
        )

    def analyze_source(
        self,
        source: CandidateSource,
        index: int,
        prompt_output_path: Path,
    ) -> SourceAnalysisRecord:
        source_json = json.dumps(source, ensure_ascii=False, indent=2)
        if len(source_json) > self.config.max_source_chars:
            source_json = source_json[: self.config.max_source_chars]

        analysis = self.model_client.request(source_json, prompt_output_path=prompt_output_path)
        return {
            "status": "ok",
            "index": index,
            "nodeId": source.get("nodeId"),
            "artifact": source.get("artifact"),
            "startLine": source.get("startLine"),
            "endLine": source.get("endLine"),
            "kind": source.get("kind"),
            "ruleId": source.get("ruleId"),
            "analysis": analysis.model_dump(),
        }

    def analyze_sources_file(
        self,
        sources_path: str | Path,
        output_dir: str | Path,
        limit: int | None,
        parallel_workers: int | None,
    ) -> None:
        sources = load_candidate_sources(Path(sources_path))
        if limit is not None:
            sources = sources[:limit]

        workers = parallel_workers if parallel_workers is not None else self.config.parallel_workers
        self.analyze_sources_parallel_to_dir(sources, Path(output_dir), workers)

    def analyze_sources_parallel_to_dir(
        self,
        sources: list[CandidateSource],
        output_dir: Path,
        parallel_workers: int,
    ) -> None:
        if parallel_workers < 1:
            raise ValueError("parallel_workers must be >= 1")
        if output_dir.exists() and not output_dir.is_dir():
            raise ValueError(f"{output_dir}: output path must be a directory")

        output_dir.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
            futures = {
                executor.submit(
                    self.analyze_source,
                    source,
                    index,
                    output_dir / prompt_filename(source, index),
                ): index
                for index, source in enumerate(sources, start=1)
            }
            completed = 0
            for future in as_completed(futures):
                index = futures[future]
                source = sources[index - 1]
                try:
                    record: SourceResultRecord = future.result()
                except Exception as error:
                    record = build_error_record(source, index, error)

                completed += 1
                output_file = output_dir / result_filename(record)
                write_pretty_json(output_file, record)
                print(
                    f"[{completed}/{len(sources)}] saved {record['status']} "
                    f"index={index} nodeId={record['nodeId']} -> {output_file}",
                    file=sys.stderr,
                )


def load_candidate_sources(path: Path) -> list[CandidateSource]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path}: expected top-level JSON object")

    candidate_sources = data["candidateSources"]
    if not isinstance(candidate_sources, list):
        raise TypeError(f"{path}: candidateSources must be a list")
    for item in candidate_sources:
        if not isinstance(item, dict):
            raise TypeError(f"{path}: every candidate source must be an object")

    return cast(list[CandidateSource], candidate_sources)


def build_error_record(
    source: CandidateSource,
    index: int,
    error: Exception,
) -> SourceErrorRecord:
    return {
        "status": "error",
        "index": index,
        "nodeId": source.get("nodeId"),
        "artifact": source.get("artifact"),
        "startLine": source.get("startLine"),
        "endLine": source.get("endLine"),
        "kind": source.get("kind"),
        "ruleId": source.get("ruleId"),
        "error": {
            "type": type(error).__name__,
            "message": str(error),
        },
    }


def result_filename(record: SourceResultRecord) -> str:
    node = record["nodeId"]
    node_part = f"node_{node}" if node is not None else "node_unknown"
    return f"{record['index']:06d}_{node_part}_{record['status']}.json"


def prompt_filename(source: CandidateSource, index: int) -> str:
    node = source.get("nodeId")
    node_part = f"node_{node}" if node is not None else "node_unknown"
    return f"{index:06d}_{node_part}_prompt.json"


def write_pretty_json(path: Path, data: SourceResultRecord) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def default_output_dir_for_sources(sources_path: str | Path) -> Path:
    path = Path(sources_path)
    name = path.name
    if not name.endswith(".sources.json"):
        raise ValueError(f"{path}: sources filename must end with .sources.json")
    return path.parent.parent / "outputs" / name.removesuffix(".sources.json")


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


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    env_file = os.getenv(
        "SOURCE_RISK_ENV_FILE",
        str(base_dir / "config" / "source_risk_model.env"),
    )
    load_env(env_file)

    sources = env_path("SOURCE_RISK_SOURCES")
    output = env_optional_path("SOURCE_RISK_OUTPUT")
    if output is None:
        output = default_output_dir_for_sources(sources)

    source_model = SourceRiskModel(
        env_path("SOURCE_RISK_MODEL_CONFIG"),
        env_str("SOURCE_RISK_MODEL_NAME"),
    )
    source_model.analyze_sources_file(
        sources,
        output,
        env_optional_int("SOURCE_RISK_LIMIT"),
        env_optional_int("SOURCE_RISK_PARALLEL_WORKERS"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
