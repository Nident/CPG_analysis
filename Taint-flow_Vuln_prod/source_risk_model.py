#!/usr/bin/env python3
"""YAML-driven LLM triage for source candidates."""

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field

from model import ModelClient
from utils.env_utils import env_optional_int, env_optional_path, env_path, env_str, load_env
from utils.payload_builder import PayloadBuilder


class RiskHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    sink_classes_to_check: list[str]
    expected_taint_shape: str
    verification_steps: list[str]


class SourceRiskAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_summary: str
    vulnerability_probability: float = Field(ge=0.0, le=1.0)
    trust_boundary: str
    attacker_control: Literal["none", "partial", "full", "unknown"]
    possible_vulnerability_classes: list[str]
    hypotheses: list[RiskHypothesis]
    arguments_for_vulnerability: list[str]
    arguments_against_vulnerability: list[str]
    missing_evidence: list[str]
    priority: Literal["low", "medium", "high"]


class SourceRiskModel:
    def __init__(self, project_dir: Path) -> None:
        self.project_dir = project_dir
        load_env(os.getenv("SOURCE_RISK_ENV_FILE", str(project_dir / "config" / "source_risk_model.env")))
        self.sources_path = self.project_path(env_path("SOURCE_RISK_SOURCES"))
        self.output_dir = self.project_path(env_path("SOURCE_RISK_OUTPUT"))
        self.model_config_path = self.project_path(env_path("SOURCE_RISK_MODEL_CONFIG"))
        self.model_name = env_str("SOURCE_RISK_MODEL_NAME")
        self.rules_path = self.project_path(env_optional_path("SOURCE_RISK_RULES") or self.model_prompt_path())
        self.limit = env_optional_int("SOURCE_RISK_LIMIT")
        self.parallel_workers = env_optional_int("SOURCE_RISK_PARALLEL_WORKERS")
        self.model_config = self.model_profile()
        self.rules = self.read_yaml(self.rules_path)
        self.payload_rules_path = self.project_path(env_optional_path("SOURCE_RISK_PAYLOAD_RULES") or Path("rules/payload.yml"))
        self.payload_builder = PayloadBuilder(self.read_yaml(self.payload_rules_path))
        self.client = self.model_client()

    def run(self) -> dict[str, Any]:
        sources = self.candidate_sources()
        if self.limit is not None:
            sources = sources[: self.limit]

        workers = self.parallel_workers or self.int_setting(self.model_config["parallel_workers"], "parallel_workers")
        if workers < 1:
            raise ValueError("SOURCE_RISK_PARALLEL_WORKERS must be >= 1")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.analyze_one, source, index): (source, index)
                for index, source in enumerate(sources, start=1)
            }
            for done, future in enumerate(as_completed(futures), start=1):
                source, index = futures[future]
                try:
                    record = future.result()
                except Exception as error:
                    record = self.error_record(source, index, error)
                self.write_json(self.output_dir / self.result_filename(record), record)
                results.append(
                    {
                        "index": index,
                        "nodeId": record.get("nodeId"),
                        "status": record["status"],
                        "file": self.result_filename(record),
                    }
                )
                print(
                    f"[{done}/{len(sources)}] saved {record['status']} "
                    f"index={index} nodeId={record.get('nodeId')}",
                    file=sys.stderr,
                )

        summary = {
            "status": "ok",
            "sourcesFile": str(self.sources_path),
            "rulesFile": str(self.rules_path),
            "payloadRulesFile": str(self.payload_rules_path),
            "modelConfigFile": str(self.model_config_path),
            "modelName": self.model_name,
            "outputDir": str(self.output_dir),
            "sourceCount": len(sources),
            "parallelWorkers": workers,
            "results": sorted(results, key=lambda item: item["index"]),
        }
        self.write_json(self.output_dir / "summary.json", summary)
        return summary

    def analyze_one(self, source: dict[str, Any], index: int) -> dict[str, Any]:
        payload = self.payload_builder.build("source_risk", source)
        source_json = self.payload_builder.dumps("source_risk", payload)
        prompt_path = self.output_dir / self.prompt_filename(source, index) if self.save_prompts() else None
        analysis = self.client.request(source_json, prompt_output_path=prompt_path)
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

    def candidate_sources(self) -> list[dict[str, Any]]:
        data = self.read_json(self.sources_path)
        sources = self.list_value(data["candidateSources"], "candidateSources")
        return [self.object_value(source, "candidateSource") for source in sources]

    def model_client(self) -> ModelClient[SourceRiskAnalysis]:
        prompt = self.object_value(self.rules["prompt"], "prompt")
        return ModelClient[SourceRiskAnalysis](
            base_url=self.str_setting(self.model_config["base_url"], "base_url"),
            api_key=self.str_setting(self.model_config["api_key"], "api_key"),
            model=self.str_setting(self.model_config["model"], "model"),
            temperature=self.float_setting(self.model_config["temperature"], "temperature"),
            max_tokens=self.int_setting(self.model_config["max_tokens"], "max_tokens"),
            timeout=self.int_setting(self.model_config["timeout"], "timeout"),
            system_prompt=self.str_setting(prompt["system_prompt"], "prompt.system_prompt"),
            user_prompt=self.str_setting(prompt["user_prompt"], "prompt.user_prompt"),
            response_schema=SourceRiskAnalysis,
        )

    def model_profile(self) -> dict[str, Any]:
        data = self.read_yaml(self.model_config_path)
        models = self.object_value(data["models"], "models")
        profile = self.object_value(models[self.model_name], f"models.{self.model_name}")
        return {"api_key": self.str_setting(data["api_key"], "api_key"), **profile}

    def model_prompt_path(self) -> Path:
        data = self.read_yaml(self.model_config_path)
        profile = self.object_value(self.object_value(data["models"], "models")[self.model_name], f"models.{self.model_name}")
        prompt_file = Path(self.str_setting(profile["prompt_file"], "prompt_file"))
        return prompt_file if prompt_file.is_absolute() else self.model_config_path.parent / prompt_file

    def error_record(self, source: dict[str, Any], index: int, error: Exception) -> dict[str, Any]:
        return {
            "status": "error",
            "index": index,
            "nodeId": source.get("nodeId"),
            "artifact": source.get("artifact"),
            "startLine": source.get("startLine"),
            "endLine": source.get("endLine"),
            "kind": source.get("kind"),
            "ruleId": source.get("ruleId"),
            "error": {"type": type(error).__name__, "message": str(error)},
        }

    def result_filename(self, record: dict[str, Any]) -> str:
        return self.output_template("result_file").format(
            index=record["index"],
            node_part=self.node_part(record),
            status=record["status"],
        )

    def prompt_filename(self, source: dict[str, Any], index: int) -> str:
        return self.output_template("prompt_file").format(
            index=index,
            node_part=self.node_part(source),
            status="prompt",
        )

    def node_part(self, record: dict[str, Any]) -> str:
        node_id = record.get("nodeId")
        return f"node_{node_id}" if isinstance(node_id, int) else "node_unknown"

    def output_template(self, key: str) -> str:
        return self.str_setting(self.rules["output"][key], f"output.{key}")

    def save_prompts(self) -> bool:
        value = self.rules["output"]["save_prompts"]
        if not isinstance(value, bool):
            raise TypeError("output.save_prompts must be bool")
        return value

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
    def write_json(path: Path, data: dict[str, Any]) -> None:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

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
    def str_setting(value: Any, name: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        return value

    @staticmethod
    def int_setting(value: Any, name: str) -> int:
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an int")
        return value

    @staticmethod
    def float_setting(value: Any, name: str) -> float:
        if not isinstance(value, int | float):
            raise TypeError(f"{name} must be numeric")
        return float(value)


def main() -> int:
    summary = SourceRiskModel(Path(__file__).resolve().parent).run()
    print(f"source risk analyzed: {summary['sourceCount']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
