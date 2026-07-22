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
from sink_finder_pipe.semantic_context import SemanticContextRegistry
from utils.env_utils import env_optional_int, env_optional_path, env_path, env_str, load_env
from utils.payload_builder import PayloadBuilder


class SourceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attacker_control: Literal["none", "partial", "full", "unknown"]
    trust_boundary: str
    relevant_previous_hypotheses: list[str]


class PathAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path_index: int
    sink_node_id: int
    sink_kind: str
    candidate_cwes: list[str]
    vulnerability_probability: float = Field(ge=0.0, le=1.0)
    source_reaches_sink: bool
    attacker_controls_sink_argument: Literal["none", "partial", "full", "unknown"]
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

    vulnerability_probability: float = Field(ge=0.0, le=1.0)
    candidate_cwes: list[str]
    summary: str
    source_assessment: SourceAssessment
    path_assessments: list[PathAssessment]
    most_interesting_paths: list[InterestingPath]
    follow_up_checks: list[str]


class SinkVulnPipeline:
    def __init__(self, project_dir: Path) -> None:
        self.project_dir = project_dir
        load_env(os.getenv("SINK_VULN_ENV_FILE", str(project_dir / "config" / "sink_vuln_model.env")))
        self.sink_paths_dir = self.project_path(env_path("SINK_VULN_SINK_PATHS"))
        self.source_risk_dir = self.project_path(env_path("SINK_VULN_SOURCE_RISK"))
        self.context_dir = self.project_path(env_path("SINK_VULN_CONTEXT_EXPANSION"))
        self.interprocedural_dir = self.project_path(env_path("SINK_VULN_INTERPROCEDURAL_CONTEXT"))
        self.xml_context_dir = self.optional_project_path(env_optional_path("SINK_VULN_XML_CONTEXT"))
        self.output_dir = self.project_path(env_path("SINK_VULN_OUTPUT"))
        self.model_config_path = self.project_path(env_path("SINK_VULN_MODEL_CONFIG"))
        self.model_name = env_str("SINK_VULN_MODEL_NAME")
        self.rules_path = self.project_path(env_optional_path("SINK_VULN_RULES") or self.model_prompt_path())
        self.max_model_requests = env_optional_int("SINK_VULN_MAX_MODEL_REQUESTS")
        self.limit = env_optional_int("SINK_VULN_LIMIT")
        self.parallel_workers = env_optional_int("SINK_VULN_PARALLEL_WORKERS")
        self.rules = self.read_yaml(self.rules_path)
        self.payload_rules_path = self.project_path(env_optional_path("SINK_VULN_PAYLOAD_RULES") or Path("rules/payload.yml"))
        self.payload_builder = PayloadBuilder(self.read_yaml(self.payload_rules_path))
        self.semantic_rules_path = self.project_path(env_optional_path("SINK_VULN_SEMANTIC_CONTEXTS") or Path(self.rules["inputs"]["semantic_contexts"]))
        self.semantic_contexts = SemanticContextRegistry(self.project_dir, self.read_yaml(self.semantic_rules_path), self.read_yaml)
        self.model_config = self.model_profile()
        self.client = self.model_client()

    def run(self) -> dict[str, Any]:
        source_path_files = self.path_files()
        workers = self.parallel_workers or self.int_value(self.model_config["parallel_workers"], "parallel_workers")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        source_path_records = [self.source_path_entry(path) for path in source_path_files]
        jobs = self.sink_jobs(source_path_records)
        request_limit = self.request_limit()
        total_sink_jobs = len(jobs)
        if request_limit is not None:
            jobs = jobs[: request_limit]

        indexes = {
            "source": self.index_dir(self.source_risk_dir, self.rules["inputs"]["source_risk_glob"]),
            "context": self.index_dir(self.context_dir, self.rules["inputs"]["context_expansion_glob"]),
            "interprocedural": self.index_dir(self.interprocedural_dir, self.rules["inputs"]["interprocedural_context_glob"]),
            "external_contexts": {"parser": self.external_context_index()},
        }

        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.analyze_job, job, indexes): job for job in jobs}
            for done, future in enumerate(as_completed(futures), start=1):
                job = futures[future]
                try:
                    record = future.result()
                except Exception as error:
                    record = self.error_record(job, indexes, error)
                output_file = self.output_dir / self.result_filename(job["inputStem"], record["status"])
                self.write_json(output_file, record)
                results.append(
                    {
                        "inputFile": job.get("inputFile"),
                        "outputFile": output_file.name,
                        "sourceNodeIds": record.get("sourceNodeIds", []),
                        "sinkNodeId": record.get("sinkNodeId"),
                        "status": record["status"],
                    }
                )
                print(f"[{done}/{len(jobs)}] saved {record['status']} sinkNodeId={record.get('sinkNodeId')} -> {output_file}", file=sys.stderr)

        summary = {
            "status": "ok",
            "sinkPathsDir": str(self.sink_paths_dir),
            "sourceRiskDir": str(self.source_risk_dir),
            "contextExpansionDir": str(self.context_dir),
            "interproceduralContextDir": str(self.interprocedural_dir),
            "xmlContextDir": str(self.xml_context_dir) if self.xml_context_dir is not None else None,
            "rulesFile": str(self.rules_path),
            "payloadRulesFile": str(self.payload_rules_path),
            "semanticContextRulesFile": str(self.semantic_rules_path),
            "modelConfigFile": str(self.model_config_path),
            "modelName": self.model_name,
            "outputDir": str(self.output_dir),
            "totalSinkJobCount": total_sink_jobs,
            "maxModelRequests": request_limit,
            "sourcePathFileCount": len(source_path_files),
            "sinkJobCount": len(jobs),
            "fileCount": len(jobs),
            "parallelWorkers": workers,
            "results": sorted(results, key=lambda item: item["outputFile"]),
        }
        self.write_json(self.output_dir / self.rules["output"]["summary_file"], summary)
        return summary

    def request_limit(self) -> int | None:
        limit = self.max_model_requests if self.max_model_requests is not None else self.limit
        if limit is not None and limit < 0:
            raise ValueError("SINK_VULN_MAX_MODEL_REQUESTS must be >= 0")
        return limit

    def analyze_job(self, job: dict[str, Any], indexes: dict[str, Any]) -> dict[str, Any]:
        source_path_record = self.object_value(job["record"], "job.record")
        source_ids = self.int_list(job.get("sourceNodeIds", []), "job.sourceNodeIds")
        payload = self.payload(source_path_record, source_ids, indexes)
        prompt_path = self.output_dir / self.prompt_filename(job["inputStem"]) if self.rules["output"]["save_prompts"] else None
        analysis = self.client.request(self.payload_builder.dumps("sink_vuln", payload), prompt_output_path=prompt_path)
        return {
            "status": "ok",
            "analysisMode": source_path_record.get("analysisMode"),
            "sourceNodeIds": source_ids,
            "sourceNodeId": source_ids[0] if source_ids else None,
            "sinkNodeId": job.get("sinkNodeId"),
            "inputFile": job.get("inputFile"),
            "previousSourceAnalysisFiles": [self.index_file(indexes["source"].get(source_id)) for source_id in source_ids],
            "contextExpansionFiles": [self.index_file(indexes["context"].get(source_id)) for source_id in source_ids],
            "interproceduralContextFiles": [self.index_file(indexes["interprocedural"].get(source_id)) for source_id in source_ids],
            "semanticContextFiles": self.semantic_context_files(payload.get("semantic_contexts")),
            "analysis": analysis.model_dump(),
        }

    def payload(self, source_path_record: dict[str, Any], source_ids: list[int], indexes: dict[str, Any]) -> dict[str, Any]:
        source_analysis = self.index_data(indexes["source"].get(source_ids[0])) if source_ids else None
        expanded_context = self.index_data(indexes["context"].get(source_ids[0])) if source_ids else None
        interprocedural_context = self.index_data(indexes["interprocedural"].get(source_ids[0])) if source_ids else None
        related_source_analyses = [self.index_data(indexes["source"].get(source_id)) for source_id in source_ids]
        related_expanded_contexts = [self.index_data(indexes["context"].get(source_id)) for source_id in source_ids]
        related_interprocedural_contexts = [self.index_data(indexes["interprocedural"].get(source_id)) for source_id in source_ids]
        external_contexts = indexes["external_contexts"]
        if not isinstance(external_contexts, dict):
            raise TypeError("external_contexts index must be a mapping")
        semantic_contexts = self.semantic_contexts.build_all(source_path_record, source_analysis, expanded_context, interprocedural_context, external_contexts)
        sections = {
            "source_path_record": source_path_record,
            "sink_candidate": source_path_record.get("sinkCandidate"),
            "previous_source_analysis": source_analysis,
            "expanded_context": expanded_context,
            "interprocedural_context": interprocedural_context,
            "related_previous_source_analyses": related_source_analyses,
            "related_expanded_contexts": related_expanded_contexts,
            "related_interprocedural_contexts": related_interprocedural_contexts,
            "semantic_contexts": semantic_contexts,
        }
        return self.payload_builder.build("sink_vuln", sections)

    def source_path_entry(self, path: Path) -> dict[str, Any]:
        record = self.read_json(path)
        return {"path": path, "record": record}

    def sink_jobs(self, source_path_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped_paths = self.paths_by_sink(source_path_entries)
        jobs: list[dict[str, Any]] = []
        for index, sink in enumerate(self.sink_candidates(), start=1):
            sink_id = self.sink_id(sink)
            if sink_id is None:
                continue
            paths = grouped_paths.get(sink_id, [])
            source_ids = sorted({item["sourceNodeId"] for item in paths if isinstance(item.get("sourceNodeId"), int)})
            record = self.sink_record(sink, sink_id, paths)
            jobs.append(
                {
                    "inputStem": f"{index:06d}_sink_node_{sink_id}",
                    "sinkNodeId": sink_id,
                    "sourceNodeIds": source_ids,
                    "inputFile": str(self.sink_candidates_path()),
                    "record": record,
                }
            )
        return jobs

    def paths_by_sink(self, source_path_entries: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
        result: dict[int, list[dict[str, Any]]] = {}
        for entry in source_path_entries:
            record = self.object_value(entry["record"], "source_path_record")
            source_id = self.optional_int(record.get("sourceNodeId"))
            for path_index, path in enumerate(record.get("paths", [])):
                if not isinstance(path, dict):
                    continue
                sink = path.get("sink")
                if not isinstance(sink, dict):
                    continue
                sink_id = self.optional_int(sink.get("nodeId"))
                if sink_id is None:
                    continue
                enriched = dict(path)
                enriched["sourceNodeId"] = source_id
                enriched["source"] = record.get("source")
                enriched["sourcePathIndex"] = path_index
                enriched["sourcePathFile"] = str(entry["path"])
                result.setdefault(sink_id, []).append(enriched)
        return result

    def sink_record(self, sink: dict[str, Any], sink_id: int, paths: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "analysisMode": "sink_centric",
            "sourceNodeId": None,
            "sourceNodeIds": sorted({path["sourceNodeId"] for path in paths if isinstance(path.get("sourceNodeId"), int)}),
            "sinkNodeId": sink_id,
            "sinkCandidate": sink,
            "reachableSourcePathCount": len(paths),
            "paths": paths if paths else [self.synthetic_sink_path(sink, sink_id)],
        }

    @staticmethod
    def synthetic_sink_path(sink: dict[str, Any], sink_id: int) -> dict[str, Any]:
        return {
            "sourceNodeId": None,
            "sink": sink,
            "path": [{"node": sink.get("node"), "role": "sink"}],
            "evidence": {
                "pathQuality": "sink_only_context",
                "sourceReachesSink": False,
                "reason": "No source-to-sink path was found. Analyze sink configuration and local context.",
            },
            "sourcePathIndex": None,
        }

    def path_files(self) -> list[Path]:
        if not self.sink_paths_dir.is_dir():
            raise ValueError(f"{self.sink_paths_dir}: sink paths input must be a directory")
        return sorted(self.sink_paths_dir.glob(self.rules["inputs"]["sink_path_glob"]))

    def sink_candidates(self) -> list[dict[str, Any]]:
        path = self.sink_candidates_path()
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise TypeError(f"{path}: expected JSON list")
        return [self.object_value(item, "sink_candidate") for item in data]

    def sink_candidates_path(self) -> Path:
        return self.sink_paths_dir / self.str_value(self.rules["inputs"]["sink_candidates_file"], "inputs.sink_candidates_file")

    @staticmethod
    def sink_id(sink: dict[str, Any]) -> int | None:
        node_id = sink.get("nodeId")
        if isinstance(node_id, int):
            return node_id
        node = sink.get("node")
        if isinstance(node, dict) and isinstance(node.get("nodeId"), int):
            return node["nodeId"]
        return None

    def index_dir(self, path: Path, pattern: str) -> dict[int, dict[str, Any]]:
        if not path.exists():
            return {}
        if not path.is_dir():
            raise ValueError(f"{path}: expected directory")
        index: dict[int, dict[str, Any]] = {}
        for item in sorted(path.glob(pattern)):
            data = self.read_json(item)
            node_id = self.optional_int(data.get("nodeId")) or self.optional_int(data.get("sourceNodeId"))
            if node_id is not None:
                index[node_id] = {"path": str(item), "data": data}
        return index

    def external_context_index(self) -> dict[int, dict[str, Any]]:
        if self.xml_context_dir is None:
            return {}
        path = self.xml_context_dir / self.rules["inputs"]["xml_context_file"]
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise TypeError(f"{path}: expected JSON list")
        index: dict[int, dict[str, Any]] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            entry = {"path": str(path), "data": cast(dict[str, Any], item)}
            for node_id in item.get("sinkNodeIds", []):
                if isinstance(node_id, int):
                    index[node_id] = entry
        return index

    @staticmethod
    def semantic_context_files(semantic_contexts: Any) -> list[str]:
        if not isinstance(semantic_contexts, dict):
            return []
        files: list[str] = []
        for context in semantic_contexts.values():
            external = context.get("externalContexts") if isinstance(context, dict) else None
            if not isinstance(external, list):
                continue
            for item in external:
                if isinstance(item, dict) and isinstance(item.get("path"), str) and item["path"] not in files:
                    files.append(item["path"])
        return files

    def model_client(self) -> ModelClient[SinkVulnerabilityAnalysis]:
        prompt = self.rules["prompt"]
        return ModelClient[SinkVulnerabilityAnalysis](
            base_url=self.str_value(self.model_config["base_url"], "base_url"),
            api_key=self.str_value(self.model_config["api_key"], "api_key"),
            model=self.str_value(self.model_config["model"], "model"),
            temperature=self.float_value(self.model_config["temperature"], "temperature"),
            max_tokens=self.int_value(self.model_config["max_tokens"], "max_tokens"),
            timeout=self.int_value(self.model_config["timeout"], "timeout"),
            system_prompt=self.str_value(prompt["system_prompt"], "prompt.system_prompt"),
            user_prompt=self.str_value(prompt["user_prompt"], "prompt.user_prompt"),
            response_schema=SinkVulnerabilityAnalysis,
        )

    def model_profile(self) -> dict[str, Any]:
        data = self.read_yaml(self.model_config_path)
        profile = self.object_value(self.object_value(data["models"], "models")[self.model_name], f"models.{self.model_name}")
        return {"api_key": self.str_value(data["api_key"], "api_key"), **profile}

    def model_prompt_path(self) -> Path:
        data = self.read_yaml(self.model_config_path)
        profile = self.object_value(self.object_value(data["models"], "models")[self.model_name], f"models.{self.model_name}")
        prompt = Path(self.str_value(profile["prompt_file"], "prompt_file"))
        return prompt if prompt.is_absolute() else self.model_config_path.parent / prompt

    def error_record(self, job: dict[str, Any], indexes: dict[str, Any], error: Exception) -> dict[str, Any]:
        source_ids = self.int_list(job.get("sourceNodeIds", []), "job.sourceNodeIds")
        return {
            "status": "error",
            "sourceNodeIds": source_ids,
            "sourceNodeId": source_ids[0] if source_ids else None,
            "sinkNodeId": job.get("sinkNodeId"),
            "inputFile": job.get("inputFile"),
            "previousSourceAnalysisFiles": [self.index_file(indexes["source"].get(source_id)) for source_id in source_ids],
            "contextExpansionFiles": [self.index_file(indexes["context"].get(source_id)) for source_id in source_ids],
            "interproceduralContextFiles": [self.index_file(indexes["interprocedural"].get(source_id)) for source_id in source_ids],
            "semanticContextFiles": [],
            "error": {"type": type(error).__name__, "message": str(error)},
        }

    def result_filename(self, input_stem: str, status: str) -> str:
        return self.rules["output"]["result_file"].format(input_stem=input_stem, status=status)

    def prompt_filename(self, input_stem: str) -> str:
        return self.rules["output"]["prompt_file"].format(input_stem=input_stem)

    @staticmethod
    def index_data(entry: dict[str, Any] | None) -> dict[str, Any] | None:
        return entry["data"] if entry is not None else None

    @staticmethod
    def index_file(entry: dict[str, Any] | None) -> str | None:
        return entry["path"] if entry is not None else None

    def project_path(self, path: Path) -> Path:
        return path if path.is_absolute() else self.project_dir / path

    def optional_project_path(self, path: Path | None) -> Path | None:
        return None if path is None else self.project_path(path)

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
    def write_json(path: Path, data: Any) -> None:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def object_value(value: Any, name: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError(f"{name} must be an object")
        return cast(dict[str, Any], value)

    @staticmethod
    def optional_int(value: Any) -> int | None:
        return value if isinstance(value, int) else None

    @staticmethod
    def int_list(value: Any, name: str) -> list[int]:
        if not isinstance(value, list) or not all(isinstance(item, int) for item in value):
            raise TypeError(f"{name} must be list[int]")
        return cast(list[int], value)

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
    def float_value(value: Any, name: str) -> float:
        if not isinstance(value, int | float):
            raise TypeError(f"{name} must be numeric")
        return float(value)


def main() -> int:
    summary = SinkVulnPipeline(Path(__file__).resolve().parents[1]).run()
    print(f"sink vuln analyzed: files={summary['fileCount']} output={summary['outputDir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
