from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, cast

from sink_finder_pipe.graph import CPGGraph
from sink_finder_pipe.rules import SinkFinderRules
from sink_finder_pipe.search import SinkPathSearch
from utils.env_utils import env_path, load_env


class SinkPathFinderPipeline:
    def __init__(self, project_dir: Path) -> None:
        self.project_dir = project_dir
        load_env(os.getenv("SINK_PATH_ENV_FILE", str(project_dir / "config" / "sink_path_finder.env")))
        self.cpg_path = self.project_path(env_path("SINK_PATH_CPG"))
        self.sources_path = self.project_path(env_path("SINK_PATH_SOURCES"))
        self.output_dir = self.project_path(env_path("SINK_PATH_OUTPUT"))
        self.rules_path = self.project_path(env_path("SINK_PATH_RULES"))
        self.rules = SinkFinderRules(self.rules_path)

    def run(self) -> dict[str, Any]:
        graph = CPGGraph(self.cpg_path, self.rules)
        sources = self.candidate_sources()
        sinks = graph.find_sink_candidates()
        search = SinkPathSearch(graph, self.rules, sinks)
        workers = self.int_setting(self.rules.search()["parallel_workers"], "search.parallel_workers")
        if workers < 1:
            raise ValueError("search.parallel_workers must be >= 1")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.write_json(self.output_dir / self.rules.output()["sink_candidates_file"], [graph.sink_record(sink) for sink in sinks])

        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(search.analyze_source, source, index): (source, index)
                for index, source in enumerate(sources, start=1)
            }
            for done, future in enumerate(as_completed(futures), start=1):
                source, index = futures[future]
                try:
                    record = future.result()
                except Exception as error:
                    record = self.error_record(source, index, error)
                output_file = self.output_dir / self.source_filename(record)
                self.write_json(output_file, record)
                results.append(
                    {
                        "index": index,
                        "sourceNodeId": record.get("sourceNodeId"),
                        "status": record["status"],
                        "reachableSinkCount": record.get("reachableSinkCount", 0),
                        "file": output_file.name,
                    }
                )
                print(
                    f"[{done}/{len(sources)}] saved {record['status']} "
                    f"sourceNodeId={record.get('sourceNodeId')} -> {output_file}",
                    file=sys.stderr,
                )

        summary = {
            "status": "ok",
            "sourcesFile": str(self.sources_path),
            "cpgFile": str(self.cpg_path),
            "rulesFile": str(self.rules_path),
            "outputDir": str(self.output_dir),
            "sourceCount": len(sources),
            "sinkCandidateCount": len(sinks),
            "maxDepth": self.rules.search()["max_depth"],
            "maxPathsPerSource": self.rules.search()["max_paths_per_source"],
            "parallelWorkers": workers,
            "sources": sorted(results, key=lambda item: item["index"]),
        }
        self.write_json(self.output_dir / self.rules.output()["summary_file"], summary)
        return summary

    def candidate_sources(self) -> list[dict[str, Any]]:
        data = self.read_json(self.sources_path)
        sources = self.list_value(data["candidateSources"], "candidateSources")
        return [self.object_value(source, "candidateSource") for source in sources]

    def source_filename(self, record: dict[str, Any]) -> str:
        node_id = record.get("sourceNodeId")
        node_part = f"node_{node_id}" if isinstance(node_id, int) else "node_unknown"
        return self.rules.output()["source_file"].format(index=record["index"], node_part=node_part, status=record["status"])

    @staticmethod
    def error_record(source: dict[str, Any], index: int, error: Exception) -> dict[str, Any]:
        return {
            "status": "error",
            "index": index,
            "sourceNodeId": source.get("nodeId") if isinstance(source.get("nodeId"), int) else None,
            "source": source,
            "error": {"type": type(error).__name__, "message": str(error)},
        }

    def project_path(self, path: Path) -> Path:
        return path if path.is_absolute() else self.project_dir / path

    @staticmethod
    def read_json(path: Path) -> dict[str, Any]:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError(f"{path}: expected JSON object")
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
    def list_value(value: Any, name: str) -> list[Any]:
        if not isinstance(value, list):
            raise TypeError(f"{name} must be a list")
        return value

    @staticmethod
    def int_setting(value: Any, name: str) -> int:
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an int")
        return value
