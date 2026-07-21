#!/usr/bin/env python3
"""Main orchestrator for YAML-driven source-to-sink path discovery."""

from __future__ import annotations

from pathlib import Path

from sink_finder_pipe.pipeline import SinkPathFinderPipeline


def main() -> int:
    summary = SinkPathFinderPipeline(Path(__file__).resolve().parent).run()
    print(
        f"sink paths: sources={summary['sourceCount']} "
        f"sinks={summary['sinkCandidateCount']} output={summary['outputDir']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
