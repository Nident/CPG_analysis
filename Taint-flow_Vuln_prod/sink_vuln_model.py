#!/usr/bin/env python3
"""Main orchestrator for LLM source-to-sink vulnerability verification."""

from __future__ import annotations

from pathlib import Path

from sink_finder_pipe.vuln import SinkVulnPipeline


def main() -> int:
    summary = SinkVulnPipeline(Path(__file__).resolve().parent).run()
    print(f"sink vuln analyzed: files={summary['fileCount']} output={summary['outputDir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
