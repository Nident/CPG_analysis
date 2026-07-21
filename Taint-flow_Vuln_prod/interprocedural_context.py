#!/usr/bin/env python3
"""Main orchestrator for synthetic interprocedural propagation context."""

from __future__ import annotations

from pathlib import Path

from sink_finder_pipe.interprocedural import InterproceduralContextPipeline


def main() -> int:
    summary = InterproceduralContextPipeline(Path(__file__).resolve().parent).run()
    print(f"interprocedural context: sources={summary['sourceCount']} output={summary['outputDir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
