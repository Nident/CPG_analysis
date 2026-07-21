#!/usr/bin/env python3
"""Main orchestrator for deterministic downstream context expansion."""

from __future__ import annotations

from pathlib import Path

from sink_finder_pipe.context import ContextExpansionPipeline


def main() -> int:
    summary = ContextExpansionPipeline(Path(__file__).resolve().parent).run()
    print(f"context expanded: sources={summary['sourceCount']} output={summary['outputDir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
