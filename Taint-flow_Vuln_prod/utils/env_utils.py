"""Small .env loader for script configuration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping


def load_env(path: str | Path) -> None:
    env_path = Path(path)
    if not env_path.exists():
        raise FileNotFoundError(f"env file not found: {env_path}")

    global_env_path = env_path.parent / ".env"
    pairs: list[tuple[str, str, str]] = []
    if env_path.name != ".env" and global_env_path.exists():
        pairs.extend(parse_env_pairs(global_env_path))
    pairs.extend(parse_env_pairs(env_path))

    values = dict(os.environ)
    for key, value, _ in pairs:
        values.setdefault(key, value)
    values.update(derived_project_values(values))

    for key, value, raw_line in pairs:
        if key in os.environ:
            continue
        try:
            os.environ[key] = value.format_map(values)
        except KeyError as error:
            raise KeyError(f"{env_path}: missing template variable {error.args[0]!r} in line: {raw_line!r}") from error

    for key, value in derived_project_values(os.environ).items():
        os.environ.setdefault(key, value)


def parse_env_pairs(path: Path) -> list[tuple[str, str, str]]:
    pairs: list[tuple[str, str, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator != "=":
            raise ValueError(f"{path}: invalid env line: {raw_line!r}")
        key = key.strip()
        value = value.strip().strip("'\"")
        if not key:
            raise ValueError(f"{path}: empty env key")
        pairs.append((key, value, raw_line))
    return pairs


def derived_project_values(values: Mapping[str, str]) -> dict[str, str]:
    project_name = values.get("PROJECT_NAME")
    if not project_name:
        return {}
    target = strip_cpg_suffix(project_name)
    parts = [part for part in target.split("/") if part]
    cpg_stem = parts[-1]
    project_dir = parts[0] if len(parts) > 1 else cpg_stem
    analysis_name = cpg_stem.removeprefix("cpg_")
    return {
        "PROJECT_NAME": target,
        "PROJECT_DIR": project_dir,
        "CPG_STEM": cpg_stem,
        "ANALYSIS_NAME": analysis_name,
    }


def strip_cpg_suffix(value: str) -> str:
    if value.endswith(".json.bz2"):
        return value.removesuffix(".json.bz2")
    if value.endswith(".json"):
        return value.removesuffix(".json")
    return value


def env_path(name: str) -> Path:
    value = os.getenv(name)
    if value is None:
        raise KeyError(f"missing env var: {name}")
    return Path(value)


def env_optional_path(name: str) -> Path | None:
    value = os.getenv(name)
    return Path(value) if value else None


def env_str(name: str) -> str:
    value = os.getenv(name)
    if value is None:
        raise KeyError(f"missing env var: {name}")
    return value


def env_int(name: str) -> int:
    return int(env_str(name))


def env_optional_int(name: str) -> int | None:
    value = os.getenv(name)
    return int(value) if value else None
