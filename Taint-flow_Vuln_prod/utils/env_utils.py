"""Small .env loader for script configuration."""

from __future__ import annotations

import os
from pathlib import Path


def load_env(path: str | Path) -> None:
    env_path = Path(path)
    if not env_path.exists():
        raise FileNotFoundError(f"env file not found: {env_path}")

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator != "=":
            raise ValueError(f"{env_path}: invalid env line: {raw_line!r}")
        key = key.strip()
        value = value.strip().strip("'\"")
        if not key:
            raise ValueError(f"{env_path}: empty env key")
        os.environ.setdefault(key, value)


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
