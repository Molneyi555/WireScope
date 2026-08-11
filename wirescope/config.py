from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


DEFAULT_CONFIG: Dict[str, Any] = {
    "live": {"interval": 1.5},
    "browser": {
        "duration": 20.0,
        "idle": 3.0,
        "port": 9223,
        "profile": "/private/tmp/wirescope-browser-profile",
        "disable_cache": True,
        "max_body_bytes": 1_000_000,
    },
    "quality": {"host": "1.1.1.1", "domain": "example.com", "count": 5},
    "dns": {"comparison_servers": "1.1.1.1,8.8.8.8,9.9.9.9"},
    "privacy": {"redact_sensitive": True},
    "output": {"directory": "wirescope-results"},
}


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = {key: (deep_merge(value, {}) if isinstance(value, dict) else value) for key, value in base.items()}
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def default_user_path() -> Path:
    configured = os.environ.get("WIRESCOPE_CONFIG")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".config" / "wirescope" / "config.json"


def find_config() -> Optional[Path]:
    configured = os.environ.get("WIRESCOPE_CONFIG")
    candidates = [Path(configured).expanduser()] if configured else [Path.cwd() / ".wirescope.json", default_user_path()]
    return next((path for path in candidates if path.is_file()), None)


def load_config() -> Tuple[Dict[str, Any], Optional[Path], Optional[str]]:
    path = find_config()
    if path is None:
        return deep_merge(DEFAULT_CONFIG, {}), None, None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("root must be a JSON object")
        return deep_merge(DEFAULT_CONFIG, value), path, None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return deep_merge(DEFAULT_CONFIG, {}), path, str(exc)


def write_default_config(path: Path, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def get(config: Dict[str, Any], section: str, key: str, fallback: Any) -> Any:
    value = config.get(section, {})
    return value.get(key, fallback) if isinstance(value, dict) else fallback

