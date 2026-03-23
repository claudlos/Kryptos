"""Helpers for wrapping standalone research scripts as structured toolkit strategies."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .paths import REPO_ROOT


def run_script_and_load_json(script_name: str, output_path: str) -> dict[str, object]:
    script_path = REPO_ROOT / script_name
    completed = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    payload_path = REPO_ROOT / output_path
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["_stdout_tail"] = "\n".join(completed.stdout.strip().splitlines()[-20:]) if completed.stdout.strip() else ""
    return payload


def preview_from_text(text: str, limit: int = 85) -> str:
    return text if len(text) <= limit else f"{text[:limit]}..."
