from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Sequence


def run_integrity_check(
    command_template: Sequence[str],
    db_path: Path,
    cwd: Path,
    timeout_seconds: int = 30,
) -> dict[str, object]:
    command: list[str] = []
    replaced = False
    for token in command_template:
        if token == "{db_path}":
            command.append(str(db_path))
            replaced = True
        else:
            command.append(token)

    if not replaced:
        command.append(str(db_path))

    started = time.time()
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        elapsed_ms = int((time.time() - started) * 1000)
        return {
            "ok": proc.returncode == 0,
            "command": command,
            "exit_code": proc.returncode,
            "elapsed_ms": elapsed_ms,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        return {
            "ok": False,
            "command": command,
            "exit_code": -1,
            "elapsed_ms": elapsed_ms,
            "stdout": (exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "").strip() if isinstance(exc.stderr, str) else "integrity check timed out",
        }
