"""Python startup hook for Faramesh autoload.

Python automatically imports `sitecustomize` if present on `sys.path`.
This hook loads `faramesh/autopatch.py` directly so interception can activate
even when the full Faramesh package dependencies have not been imported yet.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


def _load_autopatch_from_source() -> None:
    """Load autopatch module directly from source path without importing package root."""
    autopatch_path = Path(__file__).resolve().parent / "faramesh" / "autopatch.py"
    if not autopatch_path.exists():
        return

    spec = importlib.util.spec_from_file_location("faramesh_autopatch_runtime", autopatch_path)
    if spec is None or spec.loader is None:
        return

    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("faramesh_autopatch_runtime", module)
    spec.loader.exec_module(module)


if os.environ.get("FARAMESH_AUTOLOAD") == "1":
    try:
        _load_autopatch_from_source()
    except Exception:
        # Startup hooks must never break interpreter startup.
        pass
