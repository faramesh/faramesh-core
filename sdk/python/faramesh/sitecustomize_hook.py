"""
Faramesh sitecustomize hook.

When installed via PYTHONPATH or as a .pth file, this activates
the auto-patcher at Python startup. The patcher only fires when
FARAMESH_AUTOLOAD=1 is set (by `faramesh run`).

Installation:
  # Option 1: Set PYTHONPATH (faramesh run does this automatically)
  export PYTHONPATH=/path/to/faramesh-python-sdk-code:$PYTHONPATH

  # Option 2: Add a .pth file to site-packages
  echo "import faramesh.autopatch" > $(python -c "import site; print(site.getsitepackages()[0])")/faramesh-autopatch.pth
"""
import os

if os.environ.get("FARAMESH_AUTOLOAD") == "1":
    try:
        import faramesh.autopatch  # noqa: F401 — import triggers install()
    except ImportError:
        pass
