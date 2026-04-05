"""
Faramesh sitecustomize hook.

This activates the auto-patcher at Python startup. The patcher only fires when
FARAMESH_AUTOLOAD=1 is set (by `faramesh run`).

Installation:
  # Preferred: install faramesh-sdk package (ships sitecustomize module)
  pip install faramesh-sdk

  # Source checkout: add sdk/python to PYTHONPATH
  export PYTHONPATH=/path/to/faramesh-core/sdk/python:$PYTHONPATH

  # Option 2: Add a .pth file to site-packages
  echo "import faramesh.autopatch" > $(python -c "import site; print(site.getsitepackages()[0])")/faramesh-autopatch.pth
"""
import os

if os.environ.get("FARAMESH_AUTOLOAD") == "1":
    try:
        import faramesh.autopatch  # noqa: F401 — import triggers install()
    except ImportError:
        pass
