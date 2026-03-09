"""
Binary manager for the faramesh Go daemon.

Downloads and caches the correct platform binary from GitHub Releases on
first use. Starts the daemon as a managed subprocess. No Go toolchain required
by SDK users — just `pip install faramesh`.

Pattern borrowed from ruff, pyright, and esbuild.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

_GITHUB_ORG = "faramesh"
_GITHUB_REPO = "faramesh-core"
_VERSION = "0.1.0"

_PLATFORM_MAP = {
    ("linux", "x86_64"): "linux-amd64",
    ("linux", "aarch64"): "linux-arm64",
    ("darwin", "x86_64"): "darwin-amd64",
    ("darwin", "arm64"): "darwin-arm64",
    ("windows", "amd64"): "windows-amd64",
    ("windows", "x86_64"): "windows-amd64",
}

_cache_dir = Path(os.environ.get("FARAMESH_CACHE_DIR", Path.home() / ".faramesh" / "bin"))
_daemon_proc: subprocess.Popen | None = None
_daemon_lock = threading.Lock()


def binary_path() -> Path:
    """Return the path to the cached faramesh binary, downloading if needed."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    key = (system, machine)
    platform_tag = _PLATFORM_MAP.get(key)
    if platform_tag is None:
        raise RuntimeError(
            f"Unsupported platform: {system}/{machine}. "
            "Please install the faramesh binary manually: https://faramesh.dev/install"
        )

    suffix = ".exe" if system == "windows" else ""
    dest = _cache_dir / f"faramesh-{_VERSION}-{platform_tag}{suffix}"

    if dest.exists():
        return dest

    _download_binary(platform_tag, dest, suffix)
    return dest


def _download_binary(platform_tag: str, dest: Path, suffix: str) -> None:
    """Download the faramesh binary from GitHub Releases."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    filename = f"faramesh-{platform_tag}{suffix}"
    url = (
        f"https://github.com/{_GITHUB_ORG}/{_GITHUB_REPO}/releases/download/"
        f"v{_VERSION}/{filename}"
    )

    print(f"faramesh: downloading binary from {url}", file=sys.stderr)

    # Download to a temp file first to avoid partial writes.
    tmp_fd, tmp_path = tempfile.mkstemp(dir=dest.parent)
    try:
        with os.fdopen(tmp_fd, "wb") as tmp_file:
            with urllib.request.urlopen(url, timeout=60) as resp:
                shutil.copyfileobj(resp, tmp_file)
        os.chmod(tmp_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
        shutil.move(tmp_path, dest)
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise RuntimeError(
            f"Failed to download faramesh binary from {url}: {e}\n"
            "Install manually: https://faramesh.dev/install"
        ) from e

    print(f"faramesh: binary cached at {dest}", file=sys.stderr)


def ensure_daemon_running(
    policy: str,
    socket_path: str = "/tmp/faramesh.sock",
    data_dir: str | None = None,
) -> None:
    """Start the faramesh daemon as a subprocess if it isn't already running.

    This is called automatically by govern() on the first call. Subsequent
    calls are no-ops (guarded by _daemon_lock).

    The daemon is started with the given policy file. If the socket already
    exists and accepts connections, the daemon is assumed to be running and
    this function returns immediately.
    """
    global _daemon_proc

    # Fast path: if the socket already exists, assume daemon is running.
    if os.path.exists(socket_path):
        return

    with _daemon_lock:
        # Double-check after acquiring lock.
        if os.path.exists(socket_path):
            return
        if _daemon_proc is not None and _daemon_proc.poll() is None:
            return

        try:
            bin_path = binary_path()
        except RuntimeError:
            # Development mode: try to find faramesh on PATH.
            bin_path_str = shutil.which("faramesh")
            if bin_path_str is None:
                raise
            bin_path = Path(bin_path_str)

        cmd = [str(bin_path), "serve", "--policy", policy, "--socket", socket_path]
        if data_dir:
            cmd += ["--data-dir", data_dir]

        _daemon_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait up to 3s for the socket to appear.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if os.path.exists(socket_path):
                return
            time.sleep(0.05)

        if _daemon_proc.poll() is not None:
            raise RuntimeError(
                f"faramesh daemon exited immediately. "
                f"Check that {policy} is a valid policy file. "
                "Run: faramesh policy validate " + policy
            )
