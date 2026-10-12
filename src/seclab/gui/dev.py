"""Chạy GUI ở chế độ phát triển và khởi động lại khi mã Python được lưu."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path


_POLL_SECONDS = 0.4
_STABLE_SECONDS = 0.8


def _snapshot(source_root: Path) -> tuple[tuple[str, int, int], ...]:
    files = []
    for path in source_root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        try:
            info = path.stat()
        except OSError:
            continue
        files.append((path.relative_to(source_root).as_posix(), info.st_mtime_ns, info.st_size))
    return tuple(sorted(files))


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main() -> int:
    source_root = Path(__file__).resolve().parents[1]
    launch = [sys.executable, "-m", "seclab.gui.app"]
    observed = _snapshot(source_root)
    process = subprocess.Popen(launch, cwd=Path.cwd())
    pending_since: float | None = None
    print(f"[seclab-gui-dev] Đang theo dõi {source_root}; lưu mã Python để tự khởi động lại. Nhấn Ctrl+C để dừng.", flush=True)
    try:
        while True:
            exit_code = process.poll()
            if exit_code is not None:
                return exit_code

            current = _snapshot(source_root)
            if current != observed:
                observed = current
                pending_since = time.monotonic()
            elif pending_since is not None and time.monotonic() - pending_since >= _STABLE_SECONDS:
                print("[seclab-gui-dev] Mã nguồn đã thay đổi; đang khởi động lại giao diện.", flush=True)
                _stop(process)
                process = subprocess.Popen(launch, cwd=Path.cwd())
                observed = _snapshot(source_root)
                pending_since = None
            time.sleep(_POLL_SECONDS)
    except KeyboardInterrupt:
        print("\n[seclab-gui-dev] Đang dừng trình theo dõi giao diện.", flush=True)
        _stop(process)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())


