"""Small bounded workspaces: normalized JSON only, beneath a private temporary root."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
from pathlib import Path

from .models import Report, Snapshot
from .parsing import ReportError, parse_report

SAMPLE_DIR = Path(__file__).parent / "data"
SAMPLES = {name: SAMPLE_DIR / f"{name}.json" for name in ("baseline", "previous", "current")}


class StorageFull(ReportError):
    """The intentionally small local workspace has reached its limit."""


class ReportStore:
    def __init__(self, *, ttl: int = 14_400, max_workspaces: int = 64, max_reports: int = 20):
        self._temporary = tempfile.TemporaryDirectory(prefix="cloud-posture-")
        self.root = Path(self._temporary.name)
        self.root.chmod(0o700)
        self.ttl = ttl
        self.max_workspaces = max_workspaces
        self.max_reports = max_reports
        self._lock = threading.RLock()

    def close(self) -> None:
        self._temporary.cleanup()

    def _folder(self, workspace: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", workspace):
            raise ReportError("Invalid workspace identifier.")
        return self.root / workspace

    def _cleanup(self) -> None:
        threshold = time.time() - self.ttl
        for folder in self.root.iterdir():
            if folder.is_dir() and folder.stat().st_mtime < threshold:
                shutil.rmtree(folder)

    def ensure(self, workspace: str, *, seed: bool = True) -> None:
        with self._lock:
            self._cleanup()
            folder = self._folder(workspace)
            if not folder.exists():
                if sum(1 for p in self.root.iterdir() if p.is_dir()) >= self.max_workspaces:
                    raise StorageFull(
                        "Temporary workspace limit reached. Try again after a workspace expires."
                    )
                folder.mkdir(mode=0o700)
                if seed:
                    for path in SAMPLES.values():
                        self.add(workspace, parse_report(path.read_bytes()))
            os.utime(folder)

    def list(self, workspace: str) -> list[Snapshot]:
        with self._lock:
            folder = self._folder(workspace)
            if not folder.exists():
                return []
            snapshots = [
                Snapshot(path.stem, parse_report(path.read_bytes()))
                for path in folder.glob("*.json")
            ]
            return sorted(
                snapshots,
                key=lambda s: (s.report.generated_at, s.report.report_id, s.key),
                reverse=True,
            )

    def get(self, workspace: str, key: str) -> Snapshot | None:
        if not re.fullmatch(r"[a-f0-9]{64}", key):
            return None
        with self._lock:
            path = self._folder(workspace) / f"{key}.json"
            if not path.is_file():
                return None
            return Snapshot(key, parse_report(path.read_bytes()))

    def add(self, workspace: str, report: Report) -> tuple[str, bool]:
        blob = json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=True).encode()
        if len(blob) > 1_048_576:
            raise ReportError("Normalized report exceeds the 1 MiB storage limit.")
        key = hashlib.sha256(blob).hexdigest()
        with self._lock:
            folder = self._folder(workspace)
            folder.mkdir(mode=0o700, exist_ok=True)
            path = folder / f"{key}.json"
            if path.exists():
                return key, False
            existing = self.list(workspace)
            if any(
                s.report.report_id == report.report_id
                and s.report.generated_at == report.generated_at
                for s in existing
            ):
                raise ReportError(
                    "That report id and timestamp already exist with different contents."
                )
            if len(existing) >= self.max_reports:
                raise StorageFull(
                    "This workspace holds at most 20 reports. Reset it to start again."
                )
            # Only server-generated hashes form filenames; upload filenames are never used.
            pending: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=folder, prefix=".pending-", delete=False
                ) as handle:
                    pending = Path(handle.name)
                    handle.write(blob)
                pending.replace(path)
            except OSError as exc:
                raise StorageFull(
                    "Temporary storage is unavailable. Reset or restart the local app."
                ) from exc
            finally:
                if pending is not None:
                    pending.unlink(missing_ok=True)
            return key, True

    def reset(self, workspace: str) -> None:
        with self._lock:
            shutil.rmtree(self._folder(workspace), ignore_errors=True)
