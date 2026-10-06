"""Append-only, hash-chained audit log.

Every entry links to the previous entry's hash, so tampering is detectable
via :meth:`AuditLog.verify_chain`.

Two integrity modes:
  * Unkeyed (``key=None``): plain ``sha256(prev_hash + canonical(payload))``.
    Tamper-evident against accidental corruption and attackers who cannot
    recompute hashes — NOT against an attacker who reads this source and
    rewrites the chain. Use only where the log file itself is access-controlled.
  * Keyed (``key=<bytes>``): ``HMAC-SHA256(key, prev_hash + canonical(payload))``.
    Forging entries requires the key. The key must live outside the log file
    (operator-managed, e.g. environment variable). Verification requires the
    same key.

Truncation: deleting trailing lines leaves a valid-looking shorter chain.
To detect it, file mode maintains an atomic checkpoint sidecar
(``<path>.checkpoint``) holding the latest ``(seq, hash)``. ``verify_chain``
fails if the log tip does not match the checkpoint. Protect the checkpoint
as you protect the log; for high-assurance deployments, anchor the tip hash
externally (see :meth:`AuditLog.tip`).

Concurrency: file mode serializes read-modify-append with ``fcntl.flock``
(one writer per file across processes). In-memory mode uses a threading lock.

Two modes:
  * ``AuditLog()`` — in-memory only.
  * ``AuditLog(path)`` — append-only JSONL file (created on first record).
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import threading
import time

try:
    import fcntl
except ImportError:  # Windows: no flock; document one-writer-per-file
    fcntl = None  # type: ignore[assignment]

GENESIS_PREV_HASH = "0" * 64

_RESERVED = ("ts", "seq", "prev_hash", "hash")


def canonical_json(obj) -> str:
    """Canonical JSON used for hashing: sorted keys, compact, default=str."""
    return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))


def _entry_hash(prev_hash: str, entry: dict, key: bytes | None = None) -> str:
    payload = {k: v for k, v in entry.items() if k not in ("hash", "prev_hash")}
    msg = (prev_hash + canonical_json(payload)).encode("utf-8")
    if key is not None:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


class _CorruptLog(Exception):
    """Internal: a log line is not valid JSON or not a dict."""


class AuditLog:
    def __init__(self, path: str | None = None, key: bytes | None = None) -> None:
        if key is not None and not isinstance(key, (bytes, bytearray)):
            raise TypeError("audit key must be bytes or None")
        self._path = path
        self._key = bytes(key) if key is not None else None
        self._checkpoint = path + ".checkpoint" if path is not None else None
        self._lock = threading.Lock()
        self._entries: list[dict] = []  # in-memory mode store

    # -- internals ------------------------------------------------------

    def _parse_lines(self, fh) -> list[dict]:
        entries: list[dict] = []
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise _CorruptLog(f"line {lineno}: not valid JSON") from e
            if not isinstance(obj, dict):
                raise _CorruptLog(f"line {lineno}: not a JSON object")
            entries.append(obj)
        return entries

    def _read_file(self) -> list[dict]:
        try:
            with open(self._path, "r", encoding="utf-8") as f:  # type: ignore[arg-type]
                return self._parse_lines(f)
        except FileNotFoundError:
            return []

    def _snapshot(self) -> list[dict]:
        """Fresh entries: re-reads the file when file-backed."""
        if self._path is None:
            return list(self._entries)
        return self._read_file()

    def _write_checkpoint(self, seq: int, entry_hash: str) -> None:
        blob = canonical_json({"seq": seq, "hash": entry_hash})
        tmp = self._checkpoint + ".tmp"  # type: ignore[operator]
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._checkpoint)  # type: ignore[arg-type]

    def _read_checkpoint(self) -> dict | None:
        try:
            with open(self._checkpoint, "r", encoding="utf-8") as f:  # type: ignore[arg-type]
                return json.loads(f.read())
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _build_entry(self, entry: dict, prev_hash: str, seq: int) -> dict:
        stored = dict(entry)
        for k in _RESERVED:
            stored.pop(k, None)  # caller-supplied reserved keys are overwritten
        stored["ts"] = time.time()
        stored["seq"] = seq
        stored["prev_hash"] = prev_hash
        stored["hash"] = _entry_hash(prev_hash, stored, self._key)
        return stored

    # -- public API -----------------------------------------------------

    def record(self, entry: dict) -> dict:
        """Append ``entry`` and return a detached copy of the stored entry.

        Adds ``ts``, ``seq``, ``prev_hash``, ``hash`` (reserved keys in the
        caller's dict are overwritten; the caller's dict is never mutated).
        In file mode the append and the checkpoint update happen under an
        exclusive ``flock``, so concurrent writers cannot interleave.
        """
        with self._lock:
            if self._path is None:
                entries = self._entries
                prev_hash = entries[-1]["hash"] if entries else GENESIS_PREV_HASH
                stored = self._build_entry(entry, prev_hash, len(entries))
                self._entries.append(stored)
                return copy.deepcopy(stored)
            # File mode: read-modify-append under an exclusive lock.
            with open(self._path, "a+", encoding="utf-8") as f:  # type: ignore[arg-type]
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.seek(0)
                    entries = self._parse_lines(f)
                    prev_hash = entries[-1]["hash"] if entries else GENESIS_PREV_HASH
                    stored = self._build_entry(entry, prev_hash, len(entries))
                    f.seek(0, os.SEEK_END)
                    f.write(canonical_json(stored) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                    self._write_checkpoint(stored["seq"], stored["hash"])
                finally:
                    if fcntl is not None:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            return copy.deepcopy(stored)

    def verify_chain(self) -> bool:
        """Verify the chain. False on ANY tamper: modified, deleted
        (including truncated tail, via the checkpoint), reordered, forged
        (in keyed mode), or unparseable lines.
        """
        with self._lock:
            try:
                entries = self._snapshot()
            except _CorruptLog:
                return False
            # Truncation check: the log tip must match the checkpoint.
            if self._checkpoint is not None:
                cp = self._read_checkpoint()
                if cp is not None:
                    if not entries:
                        return False
                    tip = entries[-1]
                    if tip.get("seq") != cp.get("seq") or tip.get("hash") != cp.get("hash"):
                        return False
            prev = GENESIS_PREV_HASH
            for i, entry in enumerate(entries):
                try:
                    if not isinstance(entry, dict):
                        return False
                    if entry.get("seq") != i:
                        return False
                    if entry.get("prev_hash") != prev:
                        return False
                    if entry.get("hash") != _entry_hash(prev, entry, self._key):
                        return False
                except (TypeError, ValueError):
                    return False
                prev = entry["hash"]
            return True

    def tip(self) -> tuple[int, str] | None:
        """Return (seq, hash) of the latest entry, for external anchoring."""
        with self._lock:
            try:
                entries = self._snapshot()
            except _CorruptLog:
                return None
            if not entries:
                return None
            last = entries[-1]
            return (last.get("seq"), last.get("hash"))  # type: ignore[return-value]

    def __iter__(self):
        """Yield detached copies of stored entries, oldest first."""
        with self._lock:
            try:
                entries = self._snapshot()
            except _CorruptLog:
                return iter(())
            return iter(copy.deepcopy(entries))

    def __len__(self) -> int:
        with self._lock:
            try:
                return len(self._snapshot())
            except _CorruptLog:
                return 0
