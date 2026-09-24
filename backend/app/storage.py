"""File-backed, crash-safe persistence for upload sessions.

Each session lives in a single directory holding:
  meta.json        – immutable metadata, written atomically with fsync
  chunks/NNNN      – one file per confirmed chunk (raw bytes), atomically renamed
  receipt.json     – present only after a successful atomic seal
  chunk_index.json – per-chunk trusted digests, written at seal time for new
                     sessions; old (sealed) sessions get it built on their
                     first successful audit / repair
  repair/          – only while a block repair is in progress:
    state.json     – resumable repair plan (bad / repaired chunk indices)
    restore.tmp    – fsynced copy of the validated original file

A process-wide threading.RLock serializes writers within one server
process; atomic rename + fsync make the on-disk state crash-consistent,
so progress, receipts and half-finished repairs survive service restarts.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
from dataclasses import dataclass
from typing import Optional

CHUNK_SIZE = 65536

# Default limits; can be overridden through the environment.
MIN_SESSION_LEN = 1
MAX_SESSION_LEN = 32
MIN_TOTAL_SIZE = 1
MAX_TOTAL_SIZE = 8 * 1024 * 1024

_DIGEST_PREFIX = "sha256:"
_INDEX_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_sha256_hex(value: str) -> bool:
    return bool(_SHA256_RE.match(value))


@dataclass
class Metadata:
    total_size: int
    sha256: str
    chunk_count: int


def _validate_session(session: str) -> str:
    if not MIN_SESSION_LEN <= len(session) <= MAX_SESSION_LEN:
        raise RejectError("session id must be 1-32 characters long")
    if not session.isascii() or not session.isalnum():
        raise RejectError("session id must contain only ASCII letters and digits")
    return session


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: str, data: bytes) -> None:
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _fsync_dir(directory)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _read_json(path: str) -> dict:
    with open(path, "rb") as fh:
        return json.loads(fh.read())


def _ranges(members: set[int], chunk_count: int) -> list[list[int]]:
    """Compress a set of chunk indices into closed [start, end] ranges."""
    ranges: list[list[int]] = []
    start: Optional[int] = None
    prev: Optional[int] = None
    for i in range(chunk_count):
        if i in members:
            if start is None:
                start = prev = i
            elif i == prev + 1:
                prev = i
            else:
                ranges.append([start, prev])
                start = prev = i
    if start is not None:
        ranges.append([start, prev])
    return ranges


def _missing_ranges(present: set[int], chunk_count: int) -> list[list[int]]:
    return _ranges(set(range(chunk_count)) - present, chunk_count)


def _utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


class ConflictError(Exception):
    """Content/metadata of an idempotent retransmission does not match."""


class RejectError(Exception):
    """Chunk index/offset/length is malformed (mapped to HTTP 400)."""


class UploadStore:
    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self._lock = threading.RLock()
        # Test hook: cap how many bad blocks a single repair call replaces;
        # production callers leave this None (repair converges in one call).
        # A paused repair persists its plan and resumes on the next request
        # or after a restart.
        self.repair_block_limit: Optional[int] = None

    # ---- paths -----------------------------------------------------------

    def _dir(self, session: str) -> str:
        return os.path.join(self.root, session)

    def _meta_path(self, session: str) -> str:
        return os.path.join(self._dir(session), "meta.json")

    def _chunks_dir(self, session: str) -> str:
        return os.path.join(self._dir(session), "chunks")

    def _chunk_path(self, session: str, index: int) -> str:
        return os.path.join(self._chunks_dir(session), f"{index:08d}")

    def _receipt_path(self, session: str) -> str:
        return os.path.join(self._dir(session), "receipt.json")

    def _index_path(self, session: str) -> str:
        return os.path.join(self._dir(session), "chunk_index.json")

    def _repair_dir(self, session: str) -> str:
        return os.path.join(self._dir(session), "repair")

    def _repair_state_path(self, session: str) -> str:
        return os.path.join(self._repair_dir(session), "state.json")

    def _restore_path(self, session: str) -> str:
        return os.path.join(self._repair_dir(session), "restore.tmp")

    # ---- reads -----------------------------------------------------------

    def get_metadata(self, session: str) -> Optional[Metadata]:
        try:
            raw = _read_json(self._meta_path(session))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        return Metadata(
            total_size=int(raw["total_size"]),
            sha256=str(raw["sha256"]),
            chunk_count=int(raw["chunk_count"]),
        )

    def _present_indices(self, session: str, chunk_count: int) -> set[int]:
        present: set[int] = set()
        try:
            names = os.listdir(self._chunks_dir(session))
        except FileNotFoundError:
            return present
        for name in names:
            if len(name) == 8 and name.isdigit():
                idx = int(name)
                if 0 <= idx < chunk_count:
                    present.add(idx)
        return present

    def _read_receipt(self, session: str) -> Optional[dict]:
        try:
            raw = _read_json(self._receipt_path(session))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        return raw

    def _receipt_meta(self, receipt: dict) -> Optional[Metadata]:
        """Pinned metadata anchored on the sealed receipt.

        For a sealed session the receipt is the single root of trust: any
        other persisted description (meta.json, a hand-written repair plan,
        ...) contradicting it is silent corruption and is ignored, so a
        wrong file can never become a credential for rewriting sealed
        blocks. Returns None when the receipt itself is internally
        inconsistent, in which case it can anchor no verification.
        """
        try:
            total_size = int(receipt["total_size"])
            sha256 = str(receipt["sha256"])
            chunks = int(receipt["chunks"])
            chunk_size = int(receipt.get("chunk_size", CHUNK_SIZE))
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
        if not _is_sha256_hex(sha256):
            return None
        if chunk_size != CHUNK_SIZE:
            return None
        if not MIN_TOTAL_SIZE <= total_size <= MAX_TOTAL_SIZE:
            return None
        if chunks != (total_size + CHUNK_SIZE - 1) // CHUNK_SIZE:
            return None
        if str(receipt.get("receipt_id")) != _DIGEST_PREFIX + sha256:
            return None
        return Metadata(total_size=total_size, sha256=sha256, chunk_count=chunks)

    def _read_index(self, session: str, meta: Metadata) -> Optional[list[dict]]:
        """Trusted per-chunk digests, or None when absent/unusable.

        An index is trusted only when it matches the pinned metadata; any
        malformed or stale index is ignored, in which case audit falls back
        to the old-session procedure (block lengths + whole-file digest) and
        rebuilds it after a successful verification.
        """
        try:
            raw = _read_json(self._index_path(session))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
        try:
            if int(raw.get("version")) != _INDEX_VERSION:
                return None
            if int(raw["total_size"]) != meta.total_size:
                return None
            if str(raw["sha256"]) != meta.sha256:
                return None
            entries = raw["chunks"]
            if not isinstance(entries, list) or len(entries) != meta.chunk_count:
                return None
            digests: list[dict] = []
            for pos, entry in enumerate(entries):
                if int(entry["i"]) != pos:
                    return None
                size = int(entry["size"])
                digest = str(entry["sha256"])
                if size != self._expected_chunk_size(meta, pos * CHUNK_SIZE):
                    return None
                if not _is_sha256_hex(digest):
                    return None
                digests.append({"i": pos, "size": size, "sha256": digest})
        except (KeyError, TypeError, ValueError):
            return None
        return digests

    def _read_repair_state(
        self, session: str, meta: Metadata
    ) -> Optional[dict]:
        """Persisted repair plan, or None. A plan not matching the pinned
        metadata is stale (left over from an incompatible older state) and is
        discarded by the caller."""
        try:
            raw = _read_json(self._repair_state_path(session))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
        try:
            state = {
                "total_size": int(raw["total_size"]),
                "sha256": str(raw["sha256"]),
                "bad": sorted(int(i) for i in raw["bad"]),
                "repaired": sorted(int(i) for i in raw.get("repaired", [])),
                "missing": sorted(int(i) for i in raw.get("missing", [])),
                "bad_length": sorted(int(i) for i in raw.get("bad_length", [])),
                "digest_mismatch": sorted(
                    int(i) for i in raw.get("digest_mismatch", [])
                ),
            }
        except (KeyError, TypeError, ValueError):
            return None
        if state["total_size"] != meta.total_size or state["sha256"] != meta.sha256:
            return None
        if not set(state["repaired"]) <= set(state["bad"]):
            return None
        return state

    def status(self, session: str) -> Optional[dict]:
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                return None
            receipt = self._read_receipt(session)
            if receipt is not None:
                # A sealed session is described by its receipt; a silently
                # corrupted meta.json must not leak into the reported state.
                anchored = self._receipt_meta(receipt)
                if anchored is not None:
                    meta = anchored
            present = sorted(self._present_indices(session, meta.chunk_count))
            return {
                "session": session,
                "total_size": meta.total_size,
                "sha256": meta.sha256,
                "chunk_count": meta.chunk_count,
                "confirmed_chunks": present,
                "missing_ranges": _missing_ranges(set(present), meta.chunk_count),
                "sealed": receipt is not None,
                "receipt": receipt,
                "index_present": self._read_index(session, meta) is not None,
                "repair_active": self._read_repair_state(session, meta) is not None,
            }

    # ---- chunk upload (never allowed to rewrite sealed data) -------------

    def put_chunk(
        self,
        session: str,
        offset: int,
        data: bytes,
        total_size: Optional[int],
        sha256: Optional[str],
    ) -> dict:
        _validate_session(session)
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise RejectError("offset must be an integer")
        if offset < 0:
            raise RejectError("offset must be >= 0")
        if not isinstance(data, (bytes, bytearray)):
            raise RejectError("chunk payload must be raw bytes")
        data = bytes(data)

        with self._lock:
            existing = self.get_metadata(session)
            receipt = self._read_receipt(session)
            if existing is None:
                # Build + validate in memory first; nothing touches disk until
                # every shape check has passed.
                meta = self._build_metadata(total_size, sha256)
            else:
                meta = existing
                if receipt is not None:
                    # Once sealed, the receipt pins the metadata: a silently
                    # corrupted meta.json cannot redefine what counts as an
                    # identical retransmission.
                    anchored = self._receipt_meta(receipt)
                    if anchored is not None:
                        meta = anchored
                if total_size is not None and total_size != meta.total_size:
                    raise ConflictError(
                        f"total_size mismatch: session pinned to {meta.total_size}"
                    )
                if sha256 is not None and sha256 != meta.sha256:
                    raise ConflictError("sha256 mismatch: session digest is pinned")

            if offset % CHUNK_SIZE != 0:
                raise RejectError(f"offset {offset} is not aligned to {CHUNK_SIZE}")
            if offset >= meta.total_size:
                raise RejectError(
                    f"offset {offset} is beyond total_size {meta.total_size}"
                )
            expected_size = self._expected_chunk_size(meta, offset)
            if len(data) != expected_size:
                raise RejectError(
                    f"chunk length {len(data)} at offset {offset} must be {expected_size}"
                )
            index = offset // CHUNK_SIZE

            # All checks passed: pin the metadata on the first valid chunk.
            if existing is None:
                os.makedirs(self._chunks_dir(session), exist_ok=True)
                _atomic_write(
                    self._meta_path(session),
                    json.dumps(
                        {
                            "total_size": meta.total_size,
                            "sha256": meta.sha256,
                            "chunk_count": meta.chunk_count,
                        },
                        indent=2,
                    ).encode(),
                )

            sealed = receipt is not None
            path = self._chunk_path(session, index)
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    stored = fh.read()
                if stored != data:
                    raise ConflictError(
                        f"chunk at offset {offset} already confirmed with different bytes"
                    )
                duplicate = True
            else:
                if sealed:
                    raise ConflictError("session is already sealed; no new chunks accepted")
                _atomic_write(path, data)
                duplicate = False

            present = self._present_indices(session, meta.chunk_count)
            return {
                "session": session,
                "offset": offset,
                "index": index,
                "size": len(data),
                "duplicate": duplicate,
                "confirmed_chunks": sorted(present),
                "chunk_count": meta.chunk_count,
                "missing_ranges": _missing_ranges(present, meta.chunk_count),
                "sealed": sealed,
            }

    def _build_metadata(
        self, total_size: Optional[int], sha256: Optional[str]
    ) -> Metadata:
        if total_size is None or sha256 is None:
            raise RejectError(
                "total_size and sha256 are required for the first chunk of a session"
            )
        if not isinstance(total_size, int) or isinstance(total_size, bool):
            raise RejectError("total_size must be an integer")
        if not MIN_TOTAL_SIZE <= total_size <= MAX_TOTAL_SIZE:
            raise RejectError(
                f"total_size must be between {MIN_TOTAL_SIZE} and {MAX_TOTAL_SIZE} bytes"
            )
        if not isinstance(sha256, str) or not _is_sha256_hex(sha256):
            raise RejectError("sha256 must be 64 lowercase hex characters")

        chunk_count = (total_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        return Metadata(
            total_size=total_size, sha256=sha256, chunk_count=chunk_count
        )

    @staticmethod
    def _expected_chunk_size(meta: Metadata, offset: int) -> int:
        remaining = meta.total_size - offset
        if remaining <= 0:
            return 0
        return min(CHUNK_SIZE, remaining)

    def seal(self, session: str) -> tuple[dict, bool, Optional[list[list[int]]]]:
        """Return (receipt_or_status, ok, missing_ranges).

        ok=True  -> receipt dict (possibly an identical prior receipt)
        ok=False -> digest mismatch; missing_ranges is None
        missing -> blocks missing; receipt is None and missing_ranges set
        """
        _validate_session(session)
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                raise RejectError("unknown session; upload at least one chunk first")

            prior = self._read_receipt(session)
            if prior is not None:
                return prior, True, None

            present = self._present_indices(session, meta.chunk_count)
            missing = _missing_ranges(present, meta.chunk_count)
            if missing:
                return {}, False, missing

            entries = []
            digest = hashlib.sha256()
            for i in range(meta.chunk_count):
                with open(self._chunk_path(session, i), "rb") as fh:
                    block = fh.read()
                entries.append(
                    {"i": i, "size": len(block), "sha256": hashlib.sha256(block).hexdigest()}
                )
                digest.update(block)
            actual = digest.hexdigest()
            if actual != meta.sha256:
                raise ConflictError(
                    f"server digest {actual} does not match declared {meta.sha256}"
                )

            # Persist the per-chunk trusted index BEFORE the receipt appears,
            # so a newly sealed session can always be audited block by block.
            self._write_index(session, meta, entries)

            receipt = {
                "receipt_id": _DIGEST_PREFIX + actual,
                "session": session,
                "total_size": meta.total_size,
                "sha256": actual,
                "chunks": meta.chunk_count,
                "chunk_size": CHUNK_SIZE,
                "sealed_at": _utc_now(),
            }
            seal_marker = json.dumps(receipt, indent=2).encode()
            # Write the receipt atomically; from this instant the session is sealed.
            _atomic_write(self._receipt_path(session), seal_marker)
            return receipt, True, None

    # ---- integrity index -------------------------------------------------

    def _write_index(
        self, session: str, meta: Metadata, entries: list[dict]
    ) -> None:
        payload = {
            "version": _INDEX_VERSION,
            "total_size": meta.total_size,
            "sha256": meta.sha256,
            "chunk_size": CHUNK_SIZE,
            "chunks": entries,
            "created_at": _utc_now(),
        }
        _atomic_write(self._index_path(session), json.dumps(payload, indent=2).encode())

    def _index_entries_from_chunks(
        self, session: str, meta: Metadata
    ) -> Optional[list[dict]]:
        """Per-chunk digests computed from stored bytes.

        Returns None if any block is missing or has the wrong length, in which
        case the index must not be (re)built.
        """
        entries: list[dict] = []
        for i in range(meta.chunk_count):
            expected = self._expected_chunk_size(meta, i * CHUNK_SIZE)
            try:
                with open(self._chunk_path(session, i), "rb") as fh:
                    block = fh.read()
            except (FileNotFoundError, OSError):
                return None
            if len(block) != expected:
                return None
            entries.append(
                {"i": i, "size": len(block), "sha256": hashlib.sha256(block).hexdigest()}
            )
        return entries

    def _whole_file_digest(self, session: str, meta: Metadata) -> Optional[str]:
        """Whole-file digest across chunk order; None if a block is unreadable."""
        digest = hashlib.sha256()
        for i in range(meta.chunk_count):
            try:
                with open(self._chunk_path(session, i), "rb") as fh:
                    digest.update(fh.read())
            except (FileNotFoundError, OSError):
                return None
        return digest.hexdigest()

    def _scan(self, session: str, meta: Metadata, index: Optional[list[dict]]) -> dict:
        """Classify every chunk. The three anomaly categories never overlap."""
        missing: set[int] = set()
        bad_length: set[int] = set()
        digest_mismatch: set[int] = set()
        whole = hashlib.sha256()
        for i in range(meta.chunk_count):
            expected_len = self._expected_chunk_size(meta, i * CHUNK_SIZE)
            try:
                with open(self._chunk_path(session, i), "rb") as fh:
                    block = fh.read()
            except (FileNotFoundError, OSError):
                # Unreadable bytes cannot be length- or digest-checked:
                # the block is reported as missing.
                missing.add(i)
                continue
            if len(block) != expected_len:
                bad_length.add(i)
                continue
            if index is not None:
                if hashlib.sha256(block).hexdigest() != index[i]["sha256"]:
                    digest_mismatch.add(i)
            else:
                # Old session without a trusted per-chunk index: the first
                # audit verifies block lengths and the whole-file digest.
                whole.update(block)
        return {
            "missing": missing,
            "bad_length": bad_length,
            "digest_mismatch": digest_mismatch,
            "whole_digest": whole.hexdigest() if index is None else None,
        }

    def _audit_response(
        self,
        session: str,
        meta: Metadata,
        receipt: dict,
        status: str,
        *,
        index_present: bool,
        index_built: bool,
        missing: set[int],
        bad_length: set[int],
        digest_mismatch: set[int],
        mismatch_located: bool,
        unlocated_mismatch: bool = False,
        remaining: Optional[set[int]] = None,
        repaired: Optional[set[int]] = None,
        already_healthy: bool = False,
    ) -> dict:
        bad = missing | bad_length | digest_mismatch
        remaining = remaining or set()
        repaired = repaired or set()
        recovered_ranges = _ranges(repaired, meta.chunk_count)
        return {
            "session": session,
            "status": status,
            "sealed": True,
            "chunk_count": meta.chunk_count,
            "index_present": index_present,
            "index_built": index_built,
            "missing_ranges": _ranges(missing, meta.chunk_count),
            "length_anomaly_ranges": _ranges(bad_length, meta.chunk_count),
            "digest_mismatch_ranges": _ranges(digest_mismatch, meta.chunk_count),
            "digest_mismatch_located": mismatch_located,
            "unlocated_digest_mismatch": unlocated_mismatch,
            "bad_ranges": _ranges(bad, meta.chunk_count),
            "remaining_ranges": _ranges(remaining, meta.chunk_count),
            # Blocks restored so far (during REPAIRING) or in total (on the
            # HEALTHY completion call); the two names are intentionally the
            # same value for client convenience.
            "recovered_ranges": recovered_ranges,
            "repaired_ranges": recovered_ranges,
            "already_healthy": already_healthy,
            "receipt": receipt,
        }

    # ---- audit -----------------------------------------------------------

    def audit(self, session: str) -> dict:
        _validate_session(session)
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                raise RejectError("unknown session; upload at least one chunk first")
            receipt = self._read_receipt(session)
            if receipt is None:
                # Unsealed sessions are refused; auditing must never touch
                # upload progress.
                raise ConflictError(
                    "session is not sealed; integrity audit is sealed-only"
                )

            # The sealed receipt is the root of trust for every check below.
            # A meta.json (or any other persisted description) contradicting
            # it is silent corruption and is ignored, so content that
            # disagrees with the receipt can never audit HEALTHY. A receipt
            # that is itself internally inconsistent anchors nothing.
            anchored = self._receipt_meta(receipt)
            if anchored is None:
                return self._audit_response(
                    session,
                    meta,
                    receipt,
                    "DEGRADED",
                    index_present=False,
                    index_built=False,
                    missing=set(),
                    bad_length=set(),
                    digest_mismatch=set(),
                    mismatch_located=False,
                    unlocated_mismatch=True,
                )
            meta = anchored

            index = self._read_index(session, meta)

            state = self._read_repair_state(session, meta)
            if state is None and os.path.isdir(self._repair_dir(session)):
                # Corrupt/stale repair directory without a usable plan.
                shutil.rmtree(self._repair_dir(session), ignore_errors=True)
            if state is not None and self._try_complete_repair(
                session, meta, receipt, state
            ):
                # A previous run had already replaced every block but crashed
                # before cleanup: finish convergence now.
                state = None
                index = self._read_index(session, meta)
            if state is not None:
                # Compute the TRUE remaining blocks against the persisted,
                # receipt-verified original (restore.tmp) rather than trusting
                # the plan's snapshot, so audit stays read-only yet accurate
                # even if a block rots while a repair is paused.
                categories: Optional[dict] = None
                try:
                    with open(self._restore_path(session), "rb") as fh:
                        original = fh.read()
                    if (
                        len(original) == meta.total_size
                        and hashlib.sha256(original).hexdigest() == meta.sha256
                    ):
                        categories, _ = self._plan_repair(session, meta, original)
                except (FileNotFoundError, OSError):
                    categories = None
                if categories is None:
                    categories = {
                        "missing": set(state["missing"]),
                        "bad_length": set(state["bad_length"]),
                        "digest_mismatch": set(state["digest_mismatch"]),
                    }
                remaining = (
                    categories["missing"]
                    | categories["bad_length"]
                    | categories["digest_mismatch"]
                )
                repaired = set(state["repaired"]) - remaining
                return self._audit_response(
                    session,
                    meta,
                    receipt,
                    "REPAIRING",
                    index_present=index is not None,
                    index_built=False,
                    missing=categories["missing"],
                    bad_length=categories["bad_length"],
                    digest_mismatch=categories["digest_mismatch"],
                    # The repair plan was derived from the validated original,
                    # so every remaining block is precisely located.
                    mismatch_located=True,
                    remaining=remaining,
                    repaired=repaired,
                )

            scan = self._scan(session, meta, index)
            missing = scan["missing"]
            bad_length = scan["bad_length"]
            mismatch = scan["digest_mismatch"]
            unlocated = False

            if not (missing or bad_length or mismatch):
                whole_digest = self._whole_file_digest(session, meta)
                if whole_digest != meta.sha256:
                    if index is not None:
                        # Every block matched its trusted digest yet the
                        # whole-file digest fails: the stored index itself is
                        # untrustworthy/inconsistent and cannot locate anything.
                        index = None
                    unlocated = True
                elif index is None:
                    # Old session, first audit, lengths all correct and the
                    # whole-file digest matches: promote it with a trusted
                    # per-chunk index.
                    entries = self._index_entries_from_chunks(session, meta)
                    if entries is not None:
                        self._write_index(session, meta, entries)
                        index = entries
                        return self._audit_response(
                            session,
                            meta,
                            receipt,
                            "HEALTHY",
                            index_present=True,
                            index_built=True,
                            missing=set(),
                            bad_length=set(),
                            digest_mismatch=set(),
                            mismatch_located=True,
                        )

            if unlocated:
                status = "DEGRADED"
                return self._audit_response(
                    session,
                    meta,
                    receipt,
                    status,
                    index_present=False,
                    index_built=False,
                    missing=missing,
                    bad_length=bad_length,
                    digest_mismatch=set(),
                    mismatch_located=False,
                    unlocated_mismatch=True,
                )

            status = "HEALTHY" if not (missing or bad_length or mismatch) else "DEGRADED"
            return self._audit_response(
                session,
                meta,
                receipt,
                status,
                index_present=index is not None,
                index_built=False,
                missing=missing,
                bad_length=bad_length,
                digest_mismatch=mismatch,
                mismatch_located=True,
            )

    # ---- repair ----------------------------------------------------------

    def repair(self, session: str, data: bytes) -> dict:
        _validate_session(session)
        if not isinstance(data, (bytes, bytearray)):
            raise RejectError("repair payload must be raw bytes")
        data = bytes(data)

        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                raise RejectError("unknown session; upload at least one chunk first")
            receipt = self._read_receipt(session)
            if receipt is None:
                raise ConflictError("session is not sealed; repair is sealed-only")
            # The receipt, not meta.json, decides which file is the original:
            # a silently rewritten session description must never turn a
            # wrong file into a credential for rewriting sealed blocks. All
            # validation happens before anything is written, so a refused
            # file leaves every byte and every state file untouched.
            anchored = self._receipt_meta(receipt)
            if anchored is None:
                raise ConflictError(
                    "sealed receipt is internally inconsistent; repair is refused"
                )
            meta = anchored
            receipt_before = json.dumps(receipt, sort_keys=True)

            # The uploaded file is accepted only when it IS the receipted
            # original: exact length and exact whole-file digest. A wrong file
            # gets a stable 400 and never touches any block or repair state.
            if len(data) != meta.total_size:
                raise RejectError(
                    f"repair file length {len(data)} does not match receipt "
                    f"total_size {meta.total_size}"
                )
            if hashlib.sha256(data).hexdigest() != meta.sha256:
                raise RejectError(
                    "repair file sha256 does not match the sealed receipt digest"
                )

            # The per-chunk index is reported for context, but repair planning
            # always compares stored bytes with the validated original below:
            # the receipt digest (checked above) is the root of trust, so a
            # tampered or stale index can never hide a corrupt block.
            index = self._read_index(session, meta)

            state = self._read_repair_state(session, meta)
            if state is None and os.path.isdir(self._repair_dir(session)):
                shutil.rmtree(self._repair_dir(session), ignore_errors=True)
            if state is not None and self._try_complete_repair(
                session, meta, receipt, state
            ):
                # Crash happened after the final block but before cleanup:
                # the validated file is a repeat repair -> report HEALTHY.
                state = None
                index = self._read_index(session, meta)
                receipt = self._read_receipt(session) or receipt

            # Recompute the plan from the validated original on EVERY call.
            # Categories are a snapshot for reporting; membership is refreshed
            # after each replacement, which also picks up fresh bit rot in a
            # block an earlier plan considered fine and makes resume converge
            # unconditionally.
            categories, bad = self._plan_repair(session, meta, data)

            if state is None:
                if not bad:
                    # Nothing wrong with the blocks: a repeated repair is an
                    # idempotent no-op for chunk data, but still reconciles a
                    # missing or forged index against the receipted bytes.
                    index_built = self._reconcile_index(session, meta, index)
                    shutil.rmtree(self._repair_dir(session), ignore_errors=True)
                    return self._audit_response(
                        session,
                        meta,
                        receipt,
                        "HEALTHY",
                        index_present=True,
                        index_built=index_built,
                        missing=set(),
                        bad_length=set(),
                        digest_mismatch=set(),
                        mismatch_located=True,
                        already_healthy=True,
                    )
                os.makedirs(self._repair_dir(session), exist_ok=True)
                # Persist the validated original BEFORE the plan, so after a
                # crash both the target bytes and the to-do list are on disk.
                _atomic_write(self._restore_path(session), data)
                state = {
                    "total_size": meta.total_size,
                    "sha256": meta.sha256,
                    "bad": sorted(bad),
                    "repaired": [],
                    "missing": sorted(categories["missing"]),
                    "bad_length": sorted(categories["bad_length"]),
                    "digest_mismatch": sorted(categories["digest_mismatch"]),
                }
                self._write_repair_state(session, state)
            else:
                # Refresh the fsynced restore copy from this request.
                os.makedirs(self._repair_dir(session), exist_ok=True)
                _atomic_write(self._restore_path(session), data)
                # Merge any newly discovered bad blocks into the persisted plan.
                if not bad <= set(state["bad"]):
                    merged_bad = set(state["bad"]) | bad
                    state["bad"] = sorted(merged_bad)
                    bad = merged_bad
                    for key in ("missing", "bad_length", "digest_mismatch"):
                        state[key] = sorted(set(state[key]) | categories[key])

            replaced_this_call = 0
            # The fresh plan drives the work: even a block an earlier call had
            # marked "repaired" is replaced again if it is bad once more.
            for i in sorted(bad):
                offset = i * CHUNK_SIZE
                expected = data[offset : offset + self._expected_chunk_size(meta, offset)]
                try:
                    with open(self._chunk_path(session, i), "rb") as fh:
                        current = fh.read()
                except (FileNotFoundError, OSError):
                    current = None
                if current != expected:
                    _atomic_write(self._chunk_path(session, i), expected)
                    replaced_this_call += 1
                state["repaired"] = sorted(set(state["repaired"]) | {i})
                # Progress is persisted after EVERY block, so an interruption
                # at any point resumes instead of restarting.
                self._write_repair_state(session, state)
                # Test-only limit pauses the request; whether paused or not,
                # convergence below is decided by re-scanning the blocks.
                if (
                    self.repair_block_limit is not None
                    and replaced_this_call >= self.repair_block_limit
                ):
                    break

            # Re-scan against the validated original. Any block still bad
            # (including one that rotted again after an earlier replacement)
            # remains in the persisted plan, so the next call always makes
            # progress and eventually converges.
            categories_now, bad_now = self._plan_repair(session, meta, data)

            if bad_now:
                state["bad"] = sorted(set(state["bad"]) | bad_now)
                self._write_repair_state(session, state)
                recovered = set(state["bad"]) - bad_now
                return self._audit_response(
                    session,
                    meta,
                    receipt,
                    "REPAIRING",
                    index_present=index is not None,
                    index_built=False,
                    missing=categories_now["missing"],
                    bad_length=categories_now["bad_length"],
                    digest_mismatch=categories_now["digest_mismatch"],
                    # The repair plan is derived from the validated original,
                    # so every remaining block is precisely located.
                    mismatch_located=True,
                    remaining=bad_now,
                    repaired=recovered,
                )

            # All blocks match the validated original. Nothing is committed
            if self._whole_file_digest(session, meta) != meta.sha256:
                raise ConflictError(
                    "repair did not converge: whole-file digest still mismatched"
                )

            # Reconcile the per-chunk index with the restored bytes. This both
            # builds it for old sessions (index was absent) and repairs a
            # forged/stale index: the receipted digest, not the old index, is
            # the root of trust.
            entries = self._index_entries_from_chunks(session, meta)
            if entries is None:
                raise ConflictError("repair did not converge: index build failed")
            index_built = index is None or entries != index
            self._write_index(session, meta, entries)

            # The receipt (including sealed_at) must be byte-stable throughout.
            after = self._read_receipt(session)
            if after is None or json.dumps(after, sort_keys=True) != receipt_before:
                raise ConflictError("internal error: receipt changed during repair")

            shutil.rmtree(self._repair_dir(session), ignore_errors=True)
            return self._audit_response(
                session,
                meta,
                after,
                "HEALTHY",
                index_present=True,
                index_built=index_built,
                # The repaired blocks are reported as recovered on this call.
                missing=set(),
                bad_length=set(),
                digest_mismatch=set(),
                mismatch_located=True,
                repaired=set(state["bad"]),
            )

    def _reconcile_index(
        self, session: str, meta: Metadata, index: Optional[list[dict]]
    ) -> bool:
        """Make the on-disk index match the stored, receipt-verified bytes.

        Builds it for old sessions and repairs a forged/stale index. Returns
        True when the index file was created or changed.
        """
        entries = self._index_entries_from_chunks(session, meta)
        if entries is None:
            return False
        if index is not None and entries == index:
            return False
        self._write_index(session, meta, entries)
        return True

    def _plan_repair(
        self, session: str, meta: Metadata, data: bytes
    ) -> tuple[dict, set[int]]:
        """Locate blocks that differ from the validated original.

        Because ``data`` has already been proved to match the receipted digest,
        comparing each stored block with it locates every anomaly precisely —
        missing block, wrong length or differing bytes — without relying on
        the (possibly absent or stale) per-chunk index.
        """
        missing: set[int] = set()
        bad_length: set[int] = set()
        digest_mismatch: set[int] = set()
        for i in range(meta.chunk_count):
            offset = i * CHUNK_SIZE
            expected = data[offset : offset + self._expected_chunk_size(meta, offset)]
            try:
                with open(self._chunk_path(session, i), "rb") as fh:
                    current = fh.read()
            except (FileNotFoundError, OSError):
                missing.add(i)
                continue
            if len(current) != len(expected):
                bad_length.add(i)
            elif current != expected:
                digest_mismatch.add(i)
        categories = {
            "missing": missing,
            "bad_length": bad_length,
            "digest_mismatch": digest_mismatch,
        }
        return categories, missing | bad_length | digest_mismatch

    def _try_complete_repair(
        self,
        session: str,
        meta: Metadata,
        receipt: dict,
        state: dict,
    ) -> bool:
        """Finalize an interrupted repair whose plan is fully done.

        Triggered on audit/repair when a state file is found (e.g. after a
        restart right after the final block replacement): verifies the whole
        file against the receipt, builds the trusted index for old sessions
        and clears the repair directory. Returns False when verification
        fails, meaning real work remains.
        """
        if set(state["bad"]) - set(state["repaired"]):
            return False
        if self._whole_file_digest(session, meta) != meta.sha256:
            return False
        entries = self._index_entries_from_chunks(session, meta)
        if entries is None:
            return False
        # Build the index for old sessions or reconcile a forged/stale one
        # with the receipt-verified restored bytes.
        current = self._read_index(session, meta)
        if current != entries:
            self._write_index(session, meta, entries)
        after = self._read_receipt(session)
        if after is None or after.get("sealed_at") != receipt.get("sealed_at"):
            return False
        shutil.rmtree(self._repair_dir(session), ignore_errors=True)
        return True

    def _write_repair_state(self, session: str, state: dict) -> None:
        payload = dict(state)
        payload["updated_at"] = _utc_now()
        _atomic_write(
            self._repair_state_path(session), json.dumps(payload, indent=2).encode()
        )
