"""End-to-end tests for sealed-session integrity audit and original-file repair.

Covers:
  * new sealed sessions persist a trusted per-chunk index;
  * old sealed sessions (no index) first verify block lengths + the
    whole-file digest, then get the index built, distinguishing missing
    blocks, length anomalies and unlocated digest mismatches;
  * located digest mismatches against a trusted index;
  * repair accepts ONLY the receipted original, fixes anomalous blocks,
    keeps the receipt byte-identical, is idempotent when healthy and is
    resumable across interrupted requests and service "restarts";
  * audit/repair never touch unsealed upload progress and the chunk API
    can never rewrite sealed data.
"""

from __future__ import annotations

import hashlib
import json
import os

from app import main as web
from app.storage import CHUNK_SIZE, UploadStore


def _digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _put(client, session, offset, blob, total_size=None, sha=None):
    headers = {"X-Chunk-Offset": str(offset)}
    if total_size is not None:
        headers["X-Total-Size"] = str(total_size)
    if sha is not None:
        headers["X-Content-SHA256"] = sha
    return client.put(
        f"/api/uploads/{session}/chunks", content=blob, headers=headers
    )


def _session_dir(tmp_path, session):
    return tmp_path / "data" / session


def _chunk_file(tmp_path, session, index):
    return _session_dir(tmp_path, session) / "chunks" / f"{index:08d}"


def _index_file(tmp_path, session):
    return _session_dir(tmp_path, session) / "chunk_index.json"


def _repair_state_file(tmp_path, session):
    return _session_dir(tmp_path, session) / "repair" / "state.json"


def _make_sealed(client, tmp_path, session, blob):
    sha = _digest(blob)
    count = (len(blob) + CHUNK_SIZE - 1) // CHUNK_SIZE
    for i in range(count):
        off = i * CHUNK_SIZE
        part = blob[off : min(off + CHUNK_SIZE, len(blob))]
        r = _put(client, session, off, part, len(blob), sha)
        assert r.status_code == 200, r.text
    r = client.post(f"/api/uploads/{session}/seal")
    assert r.status_code == 200, r.text
    return sha, r.json()


def _flip(path, at=0):
    data = bytearray(path.read_bytes())
    data[at] ^= 0xFF
    path.write_bytes(bytes(data))


def _truncate(path, keep):
    path.write_bytes(path.read_bytes()[:keep])


# ---------------------------------------------------------------------------
# index persistence and basic audit
# ---------------------------------------------------------------------------


def test_seal_persists_trusted_chunk_index(client, tmp_path):
    blob = os.urandom(2 * CHUNK_SIZE + 7)
    _make_sealed(client, tmp_path, "idx", blob)
    index = json.loads(_index_file(tmp_path, "idx").read_text())
    assert index["version"] == 1
    assert len(index["chunks"]) == 3
    assert [c["i"] for c in index["chunks"]] == [0, 1, 2]
    assert index["chunks"][0]["size"] == CHUNK_SIZE
    assert index["chunks"][2]["size"] == 7
    # index digests really are the per-chunk digests
    assert index["chunks"][1]["sha256"] == _digest(blob[CHUNK_SIZE:2 * CHUNK_SIZE])


def test_audit_healthy_new_session_is_stable(client, tmp_path):
    blob = os.urandom(CHUNK_SIZE + 10)
    sha, receipt = _make_sealed(client, tmp_path, "h1", blob)
    r = client.post("/api/uploads/h1/audit")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "HEALTHY"
    assert body["index_present"] is True
    assert body["index_built"] is False
    assert body["bad_ranges"] == []
    assert body["receipt"] == receipt
    assert body["receipt"]["sha256"] == sha
    # repeated audit returns the same stable result
    assert client.post("/api/uploads/h1/audit").json() == body


def test_audit_unsealed_rejected_without_touching_progress(client, tmp_path):
    blob = os.urandom(CHUNK_SIZE + 1)
    sha = _digest(blob)
    _put(client, "open", 0, blob[:CHUNK_SIZE], len(blob), sha)

    r = client.post("/api/uploads/open/audit")
    assert r.status_code == 409
    assert "not sealed" in r.json()["error"]

    status = client.get("/api/uploads/open").json()
    assert status["sealed"] is False
    assert status["confirmed_chunks"] == [0]
    assert status["missing_ranges"] == [[1, 1]]
    # no index or repair state created by the refused audit
    assert not _index_file(tmp_path, "open").exists()
    assert not (_session_dir(tmp_path, "open") / "repair").exists()
    # upload still proceeds normally afterwards
    assert _put(client, "open", CHUNK_SIZE, blob[CHUNK_SIZE:]).status_code == 200


def test_audit_unknown_session_is_400(client):
    r = client.post("/api/uploads/nope/audit")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# old sessions: length + whole-file verification, then index build
# ---------------------------------------------------------------------------


def test_old_session_first_audit_verifies_and_builds_index(client, tmp_path):
    blob = os.urandom(3 * CHUNK_SIZE + 5)
    _, receipt = _make_sealed(client, tmp_path, "old", blob)
    # simulate a session sealed before per-chunk indexes existed
    _index_file(tmp_path, "old").unlink()

    r = client.post("/api/uploads/old/audit")
    body = r.json()
    assert r.status_code == 200
    assert body["status"] == "HEALTHY"
    assert body["index_present"] is True
    assert body["index_built"] is True
    assert body["receipt"] == receipt

    # index now persisted; second audit no longer reports a build
    assert _index_file(tmp_path, "old").exists()
    again = client.post("/api/uploads/old/audit").json()
    assert again["status"] == "HEALTHY"
    assert again["index_built"] is False
    assert again["index_present"] is True


def test_old_session_missing_block_reported_as_missing(client, tmp_path):
    blob = os.urandom(3 * CHUNK_SIZE + 5)
    _make_sealed(client, tmp_path, "om", blob)
    _index_file(tmp_path, "om").unlink()
    _chunk_file(tmp_path, "om", 1).unlink()

    body = client.post("/api/uploads/om/audit").json()
    assert body["status"] == "DEGRADED"
    assert body["missing_ranges"] == [[1, 1]]
    assert body["length_anomaly_ranges"] == []
    assert body["digest_mismatch_ranges"] == []
    assert body["bad_ranges"] == [[1, 1]]
    assert body["index_built"] is False
    assert not _index_file(tmp_path, "om").exists()


def test_old_session_length_anomaly_is_distinct(client, tmp_path):
    blob = os.urandom(3 * CHUNK_SIZE + 5)
    _make_sealed(client, tmp_path, "ol", blob)
    _index_file(tmp_path, "ol").unlink()
    _truncate(_chunk_file(tmp_path, "ol", 0), CHUNK_SIZE - 3)
    _flip(_chunk_file(tmp_path, "ol", 2))  # corrupt short final block too

    body = client.post("/api/uploads/ol/audit").json()
    assert body["status"] == "DEGRADED"
    # block 0 has a wrong length; block 2's bit flip cannot be whole-file
    # located without an index, but length anomalies are reported exactly
    assert body["length_anomaly_ranges"] == [[0, 0]]
    assert body["missing_ranges"] == []
    assert body["digest_mismatch_ranges"] == []
    assert body["unlocated_digest_mismatch"] is False
    assert not _index_file(tmp_path, "ol").exists()


def test_old_session_bitflip_is_unlocated_digest_mismatch(client, tmp_path):
    blob = os.urandom(2 * CHUNK_SIZE + 9)
    _make_sealed(client, tmp_path, "ob", blob)
    _index_file(tmp_path, "ob").unlink()
    _flip(_chunk_file(tmp_path, "ob", 1))

    body = client.post("/api/uploads/ob/audit").json()
    assert body["status"] == "DEGRADED"
    assert body["digest_mismatch_located"] is False
    assert body["unlocated_digest_mismatch"] is True
    assert body["digest_mismatch_ranges"] == []
    assert body["length_anomaly_ranges"] == []
    assert body["missing_ranges"] == []
    # failed first audit must not fabricate a trusted index
    assert not _index_file(tmp_path, "ob").exists()


# ---------------------------------------------------------------------------
# new sessions: per-chunk location
# ---------------------------------------------------------------------------


def test_new_session_bitflip_is_located_to_block(client, tmp_path):
    blob = os.urandom(4 * CHUNK_SIZE + 1)
    _make_sealed(client, tmp_path, "nb", blob)
    _flip(_chunk_file(tmp_path, "nb", 2))
    _flip(_chunk_file(tmp_path, "nb", 3), at=0)

    body = client.post("/api/uploads/nb/audit").json()
    assert body["status"] == "DEGRADED"
    assert body["digest_mismatch_located"] is True
    assert body["unlocated_digest_mismatch"] is False
    assert body["digest_mismatch_ranges"] == [[2, 3]]
    assert body["bad_ranges"] == [[2, 3]]
    assert body["missing_ranges"] == []
    assert body["length_anomaly_ranges"] == []


def test_ranges_for_missing_and_bad_length_with_index(client, tmp_path):
    blob = b"p" * (5 * CHUNK_SIZE + 7)
    _make_sealed(client, tmp_path, "rg", blob)
    _chunk_file(tmp_path, "rg", 0).unlink()
    _chunk_file(tmp_path, "rg", 4).unlink()
    _truncate(_chunk_file(tmp_path, "rg", 2), 10)

    body = client.post("/api/uploads/rg/audit").json()
    assert body["status"] == "DEGRADED"
    assert body["missing_ranges"] == [[0, 0], [4, 4]]
    assert body["length_anomaly_ranges"] == [[2, 2]]
    assert body["digest_mismatch_ranges"] == []


# ---------------------------------------------------------------------------
# repair validation
# ---------------------------------------------------------------------------


def test_repair_unknown_and_unsealed_are_rejected(client):
    assert client.post("/api/uploads/nope/repair", content=b"x").status_code == 400
    blob = os.urandom(10)
    _put(client, "open2", 0, blob, len(blob), _digest(blob))
    r = client.post("/api/uploads/open2/repair", content=blob)
    assert r.status_code == 409
    # unsealed progress untouched
    assert client.get("/api/uploads/open2").json()["confirmed_chunks"] == [0]


def test_repair_wrong_file_is_stable_400_and_changes_nothing(client, tmp_path):
    blob = os.urandom(2 * CHUNK_SIZE + 50)
    _, receipt = _make_sealed(client, tmp_path, "wf", blob)
    _flip(_chunk_file(tmp_path, "wf", 1))
    before = {
        i: _chunk_file(tmp_path, "wf", i).read_bytes() for i in range(3)
    }

    # wrong length
    r1 = client.post("/api/uploads/wf/repair", content=blob + b"x")
    assert r1.status_code == 400
    assert f"{len(blob) + 1}" in r1.json()["error"]
    # wrong digest, same length
    wrong = bytearray(blob)
    wrong[0] ^= 0x01
    r2 = client.post("/api/uploads/wf/repair", content=bytes(wrong))
    assert r2.status_code == 400
    assert "sha256" in r2.json()["error"]
    # repeat the same wrong file: same stable result
    r3 = client.post("/api/uploads/wf/repair", content=bytes(wrong))
    assert r3.status_code == 400
    assert r3.json() == r2.json()

    # no repair state, no byte changes, receipt still the same
    assert not (_session_dir(tmp_path, "wf") / "repair").exists()
    for i, raw in before.items():
        assert _chunk_file(tmp_path, "wf", i).read_bytes() == raw
    assert client.post("/api/uploads/wf/seal").json() == receipt


# ---------------------------------------------------------------------------
# repair convergence
# ---------------------------------------------------------------------------


def test_repair_fixes_located_blocks_and_keeps_receipt(client, tmp_path):
    blob = os.urandom(4 * CHUNK_SIZE + 11)
    sha, receipt = _make_sealed(client, tmp_path, "rp", blob)
    _flip(_chunk_file(tmp_path, "rp", 0))
    _flip(_chunk_file(tmp_path, "rp", 3), at=5)

    audit = client.post("/api/uploads/rp/audit").json()
    assert audit["status"] == "DEGRADED"
    assert audit["digest_mismatch_ranges"] == [[0, 0], [3, 3]]

    r = client.post("/api/uploads/rp/repair", content=blob)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "HEALTHY"
    assert body["repaired_ranges"] == [[0, 0], [3, 3]]
    assert body["already_healthy"] is False
    # receipt id, digest and seal time are immutable
    assert body["receipt"] == receipt
    assert body["receipt"]["sealed_at"] == receipt["sealed_at"]

    # bytes restored, repair state cleaned up, audit healthy
    assert _chunk_file(tmp_path, "rp", 0).read_bytes() == blob[:CHUNK_SIZE]
    assert not (_session_dir(tmp_path, "rp") / "repair").exists()
    final = client.post("/api/uploads/rp/audit").json()
    assert final["status"] == "HEALTHY"
    assert final["receipt"] == receipt
    assert _digest(b"".join(
        _chunk_file(tmp_path, "rp", i).read_bytes() for i in range(5)
    )) == sha


def test_repair_old_unlocated_session_locates_and_builds_index(client, tmp_path):
    blob = os.urandom(3 * CHUNK_SIZE + 3)
    _, receipt = _make_sealed(client, tmp_path, "ro", blob)
    _index_file(tmp_path, "ro").unlink()
    _flip(_chunk_file(tmp_path, "ro", 1))
    assert client.post("/api/uploads/ro/audit").json()["unlocated_digest_mismatch"] is True

    body = client.post("/api/uploads/ro/repair", content=blob).json()
    assert body["status"] == "HEALTHY"
    assert body["index_built"] is True
    assert body["repaired_ranges"] == [[1, 1]]
    assert body["receipt"] == receipt
    assert _index_file(tmp_path, "ro").exists()
    assert client.post("/api/uploads/ro/audit").json()["status"] == "HEALTHY"


def test_repair_fixes_truncated_and_missing_blocks(client, tmp_path):
    blob = os.urandom(3 * CHUNK_SIZE + 7)
    _, receipt = _make_sealed(client, tmp_path, "rt", blob)
    _truncate(_chunk_file(tmp_path, "rt", 1), 100)
    _chunk_file(tmp_path, "rt", 2).unlink()

    body = client.post("/api/uploads/rt/audit").json()
    assert body["length_anomaly_ranges"] == [[1, 1]]
    assert body["missing_ranges"] == [[2, 2]]

    done = client.post("/api/uploads/rt/repair", content=blob).json()
    assert done["status"] == "HEALTHY"
    assert done["repaired_ranges"] == [[1, 2]]
    assert done["receipt"] == receipt
    assert client.post("/api/uploads/rt/audit").json()["status"] == "HEALTHY"


def test_repair_is_idempotent_when_already_healthy(client, tmp_path):
    blob = os.urandom(CHUNK_SIZE + 1)
    _, receipt = _make_sealed(client, tmp_path, "ih", blob)
    r1 = client.post("/api/uploads/ih/repair", content=blob)
    assert r1.status_code == 200
    assert r1.json()["status"] == "HEALTHY"
    assert r1.json()["already_healthy"] is True
    r2 = client.post("/api/uploads/ih/repair", content=blob)
    assert r2.json()["status"] == "HEALTHY"
    assert r2.json()["already_healthy"] is True
    assert r2.json()["receipt"] == receipt
    assert not (_session_dir(tmp_path, "ih") / "repair").exists()


# ---------------------------------------------------------------------------
# interrupted, restartable repair
# ---------------------------------------------------------------------------


def _corrupt_many(tmp_path, session, indices, size_chunks):
    for i in indices:
        _flip(_chunk_file(tmp_path, session, i), at=i + 1)


def test_paused_repair_audits_as_repairing_and_resumes(client, tmp_path):
    blob = os.urandom(5 * CHUNK_SIZE + 1)
    _, receipt = _make_sealed(client, tmp_path, "pr", blob)
    _corrupt_many(tmp_path, "pr", [0, 2, 4], 6)

    web.store.repair_block_limit = 1

    r1 = client.post("/api/uploads/pr/repair", content=blob)
    assert r1.status_code == 200
    b1 = r1.json()
    assert b1["status"] == "REPAIRING"
    assert b1["recovered_ranges"] == [[0, 0]]
    assert b1["remaining_ranges"] == [[2, 2], [4, 4]]
    assert _repair_state_file(tmp_path, "pr").exists()

    # audit during repair is stable and never changes the plan
    a1 = client.post("/api/uploads/pr/audit").json()
    a2 = client.post("/api/uploads/pr/audit").json()
    assert a1 == a2
    assert a1["status"] == "REPAIRING"
    assert a1["remaining_ranges"] == [[2, 2], [4, 4]]
    assert a1["recovered_ranges"] == [[0, 0]]

    r2 = client.post("/api/uploads/pr/repair", content=blob).json()
    assert r2["status"] == "REPAIRING"
    assert r2["recovered_ranges"] == [[0, 0], [2, 2]]
    assert r2["remaining_ranges"] == [[4, 4]]

    web.store.repair_block_limit = None
    r3 = client.post("/api/uploads/pr/repair", content=blob).json()
    assert r3["status"] == "HEALTHY"
    assert r3["repaired_ranges"] == [[0, 0], [2, 2], [4, 4]]
    assert r3["receipt"] == receipt
    assert not (_session_dir(tmp_path, "pr") / "repair").exists()
    assert client.post("/api/uploads/pr/audit").json()["status"] == "HEALTHY"


def test_repair_resumes_across_service_restart(client, tmp_path):
    data_dir = tmp_path / "data"
    blob = os.urandom(5 * CHUNK_SIZE + 1)
    _, receipt = _make_sealed(client, tmp_path, "rr", blob)
    _corrupt_many(tmp_path, "rr", [0, 1, 2, 3], 5)

    web.store.repair_block_limit = 1
    first = client.post("/api/uploads/rr/repair", content=blob).json()
    assert first["status"] == "REPAIRING"
    assert first["recovered_ranges"] == [[0, 0]]

    # "restart": brand new store over the same directory; each call replaces
    # at most one still-bad block (already-good planned blocks cost nothing)
    web.store = UploadStore(str(data_dir))
    web.store.repair_block_limit = 1
    r = client.post("/api/uploads/rr/repair", content=blob).json()
    assert r["status"] == "REPAIRING"
    r = client.post("/api/uploads/rr/repair", content=blob).json()
    assert r["status"] == "REPAIRING"
    r = client.post("/api/uploads/rr/repair", content=blob).json()
    assert r["status"] == "HEALTHY"
    assert r["receipt"] == receipt
    assert not (data_dir / "rr" / "repair").exists()

    # another restart: a repeat repair is an idempotent no-op, audit HEALTHY
    web.store = UploadStore(str(data_dir))
    r = client.post("/api/uploads/rr/repair", content=blob).json()
    assert r["status"] == "HEALTHY"
    assert r["already_healthy"] is True
    assert client.post("/api/uploads/rr/audit").json()["status"] == "HEALTHY"


def test_wrong_file_during_paused_repair_does_not_disturb_plan(client, tmp_path):
    blob = os.urandom(3 * CHUNK_SIZE + 1)
    _make_sealed(client, tmp_path, "pw", blob)
    _corrupt_many(tmp_path, "pw", [0, 2], 3)

    web.store.repair_block_limit = 1
    assert client.post("/api/uploads/pw/repair", content=blob).json()["status"] == "REPAIRING"

    wrong = bytearray(blob)
    wrong[10] ^= 0xAA
    r = client.post("/api/uploads/pw/repair", content=bytes(wrong))
    assert r.status_code == 400
    r = client.post("/api/uploads/pw/repair", content=blob + b"y")
    assert r.status_code == 400

    # plan and progress are intact; audit is still REPAIRING with same ranges
    audit = client.post("/api/uploads/pw/audit").json()
    assert audit["status"] == "REPAIRING"
    assert audit["remaining_ranges"] == [[2, 2]]
    assert audit["recovered_ranges"] == [[0, 0]]

    web.store.repair_block_limit = None
    done = client.post("/api/uploads/pw/repair", content=blob).json()
    assert done["status"] == "HEALTHY"


def test_audit_during_repair_reports_true_remaining_after_shift(client, tmp_path):
    blob = os.urandom(4 * CHUNK_SIZE + 1)
    _, receipt = _make_sealed(client, tmp_path, "ar", blob)
    _corrupt_many(tmp_path, "ar", [0, 3], 4)

    web.store.repair_block_limit = 1
    paused = client.post("/api/uploads/ar/repair", content=blob).json()
    assert paused["status"] == "REPAIRING"
    assert paused["remaining_ranges"] == [[3, 3]]

    # block 3 heals-equivalent is impossible, but a NEW rot appears in a block
    # the plan considered good while the repair is paused (block 2)
    _flip(_chunk_file(tmp_path, "ar", 2))
    audit = client.post("/api/uploads/ar/audit").json()
    assert audit["status"] == "REPAIRING"
    assert audit["remaining_ranges"] == [[2, 3]]
    assert audit["recovered_ranges"] == [[0, 0]]
    assert audit["digest_mismatch_ranges"] == [[2, 3]]
    # audit was read-only: no spurious completion
    assert _repair_state_file(tmp_path, "ar").exists()

    web.store.repair_block_limit = None
    done = client.post("/api/uploads/ar/repair", content=blob).json()
    assert done["status"] == "HEALTHY"
    assert done["repaired_ranges"] == [[0, 0], [2, 3]]
    assert done["receipt"] == receipt


def test_resume_picks_up_new_bit_rot_in_unplanned_block(client, tmp_path):
    blob = os.urandom(4 * CHUNK_SIZE + 1)
    _, receipt = _make_sealed(client, tmp_path, "nr", blob)
    _flip(_chunk_file(tmp_path, "nr", 0))
    _flip(_chunk_file(tmp_path, "nr", 3))
    web.store.repair_block_limit = 1
    paused = client.post("/api/uploads/nr/repair", content=blob).json()
    assert paused["status"] == "REPAIRING"

    # silent rot appears in block 2 while the repair is paused
    _flip(_chunk_file(tmp_path, "nr", 2))

    web.store.repair_block_limit = None
    done = client.post("/api/uploads/nr/repair", content=blob).json()
    assert done["status"] == "HEALTHY"
    assert done["repaired_ranges"] == [[0, 0], [2, 3]]
    assert done["receipt"] == receipt
    assert client.post("/api/uploads/nr/audit").json()["status"] == "HEALTHY"


# ---------------------------------------------------------------------------
# invariants around sealed data and status
# ---------------------------------------------------------------------------


def test_chunk_api_cannot_rewrite_sealed_data_even_during_repair(client, tmp_path):
    blob = os.urandom(3 * CHUNK_SIZE + 5)
    _make_sealed(client, tmp_path, "si", blob)
    _flip(_chunk_file(tmp_path, "si", 1))
    _flip(_chunk_file(tmp_path, "si", 2))
    web.store.repair_block_limit = 1
    paused = client.post("/api/uploads/si/repair", content=blob).json()
    assert paused["status"] == "REPAIRING"
    # The chunk API can never rewrite sealed data, repair is the only channel:
    good1 = blob[CHUNK_SIZE : 2 * CHUNK_SIZE]
    good2 = blob[2 * CHUNK_SIZE : 3 * CHUNK_SIZE]
    # block 2 is still corrupt: sending the good bytes through PUT is refused
    assert _put(client, "si", 2 * CHUNK_SIZE, good2).status_code == 409
    # block 1 was repaired: identical retransmit stays idempotent 200, foreign
    # bytes are still refused
    assert _put(client, "si", CHUNK_SIZE, good1).json()["duplicate"] is True
    assert _put(client, "si", CHUNK_SIZE, b"\x00" * CHUNK_SIZE).status_code == 409
    # repair remains the only way to restore block 2
    audit = client.post("/api/uploads/si/audit").json()
    assert audit["status"] == "REPAIRING"
    assert audit["remaining_ranges"] == [[2, 2]]
    web.store.repair_block_limit = None
    assert client.post("/api/uploads/si/repair", content=blob).json()["status"] == "HEALTHY"


def test_status_exposes_index_and_repair_flags(client, tmp_path):
    blob = os.urandom(CHUNK_SIZE + 1)
    _make_sealed(client, tmp_path, "fl", blob)
    body = client.get("/api/uploads/fl").json()
    assert body["sealed"] is True
    assert body["index_present"] is True
    assert body["repair_active"] is False

    _flip(_chunk_file(tmp_path, "fl", 1))
    web.store.repair_block_limit = 1
    # one bad block converges in a single call, so corrupt two to stay paused
    blob2 = os.urandom(3 * CHUNK_SIZE + 1)
    _make_sealed(client, tmp_path, "fl2", blob2)
    _flip(_chunk_file(tmp_path, "fl2", 0))
    _flip(_chunk_file(tmp_path, "fl2", 2))
    client.post("/api/uploads/fl2/repair", content=blob2)
    flags = client.get("/api/uploads/fl2").json()
    assert flags["repair_active"] is True
    web.store.repair_block_limit = None
    client.post("/api/uploads/fl2/repair", content=blob2)
    assert client.get("/api/uploads/fl2").json()["repair_active"] is False


# ---------------------------------------------------------------------------
# trust boundaries and boundary sizes
# ---------------------------------------------------------------------------


def test_tampered_index_cannot_hide_corruption_from_audit_or_repair(client, tmp_path):
    blob = os.urandom(2 * CHUNK_SIZE + 4)
    _, receipt = _make_sealed(client, tmp_path, "ti", blob)

    # Corrupt block 1 AND forge the index to claim the corrupt digest is right.
    target = _chunk_file(tmp_path, "ti", 1)
    _flip(target)
    forged = hashlib.sha256(target.read_bytes()).hexdigest()
    index_path = _index_file(tmp_path, "ti")
    index = json.loads(index_path.read_text())
    index["chunks"][1]["sha256"] = forged
    index_path.write_text(json.dumps(index))

    body = client.post("/api/uploads/ti/audit").json()
    # Per-block checks pass against the forged index, but the whole-file
    # digest anchor in meta/receipt exposes the lie as unlocated.
    assert body["status"] == "DEGRADED"
    assert body["unlocated_digest_mismatch"] is True
    assert body["digest_mismatch_ranges"] == []

    # Repair compares with the validated original, not the index: it locates
    # and fixes block 1 regardless of the forgery.
    done = client.post("/api/uploads/ti/repair", content=blob).json()
    assert done["status"] == "HEALTHY"
    assert done["repaired_ranges"] == [[1, 1]]
    assert done["receipt"] == receipt
    # completion rewrote a trustworthy index
    assert client.post("/api/uploads/ti/audit").json()["status"] == "HEALTHY"


def test_completed_repair_state_after_restart_autofinalizes_on_audit(client, tmp_path):
    data_dir = tmp_path / "data"
    blob = os.urandom(2 * CHUNK_SIZE + 1)
    _, receipt = _make_sealed(client, tmp_path, "ac", blob)
    _flip(_chunk_file(tmp_path, "ac", 0))
    done = client.post("/api/uploads/ac/repair", content=blob).json()
    assert done["status"] == "HEALTHY"
    # simulate a crash: state file says everything is repaired but it lingers
    repair_dir = data_dir / "ac" / "repair"
    repair_dir.mkdir(exist_ok=True)
    (repair_dir / "state.json").write_text(json.dumps({
        "total_size": len(blob),
        "sha256": _digest(blob),
        "bad": [0],
        "repaired": [0],
        "missing": [],
        "bad_length": [],
        "digest_mismatch": [0],
    }))

    web.store = UploadStore(str(data_dir))  # restart
    body = client.post("/api/uploads/ac/audit").json()
    assert body["status"] == "HEALTHY"
    assert not repair_dir.exists()
    assert body["receipt"] == receipt


def test_single_byte_file_audit_and_repair_roundtrip(client, tmp_path):
    blob = b"z"
    _, receipt = _make_sealed(client, tmp_path, "one", blob)
    assert client.post("/api/uploads/one/audit").json()["status"] == "HEALTHY"
    _flip(_chunk_file(tmp_path, "one", 0))
    body = client.post("/api/uploads/one/audit").json()
    assert body["status"] == "DEGRADED"
    assert body["digest_mismatch_ranges"] == [[0, 0]]
    done = client.post("/api/uploads/one/repair", content=blob).json()
    assert done["status"] == "HEALTHY"
    assert done["repaired_ranges"] == [[0, 0]]
    assert done["receipt"] == receipt
    assert client.post("/api/uploads/one/audit").json()["status"] == "HEALTHY"


def test_repair_wrong_length_reports_both_sizes(client, tmp_path):
    blob = os.urandom(CHUNK_SIZE + 3)
    _make_sealed(client, tmp_path, "wl", blob)
    r = client.post("/api/uploads/wl/repair", content=blob[:-1])
    assert r.status_code == 400
    msg = r.json()["error"]
    assert str(len(blob) - 1) in msg and str(len(blob)) in msg
