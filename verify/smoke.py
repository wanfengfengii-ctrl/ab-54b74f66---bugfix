"""HTTP smoke test for a running sealing-desk instance.

Exercises the whole contract over real HTTP (stdlib only):
  health + SPA, validation, out-of-order PUT, idempotent retransmission,
  409 conflicts that never mutate state, missing-range listing, atomic seal,
  identical receipt on repeated seal, sealed-session immutability, and the
  sealed-session integrity audit + original-file repair loop (including
  simulated silent disk corruption, interrupted/resumable repair and an
  old-style session without a per-chunk index).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request

BASE = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
DATA = os.environ.get("DATA_DIR", "/data")
CHUNK = 65536


def call(method: str, path: str, body: bytes | None = None, headers=None):
    req = urllib.request.Request(
        BASE + path,
        data=body,
        method=method,
        headers=headers or {},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode(errors="replace")}


def put(session, offset, data, total=None, sha=None):
    headers = {"X-Chunk-Offset": str(offset), "Content-Type": "application/octet-stream"}
    if total is not None:
        headers["X-Total-Size"] = str(total)
    if sha is not None:
        headers["X-Content-SHA256"] = sha
    return call("PUT", f"/api/uploads/{session}/chunks", data, headers)


def upload_and_seal(session, blob):
    digest = hashlib.sha256(blob).hexdigest()
    total = len(blob)
    count = (total + CHUNK - 1) // CHUNK
    for i in range(count):
        off = i * CHUNK
        part = blob[off : min(off + CHUNK, total)]
        status, body = put(session, off, part, total, digest)
        if status != 200:
            raise SystemExit(f"upload failed: {status} {body}")
    status, receipt = call("POST", f"/api/uploads/{session}/seal")
    if status != 200:
        raise SystemExit(f"seal failed: {status} {receipt}")
    return digest, receipt


def chunk_path(session, index):
    return os.path.join(DATA, session, "chunks", f"{index:08d}")


def flip_file(path, at=0):
    with open(path, "rb") as fh:
        raw = bytearray(fh.read())
    raw[at] ^= 0xFF
    with open(path, "wb") as fh:
        fh.write(bytes(raw))


def truncate_file(path, keep):
    with open(path, "rb") as fh:
        raw = fh.read()
    with open(path, "wb") as fh:
        fh.write(raw[:keep])


def write_repair_plan(session, blob, bad, repaired=None, categories=None):
    """Simulate a repair interrupted by a crash: a persisted plan on disk."""
    repair_dir = os.path.join(DATA, session, "repair")
    os.makedirs(repair_dir, exist_ok=True)
    with open(os.path.join(repair_dir, "restore.tmp"), "wb") as fh:
        fh.write(blob)
    plan = {
        "total_size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "bad": bad,
        "repaired": repaired or [],
        "missing": (categories or {}).get("missing", []),
        "bad_length": (categories or {}).get("bad_length", []),
        "digest_mismatch": (categories or {}).get("digest_mismatch", bad),
    }
    with open(os.path.join(repair_dir, "state.json"), "w") as fh:
        json.dump(plan, fh)


def wait_healthy(timeout=30.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            status, _ = call("GET", "/health")
            if status == 200:
                return
        except Exception as exc:  # connection refused while starting
            last = exc
        time.sleep(0.5)
    raise SystemExit(f"service never became healthy: {last}")


def check(cond, label):
    if not cond:
        raise SystemExit(f"SMOKE FAIL: {label}")
    print(f"  ok - {label}")


def main():
    wait_healthy()
    suffix = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
    s = f"SMOKE{suffix}"

    print("[health + static]")
    status, body = call("GET", "/health")
    check(status == 200 and body.get("status") == "ok", "GET /health -> 200 ok")
    req = urllib.request.Request(BASE + "/")
    with urllib.request.urlopen(req, timeout=10) as resp:
        index = resp.read().decode()
    check(resp.status == 200 and 'id="root"' in index, "SPA index.html is served")

    print("[validation]")
    status, body = put("bad-id!", 0, b"x", 1, "a" * 64)
    check(status == 400, f"invalid session rejected (400), got {status}")
    bad_digest = put(s + "B", 0, b"x", 1, "Z" * 64)
    check(bad_digest[0] == 400, "uppercase digest rejected (400)")

    # 3-chunk file, last chunk short
    blob = os.urandom(2 * CHUNK + 123)
    digest = hashlib.sha256(blob).hexdigest()
    c0, c1, c2 = blob[:CHUNK], blob[CHUNK:2 * CHUNK], blob[2 * CHUNK:]

    print("[out of order arrival]")
    status, body = put(s, CHUNK, c1, len(blob), digest)
    check(status == 200 and body["confirmed_chunks"] == [1], "chunk #1 first -> 200")
    status, body = put(s, 2 * CHUNK, c2)
    check(status == 200 and set(body["confirmed_chunks"]) == {1, 2}, "chunk #2 -> 200")

    print("[located rejections before completion]")
    status, body = put(s, 1, b"x")
    check(status == 400 and "not aligned" in body["error"], "unaligned offset -> 400")
    status, body = put(s, 3 * CHUNK, b"x")
    check(status == 400 and "beyond" in body["error"], "out-of-bounds offset -> 400")
    status, body = put(s, 0, c0[:-1])
    check(status == 400 and "chunk length" in body["error"], "wrong chunk length -> 400")

    print("[seal with missing blocks]")
    status, body = call("POST", f"/api/uploads/{s}/seal")
    check(status == 409 and body["missing_ranges"] == [[0, 0]],
          f"missing ranges reported: {body}")

    print("[idempotent retransmission then completion]")
    status, body = put(s, CHUNK, c1, len(blob), digest)
    check(status == 200 and body["duplicate"] is True, "identical retransmit -> 200 duplicate")
    status, body = put(s, 0, c0)
    check(status == 200 and body["confirmed_chunks"] == [0, 1, 2], "chunk #0 completes upload")

    print("[409 conflict must not overwrite]")
    evil = bytearray(c1)
    evil[0] ^= 0xFF
    status, body = put(s, CHUNK, bytes(evil))
    check(status == 409, f"different bytes at same offset -> 409, got {status} {body}")
    status, body = put(s, CHUNK, c1)
    check(status == 200 and body["duplicate"] is True,
          "original chunk still intact and idempotent after 409")
    status, body = put(s, CHUNK, c1, len(blob) + 1, digest)
    check(status == 409, "changed total_size -> 409")
    status, body = put(s, CHUNK, c1, len(blob), "a" * 64)
    check(status == 409, "changed sha256 -> 409")

    print("[atomic seal + stable receipt]")
    status, receipt = call("POST", f"/api/uploads/{s}/seal")
    check(status == 200 and receipt["sha256"] == digest and receipt["chunks"] == 3,
          f"seal succeeds with correct digest: {receipt}")
    status, again = call("POST", f"/api/uploads/{s}/seal")
    check(status == 200 and again == receipt, "repeat seal returns the SAME receipt")

    print("[sealed immutability]")
    wrong0 = bytes(CHUNK)  # all-zero chunk, differs from random c0
    status, _ = put(s, 0, wrong0)
    check(status == 409, "different chunk after seal -> 409")
    status, body = put(s, 0, c0)
    check(status == 200 and body["sealed"] is True, "identical PUT after seal stays 200")

    print("[digest mismatch never seals]")
    bad = b"q" * 50
    sb = s + "D"
    status, _ = put(sb, 0, bad, len(bad), "a" * 64)
    check(status == 200, "wrong-declared digest upload accepted chunk-wise")
    status, body = call("POST", f"/api/uploads/{sb}/seal")
    check(status == 409 and "digest" in body["error"], "digest mismatch -> 409, no receipt")
    status, body = call("GET", f"/api/uploads/{sb}")
    check(status == 200 and body["sealed"] is False and body["receipt"] is None,
          "no receipt exists after digest mismatch")

    print("[audit is sealed-only and never moves upload progress]")
    status, body = call("POST", f"/api/uploads/{sb}/audit")
    check(status == 409 and "not sealed" in body["error"],
          "audit of an unsealed session -> 409")
    status, body = call("GET", f"/api/uploads/{sb}")
    check(body["sealed"] is False and body["confirmed_chunks"] == [0],
          "refused audit left upload progress untouched")
    status, body = call("POST", f"/api/uploads/{s}MISSING/audit")
    check(status == 400, "audit of unknown session -> 400")

    # The corruption scenarios need direct access to the web's data dir.
    can_corrupt = os.path.isdir(DATA) and os.access(DATA, os.W_OK)
    if not can_corrupt:
        print(f"[skip] {DATA} not writable from verify; corruption cases need the shared volume")
        print(f"\nSMOKE OK against {BASE} (sessions {s}, {sb})")
        return

    print("[fresh sealed session: index + stable HEALTHY audit]")
    blob_a = os.urandom(3 * CHUNK + 99)
    sa = s + "A"
    da, ra = upload_and_seal(sa, blob_a)
    check(os.path.isfile(os.path.join(DATA, sa, "chunk_index.json")),
          "new seal persisted per-chunk index")
    status, body = call("POST", f"/api/uploads/{sa}/audit")
    check(status == 200 and body["status"] == "HEALTHY", f"fresh session audits HEALTHY: {body}")
    check(body["index_present"] is True and body["index_built"] is False,
          "trusted index present, not rebuilt")
    status, again = call("POST", f"/api/uploads/{sa}/audit")
    check(again == body, "repeated audit is a stable result")
    check(body["receipt"] == ra, "audit returns the unchanged receipt")
    status, body = call("GET", f"/api/uploads/{sa}")
    check(body["index_present"] is True and body["repair_active"] is False,
          "status exposes index/repair flags")

    print("[silent bit rot: located mismatch, wrong files refused, repair converges]")
    flip_file(chunk_path(sa, 1))
    flip_file(chunk_path(sa, 2), at=5)
    status, body = call("POST", f"/api/uploads/{sa}/audit")
    check(status == 200 and body["status"] == "DEGRADED", "corruption -> DEGRADED")
    check(body["digest_mismatch_ranges"] == [[1, 2]],
          f"mismatch located to blocks 1-2: {body}")
    check(body["missing_ranges"] == [] and body["length_anomaly_ranges"] == [],
          "only digest-mismatch category is reported")

    wrong_len, wrong_body = call("POST", f"/api/uploads/{sa}/repair", blob_a + b"x")
    check(wrong_len == 400 and f"{len(blob_a) + 1}" in wrong_body["error"],
          "repair file with wrong length -> stable 400")
    evil = bytearray(blob_a)
    evil[0] ^= 0x01
    wrong_digest, wb2 = call("POST", f"/api/uploads/{sa}/repair", bytes(evil))
    check(wrong_digest == 400 and "sha256" in wb2["error"],
          "repair file with wrong digest -> 400, no blocks touched")
    # a second identical wrong file gives the same stable answer
    repeat, wb3 = call("POST", f"/api/uploads/{sa}/repair", bytes(evil))
    check(repeat == 400 and wb3 == wb2, "wrong-file repair result is stable")
    status, body = call("POST", f"/api/uploads/{sa}/audit")
    check(body["status"] == "DEGRADED", "failed repair attempts changed nothing")

    status, body = call("POST", f"/api/uploads/{sa}/repair", blob_a)
    check(status == 200 and body["status"] == "HEALTHY", f"valid repair -> HEALTHY: {body}")
    check(body["repaired_ranges"] == [[1, 2]], "repair reports the restored ranges")
    check(body["receipt"] == ra and body["receipt"]["sealed_at"] == ra["sealed_at"],
          "receipt id and sealed_at are immutable across repair")
    status, body = call("POST", f"/api/uploads/{sa}/audit")
    check(body["status"] == "HEALTHY" and body["receipt"] == ra,
          "post-repair audit is HEALTHY with same receipt")
    status, body = call("POST", f"/api/uploads/{sa}/repair", blob_a)
    check(body["status"] == "HEALTHY" and body["already_healthy"] is True,
          "repeat repair on a healthy session is an idempotent no-op")

    print("[missing block and length anomaly are distinct categories]")
    blob_b = os.urandom(4 * CHUNK + 7)
    sbx = s + "B"
    _, rb = upload_and_seal(sbx, blob_b)
    os.unlink(chunk_path(sbx, 0))
    truncate_file(chunk_path(sbx, 2), 10)
    status, body = call("POST", f"/api/uploads/{sbx}/audit")
    check(body["status"] == "DEGRADED", "damaged session -> DEGRADED")
    check(body["missing_ranges"] == [[0, 0]], "missing block range reported")
    check(body["length_anomaly_ranges"] == [[2, 2]], "length anomaly range reported")
    check(body["digest_mismatch_ranges"] == [], "no spurious digest category")
    status, body = call("POST", f"/api/uploads/{sbx}/repair", blob_b)
    check(body["status"] == "HEALTHY" and body["repaired_ranges"] == [[0, 0], [2, 2]],
          "repair restores missing and truncated blocks")
    check(body["receipt"] == rb, "receipt unchanged after restoring missing/truncated")

    print("[old session without index: length+whole-file check, then index build]")
    blob_c = os.urandom(2 * CHUNK + 5)
    sc = s + "C"
    _, rc = upload_and_seal(sc, blob_c)
    os.unlink(os.path.join(DATA, sc, "chunk_index.json"))
    flip_file(chunk_path(sc, 1))
    status, body = call("POST", f"/api/uploads/{sc}/audit")
    check(body["status"] == "DEGRADED" and body["unlocated_digest_mismatch"] is True,
          "old session bit rot is an unlocated whole-file mismatch")
    check(body["digest_mismatch_located"] is False,
          "old session cannot locate without block index")
    check(not os.path.isfile(os.path.join(DATA, sc, "chunk_index.json")),
          "failed first audit does not fabricate an index")
    status, body = call("POST", f"/api/uploads/{sc}/repair", blob_c)
    check(body["status"] == "HEALTHY" and body["repaired_ranges"] == [[1, 1]],
          "repair locates and fixes the block from the original")
    check(body["index_built"] is True, "repair builds the trusted index for the old session")
    check(body["receipt"] == rc, "old-session receipt preserved")
    status, body = call("POST", f"/api/uploads/{sc}/audit")
    check(body["status"] == "HEALTHY" and body["index_present"] is True,
          "old session now audits with the built index")

    print("[interrupted repair resumes on the next request]")
    blob_d = os.urandom(3 * CHUNK + 1)
    sd = s + "E"
    _, rd = upload_and_seal(sd, blob_d)
    flip_file(chunk_path(sd, 0))
    flip_file(chunk_path(sd, 2))
    # crash after block 0 was replaced: state says 0 done, 2 pending
    with open(chunk_path(sd, 0), "wb") as fh:
        fh.write(blob_d[:CHUNK])
    write_repair_plan(sd, blob_d, bad=[0, 2], repaired=[0],
                      categories={"digest_mismatch": [0, 2]})
    status, body = call("POST", f"/api/uploads/{sd}/audit")
    check(body["status"] == "REPAIRING", "audit during an open repair -> REPAIRING")
    check(body["remaining_ranges"] == [[2, 2]], "remaining block range reported")
    check(body["recovered_ranges"] == [[0, 0]], "already recovered block reported")
    audit_again, body2 = call("POST", f"/api/uploads/{sd}/audit")
    check(body2 == body, "audit during repair is a stable read-only result")
    # a wrong file cannot disturb the persisted plan
    status, _ = call("POST", f"/api/uploads/{sd}/repair", blob_d + b"z")
    check(status == 400, "wrong file while REPAIRING -> 400")
    status, body = call("POST", f"/api/uploads/{sd}/repair", blob_d)
    check(status == 200 and body["status"] == "HEALTHY",
          "resumed repair finishes and converges")
    check(body["repaired_ranges"] == [[0, 0], [2, 2]], "resume reports all repaired blocks")
    check(body["receipt"] == rd, "resumed repair keeps the original receipt")
    check(not os.path.isdir(os.path.join(DATA, sd, "repair")),
          "repair state cleaned up after convergence")
    status, body = call("POST", f"/api/uploads/{sd}/audit")
    check(body["status"] == "HEALTHY", "final audit after resume is HEALTHY")

    print(f"\nSMOKE OK against {BASE} (sessions {s}, {sb}, {sa}, {sbx}, {sc}, {sd})")


if __name__ == "__main__":
    main()
