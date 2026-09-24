"""FastAPI application: resumable, idempotent cryo-EM upload sealing desk."""

from __future__ import annotations

import os
import re
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .storage import (
    ConflictError,
    RejectError,
    UploadStore,
)

SESSION_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

DATA_DIR = os.environ.get("DATA_DIR", "/data")
STATIC_DIR = os.environ.get("STATIC_DIR", "/app/frontend/dist")

app = FastAPI(title="Cryo-EM Sealing Desk", version="1.1.0")
store = UploadStore(DATA_DIR)


def _check_session(session: str) -> None:
    if not SESSION_RE.match(session):
        raise HTTPException(
            status_code=400,
            detail="session id must be 1-32 ASCII letters or digits",
        )


def _parse_int(name: str, raw: Optional[str]) -> Optional[int]:
    if raw is None or raw == "":
        return None
    try:
        value = int(raw, 10)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"{name} must be an integer")
    # Reject non-canonical forms like "01", "1.0", "+1", " 1 ".
    if str(value) != raw:
        raise HTTPException(status_code=400, detail=f"{name} must be a canonical integer")
    return value


@app.exception_handler(RejectError)
def _reject_handler(_request: Request, exc: RejectError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": str(exc)})


@app.exception_handler(ConflictError)
def _conflict_handler(_request: Request, exc: ConflictError) -> JSONResponse:
    return JSONResponse(status_code=409, content={"error": str(exc)})


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/uploads/{session}")
def get_status(session: str) -> dict:
    _check_session(session)
    status = store.status(session)
    if status is None:
        raise HTTPException(status_code=404, detail="no such session")
    return status


@app.put("/api/uploads/{session}/chunks")
async def put_chunk(
    session: str,
    request: Request,
    x_chunk_offset: Optional[str] = Header(default=None, alias="X-Chunk-Offset"),
    x_total_size: Optional[str] = Header(default=None, alias="X-Total-Size"),
    x_content_sha256: Optional[str] = Header(default=None, alias="X-Content-SHA256"),
) -> dict:
    _check_session(session)

    offset = _parse_int("X-Chunk-Offset", x_chunk_offset)
    if offset is None:
        raise HTTPException(status_code=400, detail="X-Chunk-Offset header is required")
    total_size = _parse_int("X-Total-Size", x_total_size)
    sha256 = x_content_sha256.lower() if x_content_sha256 else None
    if sha256 is not None and not SHA256_RE.match(sha256):
        raise HTTPException(
            status_code=400,
            detail="X-Content-SHA256 must be 64 lowercase hex characters",
        )

    data = await request.body()
    return store.put_chunk(session, offset, data, total_size, sha256)


@app.post("/api/uploads/{session}/seal")
def seal(session: str) -> JSONResponse:
    _check_session(session)
    try:
        result, _ok, missing = store.seal(session)
    except RejectError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except ConflictError as exc:
        # Digest mismatch: no receipt is produced.
        return JSONResponse(status_code=409, content={"error": str(exc)})

    if missing is not None:
        return JSONResponse(
            status_code=409,
            content={
                "error": "upload is incomplete",
                "missing_ranges": missing,
            },
        )
    return JSONResponse(status_code=200, content=result)


@app.post("/api/uploads/{session}/audit")
def audit(session: str) -> dict:
    """Re-verify a sealed session against the receipt.

    Returns HEALTHY / DEGRADED / REPAIRING plus the anomalous block ranges.
    Unsealed sessions are refused (409) and upload progress is never touched.
    """
    _check_session(session)
    return store.audit(session)


@app.post("/api/uploads/{session}/repair")
async def repair(session: str, request: Request) -> dict:
    """Repair anomalous blocks from the complete original file.

    The body is used only when its length and whole-file digest match the
    sealed receipt; block replacement is resumable across interrupted
    requests and service restarts, and the receipt never changes.
    """
    _check_session(session)
    data = await request.body()
    return store.repair(session, data)


# Serve the built React SPA from the same origin (API routes take priority).
if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
