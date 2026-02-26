from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from common.clamav_client import (
    ClamAVConnectionError,
    ClamAVError,
    ClamAVProtocolError,
    clamd_ping,
    clamd_scan_bytes,
    clamd_version,
)
from common.job_index import build_job_index_record as build_job_record
from common.job_index import upsert_job_index_record_async
from common.logging_config import get_logger
from fastapi import APIRouter, File, Form, HTTPException, Request, Security, UploadFile

import runtime
import settings
from deps.auth import require_api_key
from deps.store import _upsert_result

router = APIRouter()
logger = get_logger(__name__)


async def _read_upload_bytes_limited(
    upload: UploadFile, *, max_bytes: int
) -> tuple[bytes, str]:
    hasher = hashlib.sha256()
    total = 0
    parts: list[bytes] = []
    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File too large (max {max_bytes} bytes)",
            )
        hasher.update(chunk)
        parts.append(chunk)
    return b"".join(parts), hasher.hexdigest()


def _decode_payload_bytes(
    payload: str, *, is_base64: bool, max_bytes: int
) -> tuple[bytes, str]:
    raw = (payload or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="payload cannot be empty")

    if is_base64:
        compact = "".join(raw.split())
        estimated_len = (len(compact) * 3) // 4
        if estimated_len > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Payload too large (max {max_bytes} bytes after base64 decode)",
            )
        try:
            data = base64.b64decode(compact, validate=True)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="payload_base64=true but payload is not valid base64",
            )
    else:
        data = raw.encode("utf-8")

    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413, detail=f"Payload too large (max {max_bytes} bytes)"
        )

    return data, hashlib.sha256(data).hexdigest()

@router.post("/file/scan", tags=["File Scanning"], summary="Scan a file for malware")
async def scan_file(
    request: Request,
    file: Optional[UploadFile] = File(None),
    payload: Optional[str] = Form(None),
    payload_base64: bool = Form(False),
    api_key_hash: Optional[str] = Security(require_api_key),
):
    result_backend = settings.RESULT_BACKEND
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)

    if file is None and not (isinstance(payload, str) and payload.strip()):
        raise HTTPException(status_code=400, detail="Provide a file or payload")

    can_store = bool(
        (result_backend == "table" and table_client)
        or (result_backend == "redis" and redis_client)
    )

    job_id = str(uuid4())
    submitted_at = datetime.now(timezone.utc).isoformat()
    correlation_id = getattr(getattr(request, "state", None), "request_id", None)
    if not isinstance(correlation_id, str) or not correlation_id.strip():
        correlation_id = str(uuid4())

    input_type = "file" if file is not None else "payload"

    filename = None
    content_type = None
    if file is not None:
        filename = (file.filename or "upload.bin").strip() or "upload.bin"
        content_type = file.content_type or "application/octet-stream"
        data, sha256 = await _read_upload_bytes_limited(
            file, max_bytes=int(settings.FILE_SCAN_MAX_BYTES or 0)
        )
        await file.close()
    else:
        data, sha256 = _decode_payload_bytes(
            payload or "",
            is_base64=bool(payload_base64),
            max_bytes=int(settings.FILE_SCAN_MAX_BYTES or 0),
        )
        filename = "payload.bin" if payload_base64 else "payload.txt"
        content_type = (
            "application/octet-stream"
            if payload_base64
            else "text/plain; charset=utf-8"
        )

    scan_timeout_seconds = float(settings.CLAMAV_TIMEOUT_SECONDS or 0) or 8.0
    warmup_wait_seconds = min(10.0, max(2.0, scan_timeout_seconds))

    async def _ensure_clamd_ready() -> None:
        # clamd can be briefly unavailable on cold start or signature reload; wait a bit
        # so users don't have to click "Scan" twice.
        deadline = time.monotonic() + warmup_wait_seconds
        delay = 0.25
        ping_timeout = min(0.5, scan_timeout_seconds)
        while True:
            if await asyncio.to_thread(
                clamd_ping,
                host=settings.CLAMAV_HOST,
                port=settings.CLAMAV_PORT,
                timeout_seconds=ping_timeout,
            ):
                return
            if time.monotonic() >= deadline:
                raise ClamAVConnectionError("clamd is not ready yet")
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 1.0)

    started = time.monotonic()
    try:
        await _ensure_clamd_ready()
        try:
            result = await asyncio.to_thread(
                clamd_scan_bytes,
                data,
                host=settings.CLAMAV_HOST,
                port=settings.CLAMAV_PORT,
                timeout_seconds=scan_timeout_seconds,
            )
        except (ClamAVConnectionError, ClamAVProtocolError):
            # One retry after a short delay for transient clamd startup/reload issues.
            await asyncio.sleep(0.5)
            await _ensure_clamd_ready()
            result = await asyncio.to_thread(
                clamd_scan_bytes,
                data,
                host=settings.CLAMAV_HOST,
                port=settings.CLAMAV_PORT,
                timeout_seconds=scan_timeout_seconds,
            )
    except ClamAVConnectionError as e:
        logger.warning("ClamAV is unavailable: %s", e)
        raise HTTPException(status_code=503, detail="ClamAV is unavailable")
    except ClamAVError as e:
        logger.warning("ClamAV scan failed: %s", e)
        raise HTTPException(status_code=502, detail="ClamAV scan failed")

    duration_ms = int((time.monotonic() - started) * 1000)

    version = None
    if settings.FILE_SCAN_INCLUDE_VERSION:
        try:
            version = clamd_version(
                host=settings.CLAMAV_HOST,
                port=settings.CLAMAV_PORT,
                timeout_seconds=min(2.0, float(settings.CLAMAV_TIMEOUT_SECONDS or 0) or 2.0),
            )
        except ClamAVError:
            version = None

    scanned_at = datetime.now(timezone.utc).isoformat()
    response: dict = {
        "job_id": job_id,
        "scan_id": job_id,
        "status": "completed",
        "submitted_at": submitted_at,
        "scanned_at": scanned_at,
        "input_type": input_type,
        "filename": filename,
        "content_type": content_type,
        "size_bytes": len(data),
        "sha256": sha256,
        "engine": "clamav",
        "verdict": result.verdict,
        "duration_ms": duration_ms,
        "clamav": {
            "host": settings.CLAMAV_HOST,
            "port": settings.CLAMAV_PORT,
            "response": result.raw,
        },
        "type": "file",
    }

    if result.signature:
        response["signature"] = result.signature
    if result.error:
        response["clamav"]["error"] = result.error
    if version:
        response["clamav"]["version"] = version

    stored = False
    if can_store:
        try:
            await _upsert_result(
                job_id,
                status="completed",
                details=response,
                verdict=str(result.verdict or ""),
                error=None,
                extra={
                    "submitted_at": submitted_at,
                    "api_key_hash": api_key_hash or "",
                    "correlation_id": correlation_id,
                    "scanned_at": scanned_at,
                    "size_bytes": len(data),
                    "duration_ms": duration_ms,
                    "type": "file",
                },
                request=request,
            )
            if api_key_hash:
                job_record = build_job_record(
                    api_key_hash_value=api_key_hash,
                    job_id=job_id,
                    submitted_at=submitted_at,
                    status="completed",
                    url=None,
                    scanned_at=scanned_at,
                    updated_at=scanned_at,
                    correlation_id=correlation_id,
                    error=None,
                )
                job_record["type"] = "file"
                job_record["input_type"] = input_type
                job_record["filename"] = filename or ""
                job_record["content_type"] = content_type or ""
                job_record["sha256"] = sha256
                job_record["verdict"] = str(result.verdict or "")
                job_record["signature"] = (
                    str(result.signature or "").strip() if result.signature else ""
                )
                job_record["size_bytes"] = str(len(data))
                job_record["duration_ms"] = str(duration_ms)
                await upsert_job_index_record_async(
                    backend=result_backend,
                    api_key_hash_value=api_key_hash,
                    record=job_record,
                    table_client=table_client,
                    redis_client=redis_client,
                    redis_ttl_seconds=settings.REDIS_RESULT_TTL_SECONDS,
                )
            stored = True
        except Exception as e:
            logger.warning("Failed to persist file scan result: %s", e)

    response["stored"] = stored
    return response
