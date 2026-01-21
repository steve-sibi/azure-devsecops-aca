from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Optional


SCAN_URL_MAX_LENGTH = int(os.getenv("SCAN_URL_MAX_LENGTH", "4096"))
SCAN_SOURCE_MAX_LENGTH = int(os.getenv("SCAN_SOURCE_MAX_LENGTH", "256"))
SCAN_ID_MAX_LENGTH = int(os.getenv("SCAN_ID_MAX_LENGTH", "128"))

SCAN_METADATA_MAX_KEYS = int(os.getenv("SCAN_METADATA_MAX_KEYS", "50"))
SCAN_METADATA_MAX_BYTES = int(os.getenv("SCAN_METADATA_MAX_BYTES", "8192"))
SCAN_METADATA_KEY_MAX_LENGTH = int(os.getenv("SCAN_METADATA_KEY_MAX_LENGTH", "64"))
SCAN_METADATA_STRING_VALUE_MAX_LENGTH = int(
    os.getenv("SCAN_METADATA_STRING_VALUE_MAX_LENGTH", "512")
)

ARTIFACT_PATH_MAX_LENGTH = int(os.getenv("SCAN_ARTIFACT_PATH_MAX_LENGTH", "256"))


@dataclass
class ScanMessageValidationError(ValueError):
    field: str
    message: str

    def __str__(self) -> str:
        if self.field:
            return f"{self.field}: {self.message}"
        return self.message


def _normalize_str(
    value: Any,
    *,
    field: str,
    max_length: int,
    required: bool = False,
    strip: bool = True,
) -> Optional[str]:
    if value is None:
        if required:
            raise ScanMessageValidationError(field=field, message="is required")
        return None
    if not isinstance(value, str):
        raise ScanMessageValidationError(field=field, message="must be a string")
    out = value.strip() if strip else value
    if required and not out:
        raise ScanMessageValidationError(field=field, message="cannot be empty")
    if max_length > 0 and len(out) > max_length:
        raise ScanMessageValidationError(
            field=field, message=f"must be <= {max_length} characters"
        )
    return out


def normalize_metadata(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ScanMessageValidationError(field="metadata", message="must be an object")

    out: dict[str, Any] = {}
    for k, v in value.items():
        if len(out) >= max(0, int(SCAN_METADATA_MAX_KEYS)):
            raise ScanMessageValidationError(
                field="metadata", message=f"must have <= {SCAN_METADATA_MAX_KEYS} keys"
            )
        if not isinstance(k, str):
            raise ScanMessageValidationError(
                field="metadata", message="keys must be strings"
            )
        key = k.strip()
        if not key:
            raise ScanMessageValidationError(
                field="metadata", message="keys cannot be empty"
            )
        if len(key) > max(0, int(SCAN_METADATA_KEY_MAX_LENGTH)):
            raise ScanMessageValidationError(
                field="metadata",
                message=f"key '{key}' must be <= {SCAN_METADATA_KEY_MAX_LENGTH} characters",
            )

        if v is None or isinstance(v, (bool, int, float)):
            out[key] = v
            continue
        if isinstance(v, str):
            val = v.strip()
            if len(val) > max(0, int(SCAN_METADATA_STRING_VALUE_MAX_LENGTH)):
                raise ScanMessageValidationError(
                    field="metadata",
                    message=(
                        f"value for '{key}' must be <= {SCAN_METADATA_STRING_VALUE_MAX_LENGTH} characters"
                    ),
                )
            out[key] = val
            continue

        raise ScanMessageValidationError(
            field="metadata",
            message=(
                f"value for '{key}' must be a string, number, boolean, or null"
            ),
        )

    if SCAN_METADATA_MAX_BYTES > 0:
        encoded = json.dumps(out, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        if len(encoded) > SCAN_METADATA_MAX_BYTES:
            raise ScanMessageValidationError(
                field="metadata",
                message=f"encoded size must be <= {SCAN_METADATA_MAX_BYTES} bytes",
            )
    return out


def validate_scan_task_v1(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ScanMessageValidationError(field="", message="payload must be an object")

    job_id = _normalize_str(
        payload.get("job_id"),
        field="job_id",
        max_length=SCAN_ID_MAX_LENGTH,
        required=True,
    )
    correlation_id = _normalize_str(
        payload.get("correlation_id"),
        field="correlation_id",
        max_length=SCAN_ID_MAX_LENGTH,
        required=False,
    )
    url = _normalize_str(
        payload.get("url"),
        field="url",
        max_length=SCAN_URL_MAX_LENGTH,
        required=True,
    )
    scan_type = _normalize_str(
        payload.get("type") or "url",
        field="type",
        max_length=16,
        required=True,
    )
    scan_type_l = (scan_type or "").lower()
    if scan_type_l not in ("url", "file"):
        raise ScanMessageValidationError(field="type", message="must be 'url' or 'file'")

    source = _normalize_str(
        payload.get("source"),
        field="source",
        max_length=SCAN_SOURCE_MAX_LENGTH,
        required=False,
    )
    submitted_at = _normalize_str(
        payload.get("submitted_at"),
        field="submitted_at",
        max_length=64,
        required=False,
    )

    metadata = normalize_metadata(payload.get("metadata"))

    out: dict[str, Any] = {
        "job_id": job_id,
        "url": url,
        "type": scan_type_l,
        "metadata": metadata,
    }
    if correlation_id:
        out["correlation_id"] = correlation_id
    if source:
        out["source"] = source
    if submitted_at:
        out["submitted_at"] = submitted_at
    return out


def validate_scan_artifact_v1(payload: Any) -> dict[str, Any]:
    out = validate_scan_task_v1(payload)

    artifact_path = _normalize_str(
        payload.get("artifact_path"),
        field="artifact_path",
        max_length=ARTIFACT_PATH_MAX_LENGTH,
        required=False,
    )
    artifact_sha256 = _normalize_str(
        payload.get("artifact_sha256"),
        field="artifact_sha256",
        max_length=128,
        required=False,
        strip=True,
    )
    artifact_size_bytes = payload.get("artifact_size_bytes")
    if artifact_size_bytes is not None:
        if isinstance(artifact_size_bytes, bool):
            raise ScanMessageValidationError(
                field="artifact_size_bytes", message="must be an integer"
            )
        try:
            size_int = int(artifact_size_bytes)
        except Exception as e:
            raise ScanMessageValidationError(
                field="artifact_size_bytes", message="must be an integer"
            ) from e
        if size_int < 0:
            raise ScanMessageValidationError(
                field="artifact_size_bytes", message="must be >= 0"
            )
        out["artifact_size_bytes"] = size_int

    download = payload.get("download")
    if download is not None:
        if not isinstance(download, dict):
            raise ScanMessageValidationError(field="download", message="must be an object")
        out["download"] = download

    if artifact_path:
        out["artifact_path"] = artifact_path
    if artifact_sha256:
        out["artifact_sha256"] = artifact_sha256

    return out

