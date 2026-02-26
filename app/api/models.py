from __future__ import annotations

from typing import Optional

from common.scan_messages import SCAN_SOURCE_MAX_LENGTH, SCAN_URL_MAX_LENGTH
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(
        ..., description="HTTPS URL to scan", max_length=SCAN_URL_MAX_LENGTH
    )
    type: str = Field("url", pattern="^(url|file)$", max_length=16)
    source: Optional[str] = Field(
        None,
        description="Optional source identifier",
        max_length=SCAN_SOURCE_MAX_LENGTH,
    )
    metadata: Optional[dict] = Field(None, description="Optional metadata")
    force: bool = Field(False, description="Force a re-scan (ignore URL dedupe cache)")
    visibility: Optional[str] = Field(
        None,
        description="URL scan visibility: 'shared' (cacheable) or 'private' (no cache reuse)",
        max_length=16,
        pattern="^(shared|private)$",
    )


class PubSubNegotiateRequest(BaseModel):
    job_id: str = Field(..., description="Scan job id to subscribe to")


class ApiKeyMintRequest(BaseModel):
    label: Optional[str] = Field(
        None,
        description="Optional human-readable label",
        max_length=80,
    )
    read_rpm: Optional[int] = Field(
        None,
        ge=1,
        le=100000,
        description="Optional read limit override for this key",
    )
    write_rpm: Optional[int] = Field(
        None,
        ge=1,
        le=100000,
        description="Optional write limit override for this key",
    )
    ttl_days: Optional[int] = Field(
        None,
        ge=1,
        le=3650,
        description="Optional TTL in days (expires_at set server-side)",
    )
    is_admin: bool = Field(
        False,
        description="Whether the minted key can access admin endpoints",
    )
