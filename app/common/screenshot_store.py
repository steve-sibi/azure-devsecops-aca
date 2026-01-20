from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ScreenshotData:
    content_type: str
    bytes: bytes


def redis_screenshot_key(prefix: str, job_id: str) -> str:
    return f"{prefix}{job_id}"


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str) -> bytes:
    compact = "".join((value or "").split())
    return base64.b64decode(compact, validate=True)


def store_screenshot_redis_sync(
    *,
    redis_client,
    key: str,
    image_bytes: bytes,
    content_type: str,
    ttl_seconds: int = 0,
) -> None:
    redis_client.hset(
        key,
        mapping={
            "content_type": str(content_type or "application/octet-stream"),
            "b64": _b64encode(image_bytes),
        },
    )
    if ttl_seconds > 0:
        redis_client.expire(key, int(ttl_seconds))


async def get_screenshot_redis_async(*, redis_client, key: str) -> Optional[ScreenshotData]:
    mapping = await redis_client.hgetall(key)
    if not mapping:
        return None
    b64 = mapping.get("b64")
    if not isinstance(b64, str) or not b64.strip():
        return None
    content_type = mapping.get("content_type")
    if not isinstance(content_type, str) or not content_type.strip():
        content_type = "application/octet-stream"
    try:
        return ScreenshotData(content_type=content_type, bytes=_b64decode(b64))
    except Exception:
        return None


def store_screenshot_blob_sync(
    *,
    conn_str: str,
    container: str,
    blob_name: str,
    image_bytes: bytes,
    content_type: str,
) -> None:
    from azure.core.exceptions import ResourceExistsError
    from azure.storage.blob import BlobServiceClient, ContentSettings

    service = BlobServiceClient.from_connection_string(conn_str)
    try:
        container_client = service.get_container_client(container)
        try:
            container_client.create_container()
        except ResourceExistsError:
            pass

        blob_client = container_client.get_blob_client(blob_name)
        blob_client.upload_blob(
            image_bytes,
            overwrite=True,
            content_settings=ContentSettings(
                content_type=content_type or "application/octet-stream"
            ),
        )
    finally:
        try:
            service.close()
        except Exception:
            pass

            
async def get_screenshot_blob_async(
    *,
    blob_service_client,
    container: str,
    blob_name: str,
) -> Optional[ScreenshotData]:
    from azure.core.exceptions import ResourceNotFoundError

    container_client = blob_service_client.get_container_client(container)
    blob_client = container_client.get_blob_client(blob_name)
    try:
        props = await blob_client.get_blob_properties()
        stream = await blob_client.download_blob()
        data = await stream.readall()
    except ResourceNotFoundError:
        return None
    except Exception:
        return None

    content_type = getattr(getattr(props, "content_settings", None), "content_type", None)
    if not isinstance(content_type, str) or not content_type.strip():
        content_type = "application/octet-stream"
    return ScreenshotData(content_type=content_type, bytes=data or b"")
