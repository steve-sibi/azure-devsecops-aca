from __future__ import annotations

import logging
import os
import socket
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

from common.url_validation import UrlValidationError, validate_public_https_url

logger = logging.getLogger("aca.screenshot")


@dataclass(frozen=True)
class ScreenshotCaptureResult:
    content_type: str
    image_bytes: bytes
    metrics: dict


def _truncate(value: str, max_len: int = 240) -> str:
    text = (value or "").strip()
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "y", "on")


def _parse_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _screenshot_type(fmt: str) -> tuple[str, str]:
    f = (fmt or "").strip().lower()
    if f == "png":
        return "png", "image/png"
    return "jpeg", "image/jpeg"


@lru_cache(maxsize=2048)
def _is_allowed_host(host: str, *, block_private_networks: bool) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    try:
        validate_public_https_url(
            f"https://{h}", block_private_networks=block_private_networks
        )
        return True
    except UrlValidationError:
        return False
    except socket.gaierror:
        return False
    except Exception:
        return False


def _allow_request_url(url: str, *, block_private_networks: bool) -> bool:
    parsed = urlparse(url or "")
    scheme = (parsed.scheme or "").lower()

    # Allow internal browser URLs.
    if scheme in ("about", "chrome", "chrome-error", "data", "blob"):
        return True

    # Only allow HTTPS for external network requests.
    if scheme != "https":
        return False

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return False

    # Keep the worker locked to HTTPS/443 (explicit :443 is fine). This prevents using the
    # browser as a generic port-scanner.
    port = parsed.port
    if port not in (None, 443):
        return False

    return _is_allowed_host(host, block_private_networks=block_private_networks)


def capture_website_screenshot(
    url: str,
    *,
    block_private_networks: bool,
    timeout_seconds: float,
    viewport_width: int,
    viewport_height: int,
    full_page: bool,
    image_format: str,
    jpeg_quality: int,
) -> tuple[Optional[ScreenshotCaptureResult], Optional[str]]:
    enabled = _env_flag("CAPTURE_SCREENSHOTS", False)
    if not enabled:
        return None, "disabled"

    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as e:
        logger.warning("Playwright not available; screenshots disabled: %s", e)
        return None, f"playwright_unavailable:{_truncate(str(e))}"

    screenshot_type, content_type = _screenshot_type(image_format)
    total_timeout_ms = max(1, int(timeout_seconds * 1000))
    deadline = time.monotonic() + max(0.25, float(timeout_seconds or 0))

    def remaining_ms() -> int:
        return max(1, int((deadline - time.monotonic()) * 1000))

    # Keep routing logic simple and safe: only allow public HTTPS (and browser internal schemes).
    allowed_requests = 0
    blocked_requests = 0
    allowed_by_type: dict[str, int] = {}
    blocked_by_type: dict[str, int] = {}
    blocked_examples: list[dict] = []

    def route_handler(route, request) -> None:
        nonlocal allowed_requests, blocked_requests
        req_url = getattr(request, "url", "") or ""
        rtype = str(getattr(request, "resource_type", "") or "").strip().lower() or "unknown"
        if _allow_request_url(req_url, block_private_networks=block_private_networks):
            allowed_requests += 1
            allowed_by_type[rtype] = int(allowed_by_type.get(rtype, 0)) + 1
            route.continue_()
        else:
            blocked_requests += 1
            blocked_by_type[rtype] = int(blocked_by_type.get(rtype, 0)) + 1
            if len(blocked_examples) < 12:
                blocked_examples.append({"url": _truncate(req_url, 240), "type": rtype})
            route.abort()

    image_bytes: Optional[bytes] = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                ],
            )
            user_agent = os.getenv("SCREENSHOT_USER_AGENT") or (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            )
            context = browser.new_context(
                viewport={"width": int(viewport_width), "height": int(viewport_height)},
                user_agent=user_agent,
                locale=os.getenv("SCREENSHOT_LOCALE") or "en-US",
            )
            context.route("**/*", route_handler)
            page = context.new_page()
            page.set_default_timeout(total_timeout_ms)
            page.set_default_navigation_timeout(total_timeout_ms)
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=remaining_ms())
            except PlaywrightTimeoutError:
                # Take the best-effort screenshot of whatever loaded.
                pass

            # Give stylesheets/fonts a chance to apply (best-effort, bounded by overall timeout).
            try:
                page.wait_for_load_state("load", timeout=min(remaining_ms(), 6000))
            except PlaywrightTimeoutError:
                pass
            except Exception:
                pass

            try:
                page.wait_for_function(
                    "() => !document.fonts || document.fonts.status === 'loaded'",
                    timeout=min(remaining_ms(), 2000),
                )
            except PlaywrightTimeoutError:
                pass
            except Exception:
                pass

            try:
                page.wait_for_load_state(
                    "networkidle", timeout=min(remaining_ms(), 2000)
                )
            except PlaywrightTimeoutError:
                pass
            except Exception:
                pass

            # Final settle window for late layout (bounded by overall timeout).
            settle_ms = max(0, _parse_int("SCREENSHOT_SETTLE_MS", 750))
            settle_ms = min(settle_ms, max(0, remaining_ms() - 1))
            if settle_ms > 0:
                page.wait_for_timeout(settle_ms)

            kwargs = {"type": screenshot_type, "full_page": bool(full_page)}
            if screenshot_type == "jpeg":
                kwargs["quality"] = max(1, min(100, int(jpeg_quality)))
            image_bytes = page.screenshot(**kwargs)
            try:
                context.close()
            finally:
                browser.close()
    except Exception as e:
        logger.info("Screenshot capture failed: %s", e)
        return None, f"capture_failed:{_truncate(str(e))}"

    if not isinstance(image_bytes, (bytes, bytearray)) or not image_bytes:
        return None, "empty_image"

    metrics = {
        "allowed_requests": int(allowed_requests),
        "blocked_requests": int(blocked_requests),
        "allowed_by_type": allowed_by_type,
        "blocked_by_type": blocked_by_type,
        "blocked_examples": blocked_examples,
    }
    return (
        ScreenshotCaptureResult(
            content_type=content_type, image_bytes=bytes(image_bytes), metrics=metrics
        ),
        None,
    )
