"""FastAPI security dependencies: API key authentication and upload rate limiting."""

import hmac
import logging
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import Depends, Header, HTTPException, Request, status

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter keyed by client identifier."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        """Record a request and return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= max_requests:
                retry_after = max(1, int(bucket[0] + window_seconds - now) + 1)
                return False, retry_after
            bucket.append(now)
            return True, 0

    def reset(self) -> None:
        """Clear all tracked request timestamps (used in tests)."""
        with self._lock:
            self._hits.clear()


upload_rate_limiter = SlidingWindowRateLimiter()


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> str:
    """Validate X-API-Key header on write endpoints using constant-time comparison."""
    if not settings.api_key:
        logger.error("API_KEY environment variable is not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Write endpoints are unavailable until API_KEY is configured.",
        )

    if not x_api_key or not hmac.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )
    return x_api_key


def enforce_upload_rate_limit(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> None:
    """Enforce sliding-window rate limits on the log upload endpoint."""
    client_host = request.client.host if request.client else "unknown"
    allowed, retry_after = upload_rate_limiter.check(
        key=client_host,
        max_requests=settings.upload_rate_limit_requests,
        window_seconds=settings.upload_rate_limit_window_seconds,
    )
    if not allowed:
        logger.warning("Upload rate limit exceeded for client=%s", client_host)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Upload rate limit exceeded. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )
