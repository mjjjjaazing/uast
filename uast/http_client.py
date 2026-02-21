"""
Cached HTTP client with rate limiting and retry.

Shared across all modules (analyzer, resolver, payload) to avoid
hammering APIs during recursive dependency resolution.

Features:
  - In-memory response cache with configurable TTL
  - Threading semaphore for concurrency limiting
  - Automatic retries with exponential backoff on transient errors
  - Proxy support via HTTP_PROXY / HTTPS_PROXY environment variables
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

import requests

logger = logging.getLogger("uast.http")

# Status codes that indicate transient server errors (worth retrying)
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class CachedHTTPClient:
    """Thread-safe HTTP client with caching, rate limiting, and retry."""

    DEFAULT_TIMEOUT = 8  # seconds
    CACHE_TTL = 300  # 5 minutes
    MAX_CONCURRENT = 5  # max parallel requests
    MAX_RETRIES = 3
    BACKOFF_BASE = 1.0  # seconds (1s, 2s, 4s)
    MAX_CACHE_SIZE = 1000  # LRU eviction threshold
    USER_AGENT = "UAST/0.1.0"
    ALLOWED_SCHEMES = ("http", "https")

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        cache_ttl: int = CACHE_TTL,
        max_concurrent: int = MAX_CONCURRENT,
        max_retries: int = MAX_RETRIES,
    ) -> None:
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._max_retries = max_retries
        self._cache: dict[str, tuple[float, requests.Response]] = {}
        self._cache_lock = threading.Lock()
        self._semaphore = threading.Semaphore(max_concurrent)
        self._session = requests.Session()
        self._session.headers["User-Agent"] = self.USER_AGENT

    def _validate_url(self, url: str) -> None:
        """Reject non-http(s) URLs to prevent SSRF."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in self.ALLOWED_SCHEMES:
            raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r} (only http/https allowed)")
        if not parsed.hostname:
            raise ValueError(f"Invalid URL: no hostname in {url!r}")

    def _evict_cache(self) -> None:
        """Evict oldest cache entries when MAX_CACHE_SIZE is exceeded."""
        if len(self._cache) <= self.MAX_CACHE_SIZE:
            return
        # Evict oldest entries (by cached_at timestamp)
        sorted_keys = sorted(self._cache, key=lambda k: self._cache[k][0])
        evict_count = len(self._cache) - self.MAX_CACHE_SIZE
        for key in sorted_keys[:evict_count]:
            del self._cache[key]

    def get(self, url: str, timeout: Optional[int] = None) -> requests.Response:
        """GET with caching, rate limiting, and retry."""
        self._validate_url(url)

        # Check cache
        with self._cache_lock:
            if url in self._cache:
                cached_at, resp = self._cache[url]
                if time.time() - cached_at < self._cache_ttl:
                    logger.debug("Cache hit: %s", url)
                    return resp
                del self._cache[url]

        # Rate-limited fetch with retry
        effective_timeout = timeout or self._timeout
        resp = self._request_with_retry("GET", url, effective_timeout)
        logger.debug("HTTP %d: %s", resp.status_code, url)

        # Cache successful responses and 404s
        if resp.status_code in (200, 404):
            with self._cache_lock:
                self._cache[url] = (time.time(), resp)
                self._evict_cache()

        return resp

    def head(self, url: str, timeout: Optional[int] = None) -> requests.Response:
        """HEAD request (not cached) with rate limiting."""
        self._validate_url(url)
        with self._semaphore:
            return self._session.head(
                url,
                timeout=timeout or self._timeout,
                allow_redirects=True,
            )

    def _request_with_retry(
        self, method: str, url: str, timeout: int
    ) -> requests.Response:
        """Execute an HTTP request with exponential backoff retry."""
        last_exc: Optional[requests.RequestException] = None

        for attempt in range(self._max_retries):
            try:
                logger.debug("HTTP %s (attempt %d): %s", method, attempt + 1, url)
                with self._semaphore:
                    resp = self._session.request(method, url, timeout=timeout)

                # Don't retry deterministic client errors (400, 401, 403, 404)
                if resp.status_code not in RETRYABLE_STATUS_CODES:
                    return resp

                # Retryable server error — backoff and retry
                delay = self.BACKOFF_BASE * (2 ** attempt)
                logger.info(
                    "HTTP %d for %s — retrying in %.1fs (attempt %d/%d)",
                    resp.status_code, url, delay, attempt + 1, self._max_retries,
                )
                time.sleep(delay)

            except (requests.ConnectionError, requests.Timeout) as e:
                last_exc = e
                delay = self.BACKOFF_BASE * (2 ** attempt)
                logger.info(
                    "HTTP %s failed for %s: %s — retrying in %.1fs (attempt %d/%d)",
                    method, url, type(e).__name__, delay, attempt + 1, self._max_retries,
                )
                time.sleep(delay)

        # All retries exhausted — return last response or raise last exception
        if last_exc is not None:
            raise last_exc
        return resp  # type: ignore[possibly-undefined]

    def clear_cache(self) -> None:
        """Clear the response cache."""
        with self._cache_lock:
            self._cache.clear()

    @property
    def cache_size(self) -> int:
        with self._cache_lock:
            return len(self._cache)


# Module-level singleton — all modules share this instance
http_client = CachedHTTPClient()
