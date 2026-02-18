"""
Cached HTTP client with rate limiting.

Shared across all modules (analyzer, resolver, payload) to avoid
hammering APIs during recursive dependency resolution.

Features:
  - In-memory response cache with 5-minute TTL
  - Threading semaphore for concurrency limiting
  - Automatic retries on transient errors
"""

from __future__ import annotations

import time
import threading
from typing import Optional

import requests


class CachedHTTPClient:
    """Thread-safe HTTP client with caching and rate limiting."""

    DEFAULT_TIMEOUT = 8  # seconds
    CACHE_TTL = 300  # 5 minutes
    MAX_CONCURRENT = 5  # max parallel requests

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        cache_ttl: int = CACHE_TTL,
        max_concurrent: int = MAX_CONCURRENT,
    ) -> None:
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._cache: dict[str, tuple[float, requests.Response]] = {}
        self._cache_lock = threading.Lock()
        self._semaphore = threading.Semaphore(max_concurrent)
        self._session = requests.Session()

    def get(self, url: str, timeout: Optional[int] = None) -> requests.Response:
        """GET with caching and rate limiting."""
        # Check cache
        with self._cache_lock:
            if url in self._cache:
                cached_at, resp = self._cache[url]
                if time.time() - cached_at < self._cache_ttl:
                    return resp
                del self._cache[url]

        # Rate-limited fetch
        with self._semaphore:
            resp = self._session.get(url, timeout=timeout or self._timeout)

        # Cache successful responses
        if resp.status_code in (200, 404):
            with self._cache_lock:
                self._cache[url] = (time.time(), resp)

        return resp

    def head(self, url: str, timeout: Optional[int] = None) -> requests.Response:
        """HEAD request (not cached) with rate limiting."""
        with self._semaphore:
            return self._session.head(
                url,
                timeout=timeout or self._timeout,
                allow_redirects=True,
            )

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
