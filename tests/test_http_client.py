"""
Tests for the uast HTTP client with caching, rate limiting, and retry.

Covers:
  - Response caching (hit/miss/expiry)
  - Retry with exponential backoff
  - Retryable vs non-retryable status codes
  - Connection error handling
  - Cache operations
"""

import time
from unittest.mock import patch, MagicMock

import pytest
import requests

from uast.http_client import CachedHTTPClient, RETRYABLE_STATUS_CODES


class TestCachedHTTPClient:

    def _make_client(self, **kwargs) -> CachedHTTPClient:
        return CachedHTTPClient(
            timeout=5,
            cache_ttl=kwargs.get("cache_ttl", 300),
            max_concurrent=kwargs.get("max_concurrent", 5),
            max_retries=kwargs.get("max_retries", 3),
        )

    def _mock_response(self, status_code: int = 200, json_data: dict = None) -> MagicMock:
        resp = MagicMock(spec=requests.Response)
        resp.status_code = status_code
        resp.json.return_value = json_data or {}
        return resp

    def test_get_returns_response(self):
        client = self._make_client()
        resp = self._mock_response(200, {"data": "test"})
        with patch.object(client._session, "request", return_value=resp):
            result = client.get("https://example.com/api")
        assert result.status_code == 200

    def test_get_caches_200_responses(self):
        client = self._make_client()
        resp = self._mock_response(200)
        with patch.object(client._session, "request", return_value=resp) as mock_req:
            client.get("https://example.com/api")
            client.get("https://example.com/api")
            # Second call should hit cache, not make a new request
            assert mock_req.call_count == 1

    def test_get_caches_404_responses(self):
        client = self._make_client()
        resp = self._mock_response(404)
        with patch.object(client._session, "request", return_value=resp) as mock_req:
            client.get("https://example.com/missing")
            client.get("https://example.com/missing")
            assert mock_req.call_count == 1

    def test_cache_miss_after_ttl(self):
        client = self._make_client(cache_ttl=0)  # Immediately expire
        resp = self._mock_response(200)
        with patch.object(client._session, "request", return_value=resp) as mock_req:
            client.get("https://example.com/api")
            time.sleep(0.01)
            client.get("https://example.com/api")
            # Both calls should hit the network since cache_ttl=0
            assert mock_req.call_count == 2

    def test_does_not_cache_500_responses(self):
        client = self._make_client(max_retries=1)
        resp = self._mock_response(500)
        with patch.object(client._session, "request", return_value=resp) as mock_req:
            client.get("https://example.com/api")
            assert client.cache_size == 0

    def test_clear_cache(self):
        client = self._make_client()
        resp = self._mock_response(200)
        with patch.object(client._session, "request", return_value=resp):
            client.get("https://example.com/api")
        assert client.cache_size == 1
        client.clear_cache()
        assert client.cache_size == 0

    @patch("uast.http_client.time.sleep")  # Don't actually sleep in tests
    def test_retry_on_500(self, mock_sleep):
        client = self._make_client(max_retries=3)
        fail_resp = self._mock_response(500)
        ok_resp = self._mock_response(200)
        with patch.object(
            client._session, "request", side_effect=[fail_resp, fail_resp, ok_resp]
        ) as mock_req:
            result = client.get("https://example.com/api")
            assert result.status_code == 200
            assert mock_req.call_count == 3

    @patch("uast.http_client.time.sleep")
    def test_retry_on_429(self, mock_sleep):
        client = self._make_client(max_retries=2)
        rate_resp = self._mock_response(429)
        ok_resp = self._mock_response(200)
        with patch.object(
            client._session, "request", side_effect=[rate_resp, ok_resp]
        ):
            result = client.get("https://example.com/api")
            assert result.status_code == 200

    @patch("uast.http_client.time.sleep")
    def test_no_retry_on_400(self, mock_sleep):
        client = self._make_client(max_retries=3)
        resp = self._mock_response(400)
        with patch.object(client._session, "request", return_value=resp) as mock_req:
            result = client.get("https://example.com/api")
            assert result.status_code == 400
            assert mock_req.call_count == 1  # No retry

    @patch("uast.http_client.time.sleep")
    def test_no_retry_on_404(self, mock_sleep):
        client = self._make_client(max_retries=3)
        resp = self._mock_response(404)
        with patch.object(client._session, "request", return_value=resp) as mock_req:
            result = client.get("https://example.com/api")
            assert result.status_code == 404
            assert mock_req.call_count == 1  # No retry

    @patch("uast.http_client.time.sleep")
    def test_retry_on_connection_error(self, mock_sleep):
        client = self._make_client(max_retries=3)
        ok_resp = self._mock_response(200)
        with patch.object(
            client._session,
            "request",
            side_effect=[requests.ConnectionError("refused"), ok_resp],
        ):
            result = client.get("https://example.com/api")
            assert result.status_code == 200

    @patch("uast.http_client.time.sleep")
    def test_retry_on_timeout(self, mock_sleep):
        client = self._make_client(max_retries=3)
        ok_resp = self._mock_response(200)
        with patch.object(
            client._session,
            "request",
            side_effect=[requests.Timeout("timed out"), ok_resp],
        ):
            result = client.get("https://example.com/api")
            assert result.status_code == 200

    @patch("uast.http_client.time.sleep")
    def test_raises_after_all_retries_exhausted(self, mock_sleep):
        client = self._make_client(max_retries=2)
        with patch.object(
            client._session,
            "request",
            side_effect=requests.ConnectionError("down"),
        ):
            with pytest.raises(requests.ConnectionError):
                client.get("https://example.com/api")

    @patch("uast.http_client.time.sleep")
    def test_exponential_backoff_timing(self, mock_sleep):
        client = self._make_client(max_retries=3)
        fail_resp = self._mock_response(503)
        ok_resp = self._mock_response(200)
        with patch.object(
            client._session, "request", side_effect=[fail_resp, fail_resp, ok_resp]
        ):
            client.get("https://example.com/api")
            # Check backoff delays: 1s, 2s
            assert mock_sleep.call_count == 2
            delays = [call.args[0] for call in mock_sleep.call_args_list]
            assert delays[0] == 1.0  # 1 * 2^0
            assert delays[1] == 2.0  # 1 * 2^1

    def test_head_request(self):
        client = self._make_client()
        resp = self._mock_response(200)
        with patch.object(client._session, "head", return_value=resp):
            result = client.head("https://example.com/api")
            assert result.status_code == 200

    def test_retryable_status_codes(self):
        assert 429 in RETRYABLE_STATUS_CODES
        assert 500 in RETRYABLE_STATUS_CODES
        assert 502 in RETRYABLE_STATUS_CODES
        assert 503 in RETRYABLE_STATUS_CODES
        assert 504 in RETRYABLE_STATUS_CODES
        assert 400 not in RETRYABLE_STATUS_CODES
        assert 404 not in RETRYABLE_STATUS_CODES
