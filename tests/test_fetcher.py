"""
tests/test_fetcher.py
=====================
Unit tests for :mod:`core.fetcher` — OTX IOC collection.

Uses ``requests_mock`` to simulate OTX API responses without network
access.
"""

import pytest
import requests
import requests_mock as rm

from core.fetcher import OTX_BASE_URL, fetch_iocs_from_otx


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _patch_api_key(monkeypatch):
    """Ensure OTX_API_KEY is set for all tests in this module."""
    monkeypatch.setattr("core.fetcher.OTX_API_KEY", "test-key-123")


# -----------------------------------------------------------------------
# Success path
# -----------------------------------------------------------------------
class TestFetchSuccess:
    """Tests for successful OTX API responses."""

    def test_returns_iocs_from_pulses(self):
        """IOCs are extracted and deduplicated from pulse indicators."""
        mock_response = {
            "results": [
                {
                    "indicators": [
                        {"indicator": "1.2.3.4", "type": "IPv4"},
                        {"indicator": "evil.com", "type": "domain"},
                        {"indicator": "1.2.3.4", "type": "IPv4"},
                    ]
                }
            ]
        }
        with rm.Mocker() as m:
            m.get(OTX_BASE_URL, json=mock_response, status_code=200)
            result = fetch_iocs_from_otx(limit=1)

        assert len(result) == 2
        assert result[0]["indicator"] == "1.2.3.4"
        assert result[1]["indicator"] == "evil.com"

    def test_empty_pulses_returns_empty_list(self):
        """An empty pulse list yields an empty IOC list."""
        with rm.Mocker() as m:
            m.get(
                OTX_BASE_URL,
                json={"results": []},
                status_code=200,
            )
            result = fetch_iocs_from_otx(limit=1)

        assert result == []

    def test_multiple_pulses_merged(self):
        """IOCs across multiple pulses are merged and deduplicated."""
        mock_response = {
            "results": [
                {
                    "indicators": [
                        {"indicator": "10.0.0.1", "type": "IPv4"},
                    ]
                },
                {
                    "indicators": [
                        {"indicator": "bad.org", "type": "domain"},
                        {"indicator": "10.0.0.1", "type": "IPv4"},
                    ]
                },
            ]
        }
        with rm.Mocker() as m:
            m.get(OTX_BASE_URL, json=mock_response, status_code=200)
            result = fetch_iocs_from_otx(limit=5)

        assert len(result) == 2


# -----------------------------------------------------------------------
# Failure path
# -----------------------------------------------------------------------
class TestFetchFailure:
    """Tests for OTX API error conditions."""

    def test_http_500_returns_empty_list(self):
        """A server error returns an empty list (no crash)."""
        with rm.Mocker() as m:
            m.get(OTX_BASE_URL, status_code=500)
            result = fetch_iocs_from_otx(limit=1)

        assert result == []

    def test_missing_api_key_returns_empty_list(self, monkeypatch):
        """Missing OTX_API_KEY logs warning and returns empty list."""
        monkeypatch.setattr("core.fetcher.OTX_API_KEY", "")
        result = fetch_iocs_from_otx(limit=1)
        assert result == []

    def test_connection_error_returns_empty_list(self):
        """A network error returns an empty list gracefully."""
        with rm.Mocker() as m:
            m.get(
                OTX_BASE_URL,
                exc=requests.exceptions.ConnectionError(
                    "DNS failure"
                ),
            )
            result = fetch_iocs_from_otx(limit=1)

        assert result == []
