"""
tests/test_enricher.py
======================
Unit tests for :mod:`core.enricher` — VirusTotal IOC enrichment.

Uses ``requests_mock`` to simulate VirusTotal API responses.
"""

import pytest
import requests_mock as rm

from core.enricher import VT_BASE_URL, _classify_ioc, enrich_with_virustotal


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _patch_vt_key(monkeypatch):
    """Ensure VT_API_KEY is set for all tests in this module."""
    monkeypatch.setattr("core.enricher.VT_API_KEY", "test-vt-key-456")


# -----------------------------------------------------------------------
# IOC classification
# -----------------------------------------------------------------------
class TestClassifyIOC:
    """Tests for the _classify_ioc helper."""

    def test_ipv4_address(self):
        """Valid IPv4 addresses are classified as 'ip'."""
        assert _classify_ioc("192.168.1.1") == "ip"
        assert _classify_ioc("8.8.8.8") == "ip"

    def test_domain(self):
        """Valid domain names are classified as 'domain'."""
        assert _classify_ioc("evil.com") == "domain"
        assert _classify_ioc("sub.domain.co.uk") == "domain"

    def test_hash(self):
        """MD5, SHA-1, and SHA-256 hashes are classified as 'hash'."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha256 = (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        assert _classify_ioc(md5) == "hash"
        assert _classify_ioc(sha256) == "hash"

    def test_unsupported_returns_none(self):
        """Non-classifiable values return None."""
        assert _classify_ioc("not an ioc!!") is None


# -----------------------------------------------------------------------
# Enrichment — success paths
# -----------------------------------------------------------------------
class TestEnrichSuccess:
    """Tests for successful VirusTotal enrichment."""

    def _vt_response(self, malicious=5, suspicious=2, harmless=60, undetected=3):
        """Build a mock VT API response payload."""
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                    }
                }
            }
        }

    def test_enrich_ip_address(self):
        """IPv4 IOC enrichment returns correct stats."""
        ioc = {"indicator": "1.2.3.4", "type": "IPv4"}
        with rm.Mocker() as m:
            m.get(
                f"{VT_BASE_URL}/ip_addresses/1.2.3.4",
                json=self._vt_response(malicious=10),
                status_code=200,
            )
            result = enrich_with_virustotal(ioc)

        assert result is not None
        assert result["malicious"] == 10
        assert result["source"] == "VirusTotal"
        assert result["indicator"] == "1.2.3.4"

    def test_enrich_domain(self):
        """Domain IOC enrichment returns correct stats."""
        ioc = {"indicator": "evil.com", "type": "domain"}
        with rm.Mocker() as m:
            m.get(
                f"{VT_BASE_URL}/domains/evil.com",
                json=self._vt_response(malicious=3, suspicious=1),
                status_code=200,
            )
            result = enrich_with_virustotal(ioc)

        assert result is not None
        assert result["malicious"] == 3
        assert result["suspicious"] == 1

    def test_enrich_string_input(self):
        """Plain string IOC (not dict) is also accepted."""
        with rm.Mocker() as m:
            m.get(
                f"{VT_BASE_URL}/ip_addresses/8.8.8.8",
                json=self._vt_response(malicious=0),
                status_code=200,
            )
            result = enrich_with_virustotal("8.8.8.8")

        assert result is not None
        assert result["malicious"] == 0


# -----------------------------------------------------------------------
# Enrichment — failure paths
# -----------------------------------------------------------------------
class TestEnrichFailure:
    """Tests for VirusTotal error conditions."""

    def test_missing_api_key(self, monkeypatch):
        """Missing VT_API_KEY returns None."""
        monkeypatch.setattr("core.enricher.VT_API_KEY", "")
        result = enrich_with_virustotal({"indicator": "1.2.3.4"})
        assert result is None

    def test_unsupported_ioc_type(self):
        """Unclassifiable IOC returns None."""
        result = enrich_with_virustotal({"indicator": "not-an-ioc!!"})
        assert result is None

    def test_http_404_returns_zeros(self):
        """VT 404 (not found) returns zero-count enrichment."""
        ioc = {"indicator": "9.9.9.9", "type": "IPv4"}
        with rm.Mocker() as m:
            m.get(
                f"{VT_BASE_URL}/ip_addresses/9.9.9.9",
                status_code=404,
            )
            result = enrich_with_virustotal(ioc)

        assert result is not None
        assert result["malicious"] == 0

    def test_http_500_returns_none(self):
        """VT 500 server error returns None."""
        ioc = {"indicator": "1.1.1.1", "type": "IPv4"}
        with rm.Mocker() as m:
            m.get(
                f"{VT_BASE_URL}/ip_addresses/1.1.1.1",
                status_code=500,
            )
            result = enrich_with_virustotal(ioc)

        assert result is None
