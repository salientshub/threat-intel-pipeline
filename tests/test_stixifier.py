"""
tests/test_stixifier.py
=======================
Unit tests for :mod:`core.stixifier` — STIX 2.1 conversion.

Validates STIX output structure, kill-chain phases, severity mapping,
and dynamic MITRE ATT&CK technique assignment.
"""

import stix2

from core.stixifier import (
    _build_pattern,
    _classify_severity,
    _compute_confidence,
    _map_mitre,
    bundle_indicators,
    create_stix_indicator,
)


# -----------------------------------------------------------------------
# Pattern building
# -----------------------------------------------------------------------
class TestBuildPattern:
    """Tests for STIX pattern construction."""

    def test_ipv4_pattern(self):
        """IPv4 IOC produces correct STIX pattern."""
        ioc = {"indicator": "1.2.3.4", "type": "IPv4"}
        assert _build_pattern(ioc) == "[ipv4-addr:value = '1.2.3.4']"

    def test_domain_pattern(self):
        """Domain IOC produces correct STIX pattern."""
        ioc = {"indicator": "evil.com", "type": "domain"}
        pattern = _build_pattern(ioc)
        assert pattern == "[domain-name:value = 'evil.com']"

    def test_url_pattern(self):
        """URL IOC produces correct STIX pattern."""
        ioc = {"indicator": "http://bad.com/c2", "type": "url"}
        pattern = _build_pattern(ioc)
        assert pattern == "[url:value = 'http://bad.com/c2']"

    def test_hash_pattern(self):
        """File hash IOC produces correct STIX pattern."""
        ioc = {"indicator": "abc123", "type": "FileHash-SHA256"}
        pattern = _build_pattern(ioc)
        assert "file:hashes" in pattern

    def test_fallback_pattern(self):
        """Unknown type falls back to domain pattern."""
        ioc = {"indicator": "something.weird", "type": "unknown"}
        pattern = _build_pattern(ioc)
        assert "domain-name" in pattern


# -----------------------------------------------------------------------
# Severity classification
# -----------------------------------------------------------------------
class TestClassifySeverity:
    """Tests for severity tier mapping."""

    def test_critical(self):
        """malicious > 10 yields Critical."""
        assert _classify_severity(15) == "Critical"

    def test_high(self):
        """malicious 6-10 yields High."""
        assert _classify_severity(8) == "High"

    def test_medium(self):
        """malicious 1-5 yields Medium."""
        assert _classify_severity(3) == "Medium"

    def test_low(self):
        """malicious == 0 yields Low."""
        assert _classify_severity(0) == "Low"


# -----------------------------------------------------------------------
# MITRE ATT&CK mapping
# -----------------------------------------------------------------------
class TestMitreMapping:
    """Tests for dynamic MITRE technique assignment."""

    def test_high_malicious_maps_to_t1071(self):
        """malicious > 5 maps to T1071 C2."""
        tech_id, _, phase = _map_mitre(10)
        assert tech_id == "T1071"
        assert phase == "command-and-control"

    def test_low_malicious_maps_to_t1071_001(self):
        """malicious 1-5 maps to T1071.001 Web Protocols."""
        tech_id, _, phase = _map_mitre(3)
        assert tech_id == "T1071.001"
        assert phase == "command-and-control"

    def test_zero_malicious_maps_to_t1592(self):
        """malicious == 0 maps to T1592 Reconnaissance."""
        tech_id, _, phase = _map_mitre(0)
        assert tech_id == "T1592"
        assert phase == "reconnaissance"


# -----------------------------------------------------------------------
# Confidence scoring
# -----------------------------------------------------------------------
class TestConfidence:
    """Tests for confidence score computation."""

    def test_no_enrichment_returns_25(self):
        """None enrichment yields baseline confidence of 25."""
        assert _compute_confidence(None) == 25

    def test_all_malicious_returns_high(self):
        """Mostly malicious yields high confidence."""
        enrichment = {
            "malicious": 50,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        }
        assert _compute_confidence(enrichment) == 100


# -----------------------------------------------------------------------
# STIX Indicator creation
# -----------------------------------------------------------------------
class TestCreateIndicator:
    """Tests for full STIX Indicator object creation."""

    def test_creates_valid_indicator(self):
        """A valid IOC + enrichment produces a STIX Indicator."""
        ioc = {"indicator": "10.0.0.1", "type": "IPv4"}
        enrichment = {
            "indicator": "10.0.0.1",
            "malicious": 8,
            "suspicious": 2,
            "harmless": 50,
            "undetected": 5,
            "source": "VirusTotal",
        }
        result = create_stix_indicator(ioc, enrichment)

        assert result is not None
        assert isinstance(result, stix2.Indicator)
        assert result.pattern == "[ipv4-addr:value = '10.0.0.1']"
        assert result.pattern_type == "stix"

    def test_indicator_has_kill_chain(self):
        """STIX Indicator includes kill-chain phase."""
        ioc = {"indicator": "evil.com", "type": "domain"}
        result = create_stix_indicator(ioc, {"malicious": 10})

        assert result is not None
        assert len(result.kill_chain_phases) == 1
        kc = result.kill_chain_phases[0]
        assert kc.kill_chain_name == "mitre-attack"

    def test_indicator_custom_properties(self):
        """STIX Indicator includes custom severity and source."""
        ioc = {"indicator": "5.5.5.5", "type": "IPv4"}
        enrichment = {"malicious": 12, "source": "VirusTotal"}
        result = create_stix_indicator(ioc, enrichment)

        assert result is not None
        assert result.x_severity == "Critical"
        assert result.x_source == "VirusTotal"
        assert result.x_mitre_attack_id == "T1071"

    def test_indicator_without_enrichment(self):
        """IOC with no enrichment still produces valid Indicator."""
        ioc = {"indicator": "benign.org", "type": "domain"}
        result = create_stix_indicator(ioc, None)

        assert result is not None
        assert result.x_severity == "Low"


# -----------------------------------------------------------------------
# STIX Bundle
# -----------------------------------------------------------------------
class TestBundleIndicators:
    """Tests for STIX Bundle creation."""

    def test_bundle_wraps_indicators(self):
        """Bundle contains all provided indicators."""
        ioc1 = {"indicator": "1.1.1.1", "type": "IPv4"}
        ioc2 = {"indicator": "bad.com", "type": "domain"}
        ind1 = create_stix_indicator(ioc1, {"malicious": 5})
        ind2 = create_stix_indicator(ioc2, {"malicious": 1})

        bundle = bundle_indicators([ind1, ind2])

        assert isinstance(bundle, stix2.Bundle)
        assert len(bundle.objects) == 2
        assert bundle.id.startswith("bundle--")
