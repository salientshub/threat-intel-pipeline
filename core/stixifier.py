"""
core/stixifier.py
=================
Converts enriched IOC data into STIX 2.1 Indicator objects.

Dynamic MITRE ATT&CK mapping based on enrichment severity:
* malicious > 5  → T1071 (Application Layer Protocol / C2)
* malicious 1-5  → T1071.001 (Web Protocols / C2)
* malicious == 0 → T1592 (Gather Victim Host Info / Recon)
"""

from typing import Any, Dict, List, Optional

import stix2

from utils.logger import setup_logger

log = setup_logger("stixifier")


def _build_pattern(ioc: Dict[str, str]) -> Optional[str]:
    """Return a STIX 2.1 pattern string for the given IOC.

    Args:
        ioc: Must contain ``indicator`` and ``type`` keys.

    Returns:
        A STIX pattern string, or ``None``.
    """
    value: str = ioc.get("indicator", "")
    ioc_type: str = ioc.get("type", "").lower()

    if ioc_type in ("ipv4", "ip"):
        return f"[ipv4-addr:value = '{value}']"
    if ioc_type in ("domain", "hostname"):
        return f"[domain-name:value = '{value}']"
    if ioc_type in ("url", "uri"):
        return f"[url:value = '{value}']"
    if ioc_type == "filehash-md5":
        return f"[file:hashes.'MD5' = '{value}']"
    if ioc_type == "filehash-sha1":
        return f"[file:hashes.'SHA-1' = '{value}']"
    if ioc_type == "filehash-sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"

    # Fallback heuristic
    if len(value) == 32 and all(c in "0123456789abcdefABCDEF" for c in value):
        return f"[file:hashes.'MD5' = '{value}']"
    if len(value) == 40 and all(c in "0123456789abcdefABCDEF" for c in value):
        return f"[file:hashes.'SHA-1' = '{value}']"
    if len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
        return f"[file:hashes.'SHA-256' = '{value}']"

    if value.replace(".", "").isdigit():
        return f"[ipv4-addr:value = '{value}']"
    return f"[domain-name:value = '{value}']"


def _classify_severity(malicious_count: int) -> str:
    """Map malicious engine count to severity label.

    Args:
        malicious_count: Number of engines flagging as malicious.

    Returns:
        One of Critical, High, Medium, or Low.
    """
    if malicious_count > 10:
        return "Critical"
    if malicious_count > 5:
        return "High"
    if malicious_count > 0:
        return "Medium"
    return "Low"


def _map_mitre(malicious_count: int) -> tuple:
    """Map MITRE ATT&CK technique based on enrichment.

    Args:
        malicious_count: Malicious engine count.

    Returns:
        Tuple of (technique_id, technique_name, phase_name).
    """
    if malicious_count > 5:
        return ("T1071", "Application Layer Protocol", "command-and-control")
    if malicious_count > 0:
        return ("T1071.001", "Web Protocols", "command-and-control")
    return ("T1592", "Gather Victim Host Information", "reconnaissance")


def _compute_confidence(enrichment: Optional[Dict[str, Any]]) -> int:
    """Compute confidence score (0-100) from enrichment data.

    Args:
        enrichment: VirusTotal enrichment dict, or None.

    Returns:
        Integer confidence score.
    """
    if not enrichment:
        return 25
    total = sum(
        enrichment.get(k, 0)
        for k in ("malicious", "suspicious", "harmless", "undetected")
    )
    if total == 0:
        return 25
    mal = enrichment.get("malicious", 0)
    return min(int((mal / total) * 100) + 25, 100)


def create_stix_indicator(
    ioc: Dict[str, str],
    enrichment: Optional[Dict[str, Any]] = None,
) -> Optional[stix2.Indicator]:
    """Create a STIX 2.1 Indicator from an IOC and enrichment.

    Args:
        ioc: Raw IOC dict with ``indicator`` and ``type`` keys.
        enrichment: Optional VirusTotal enrichment payload.

    Returns:
        A STIX 2.1 Indicator, or None on failure.
    """
    pattern = _build_pattern(ioc)
    if pattern is None:
        log.warning("Cannot build STIX pattern for IOC: %s", ioc)
        return None

    malicious_count: int = 0
    if enrichment:
        malicious_count = enrichment.get("malicious", 0)

    severity = _classify_severity(malicious_count)
    tech_id, tech_name, phase_name = _map_mitre(malicious_count)
    confidence = _compute_confidence(enrichment)

    kill_chain = stix2.KillChainPhase(
        kill_chain_name="mitre-attack",
        phase_name=phase_name,
    )

    custom: Dict[str, Any] = {
        "x_severity": severity,
        "x_source": (
            enrichment.get("source", "unknown") if enrichment else "unknown"
        ),
        "x_confidence": confidence,
        "x_enrichment": enrichment if enrichment else {},
        "x_mitre_attack_id": tech_id,
    }

    try:
        indicator = stix2.Indicator(
            name=f"Threat indicator: {ioc.get('indicator', 'unknown')}",
            description=(
                f"IOC enriched via automated CTI pipeline. "
                f"Severity: {severity}. "
                f"MITRE ATT&CK: {tech_id} ({tech_name})."
            ),
            pattern=pattern,
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00Z",
            kill_chain_phases=[kill_chain],
            labels=["malicious-activity", "threat-intelligence"],
            custom_properties=custom,
        )
    except Exception as exc:
        log.error("Failed to create STIX Indicator for %s: %s", ioc, exc)
        return None

    log.info(
        "Created STIX Indicator [%s] severity=%s mitre=%s for %s",
        indicator.id,
        severity,
        tech_id,
        ioc.get("indicator"),
    )
    return indicator


def bundle_indicators(indicators: List[stix2.Indicator]) -> stix2.Bundle:
    """Wrap STIX Indicator objects into a STIX Bundle.

    Args:
        indicators: One or more STIX Indicator objects.

    Returns:
        A serialisable STIX 2.1 Bundle.
    """
    bundle = stix2.Bundle(objects=indicators, allow_custom=True)
    log.info(
        "Bundled %d indicator(s) into STIX Bundle [%s].",
        len(indicators),
        bundle.id,
    )
    return bundle
