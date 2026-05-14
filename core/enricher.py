"""
core/enricher.py
================
Enriches a single IOC via the VirusTotal v3 API.

Supports **IPv4 addresses**, **domains**, and **file hashes** (MD5, SHA-1,
SHA-256).  Other types are skipped with a warning so the pipeline remains
resilient.
"""

import re
import time
from typing import Any, Dict, Optional

import requests

from config.settings import VT_API_KEY
from utils.logger import setup_logger

log = setup_logger("enricher")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# ---------------------------------------------------------------------------
# IOC classification heuristics
# ---------------------------------------------------------------------------
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$"
)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")


def _classify_ioc(value: str) -> Optional[str]:
    """Return the IOC type based on the observable value.

    Args:
        value: The raw IOC string (IP, domain, or hash).

    Returns:
        One of ``"ip"``, ``"domain"``, ``"hash"``, or ``None`` if the
        value cannot be classified.
    """
    if _IPV4_RE.match(value):
        return "ip"
    if _HASH_RE.match(value):
        return "hash"
    if _DOMAIN_RE.match(value):
        return "domain"
    return None


def enrich_with_virustotal(
    ioc: str | Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """Query VirusTotal for reputation data on a single IOC.

    Args:
        ioc: Either a plain string IOC value **or** a dict with at least
            an ``indicator`` key.

    Returns:
        Enrichment payload with keys ``indicator``, ``malicious``,
        ``suspicious``, ``harmless``, ``undetected``, and ``source``.
        Returns ``None`` when the API key is missing, the IOC type is
        unsupported, or the request fails.
    """
    if not VT_API_KEY:
        log.warning("VT_API_KEY is not set — skipping enrichment.")
        return None

    # Accept both str and dict inputs
    if isinstance(ioc, dict):
        indicator: str = ioc.get("indicator", "")
    else:
        indicator = ioc

    ioc_kind = _classify_ioc(indicator)

    if ioc_kind is None:
        log.warning(
            "Unsupported IOC type for enrichment: %s", indicator
        )
        return None

    # Build endpoint URL
    endpoint_map = {
        "ip": f"{VT_BASE_URL}/ip_addresses/{indicator}",
        "domain": f"{VT_BASE_URL}/domains/{indicator}",
        "hash": f"{VT_BASE_URL}/files/{indicator}",
    }
    url = endpoint_map[ioc_kind]
    headers: Dict[str, str] = {"x-apikey": VT_API_KEY}

    log.info(
        "Enriching IOC via VirusTotal: %s (%s)", indicator, ioc_kind
    )

    try:
        response = requests.get(url, headers=headers, timeout=30)

        # Handle rate limiting (HTTP 429)
        if response.status_code == 429:
            log.warning(
                "VT rate limit hit for %s — waiting 60s …", indicator
            )
            time.sleep(60)
            response = requests.get(url, headers=headers, timeout=30)

        # Handle 404 (not found in VT database)
        if response.status_code == 404:
            log.info("IOC not found in VirusTotal: %s", indicator)
            return {
                "indicator": indicator,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "source": "VirusTotal",
            }

        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        log.error("VT API HTTP error for %s: %s", indicator, exc)
        return None
    except requests.exceptions.RequestException as exc:
        log.error("VT API request failed for %s: %s", indicator, exc)
        return None

    # ------------------------------------------------------------------
    # Parse last_analysis_stats
    # ------------------------------------------------------------------
    try:
        attributes: dict = response.json()["data"]["attributes"]
        stats: dict = attributes.get("last_analysis_stats", {})
    except (KeyError, TypeError) as exc:
        log.error(
            "Unexpected VT response structure for %s: %s",
            indicator,
            exc,
        )
        return None

    enrichment: Dict[str, Any] = {
        "indicator": indicator,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "source": "VirusTotal",
    }

    log.info(
        "Enrichment result for %s → malicious=%d, suspicious=%d",
        indicator,
        enrichment["malicious"],
        enrichment["suspicious"],
    )
    return enrichment
