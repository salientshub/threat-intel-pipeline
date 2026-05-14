"""
core/fetcher.py
===============
Fetches Indicators of Compromise (IOCs) from AlienVault OTX pulse feed.

The module queries the *subscribed pulses* endpoint and extracts unique
indicators (IPv4, domain, hostname, URL) suitable for downstream enrichment.
"""

from typing import Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter

from config.settings import OTX_API_KEY
from utils.logger import setup_logger

try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    from requests.packages.urllib3.util.retry import Retry  # type: ignore[no-redef]

log = setup_logger("fetcher")

# AlienVault OTX v1 API — subscribed pulses
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


def _build_session() -> requests.Session:
    """Create an HTTP session with automatic retry on transient errors.

    Returns:
        A :class:`requests.Session` configured with retry on 429, 500,
        502, 503, and 504 status codes.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def fetch_iocs_from_otx(limit: int = 3) -> List[Dict[str, str]]:
    """Fetch IOCs from the user's subscribed OTX pulses.

    Args:
        limit: Maximum number of pulses to retrieve (default ``3``).

    Returns:
        Deduplicated list of IOC dicts, each containing:

        * ``indicator`` – the observable value (IP, domain, URL …)
        * ``type`` – OTX indicator type (e.g. ``IPv4``, ``domain``)

    Note:
        No exceptions are raised; errors are caught, logged, and an
        empty list is returned so the pipeline can continue gracefully.
    """
    if not OTX_API_KEY:
        log.warning("OTX_API_KEY is not set — returning empty IOC list.")
        return []

    headers: Dict[str, str] = {"X-OTX-API-KEY": OTX_API_KEY}
    params: Dict[str, object] = {"limit": limit, "modified_since": ""}

    log.info("Fetching IOCs from AlienVault OTX (limit=%d) …", limit)

    session = _build_session()
    try:
        response = session.get(
            OTX_BASE_URL, headers=headers, params=params, timeout=30
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        log.error("OTX API request failed: %s", exc)
        return []
    finally:
        session.close()

    data = response.json()
    pulses: list = data.get("results", [])
    log.info("Retrieved %d pulse(s) from OTX.", len(pulses))

    # ------------------------------------------------------------------
    # Extract unique indicators across all pulses
    # ------------------------------------------------------------------
    seen: set = set()
    iocs: List[Dict[str, str]] = []

    for pulse in pulses:
        for indicator in pulse.get("indicators", []):
            value: Optional[str] = indicator.get("indicator")
            ioc_type: Optional[str] = indicator.get("type")
            if value and value not in seen:
                seen.add(value)
                iocs.append(
                    {"indicator": value, "type": ioc_type or "unknown"}
                )

    log.info("Extracted %d unique IOC(s) from OTX pulses.", len(iocs))
    return iocs
