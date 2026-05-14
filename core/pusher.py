"""
core/pusher.py
==============
Pushes a STIX 2.1 Bundle to local OpenSearch as security events.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth
import stix2
import urllib3

from config.settings import OPENSEARCH_URL, OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD
from utils.logger import setup_logger

# Suppress SSL warnings when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = setup_logger("pusher")


def _save_simulated_bundle(bundle: stix2.Bundle) -> str:
    output_dir = Path(__file__).resolve().parent.parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"stix_bundle_{timestamp}.json"
    path = output_dir / filename
    with path.open("w", encoding="utf-8") as handle:
        handle.write(bundle.serialize(pretty=True))
    return str(path)


def _simulate_push(bundle: stix2.Bundle) -> bool:
    file_path = _save_simulated_bundle(bundle)
    log.info(
        "STIX bundle saved to %s (OpenSearch not configured).",
        file_path,
    )
    return True


def _get_auth() -> Optional[HTTPBasicAuth]:
    """Get HTTP Basic Auth credentials if configured."""
    if OPENSEARCH_USERNAME and OPENSEARCH_PASSWORD:
        return HTTPBasicAuth(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD)
    return None


def push_to_opensearch(stix_bundle: stix2.Bundle) -> bool:
    """Send a STIX bundle to OpenSearch index."""
    if not OPENSEARCH_URL:
        log.info(
            "OPENSEARCH_URL not set — falling back to simulated push."
        )
        return _simulate_push(stix_bundle)

    # Check if OpenSearch is available before pushing
    auth = _get_auth()
    try:
        health_url = f"{OPENSEARCH_URL.rstrip('/')}/_cluster/health"
        resp = requests.get(
            health_url,
            auth=auth,
            timeout=5,
            verify=False
        )
        resp.raise_for_status()
        log.info("OpenSearch is available and healthy.")
    except Exception as exc:
        log.info(
            "OpenSearch is not reachable at %s: %s — falling back to simulation.",
            OPENSEARCH_URL,
            exc,
        )
        return _simulate_push(stix_bundle)

    events: List[dict] = []
    for obj in stix_bundle.objects:
        if obj.get("type") == "indicator":
            event = json.loads(obj.serialize())
            event["@timestamp"] = datetime.now(timezone.utc).isoformat()
            event["source"] = "cti_pipeline"
            events.append(event)

    if not events:
        log.warning("No indicator objects found in bundle.")
        return False

    log.info(
        "Pushing %d event(s) to OpenSearch API at %s...",
        len(events),
        OPENSEARCH_URL,
    )

    url = f"{OPENSEARCH_URL.rstrip('/')}/cti-events/_doc"
    headers = {"Content-Type": "application/json"}

    success_count = 0
    for event in events:
        # Simple retry for each event
        for attempt in range(3):
            try:
                resp = requests.post(
                    url,
                    auth=auth,
                    headers=headers,
                    json=event,
                    timeout=10,
                    verify=False
                )
                resp.raise_for_status()
                success_count += 1
                break
            except requests.exceptions.RequestException as exc:
                if attempt < 2:
                    log.warning(
                        "Push failed (attempt %d/3), retrying... Error: %s",
                        attempt + 1,
                        exc,
                    )
                else:
                    log.error(
                        "Failed to push event to OpenSearch after 3 attempts: %s",
                        exc,
                    )

    if success_count == len(events):
        log.info("Successfully pushed all %d events.", success_count)
        return True

    log.error("Pushed %d/%d events.", success_count, len(events))
    return _simulate_push(stix_bundle)
