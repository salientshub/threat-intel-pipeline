#!/usr/bin/env python3
"""
main.py — Threat Intelligence Pipeline Orchestrator
====================================================
Entry point that orchestrates the full CTI lifecycle:

1. **Fetch** IOCs from AlienVault OTX
2. **Enrich** each IOC via VirusTotal
3. **Convert** to STIX 2.1 with MITRE ATT&CK mapping
4. **Push** the STIX bundle to Wazuh Cloud (or simulate)

CLI usage::

    python main.py
    python main.py --limit 10
    python main.py --limit 5 --no-push
"""

import argparse
import sys
import time

from config.settings import MAX_IOCS_PER_RUN, RATE_LIMIT_SECONDS
from core.enricher import enrich_with_virustotal
from core.fetcher import fetch_iocs_from_otx
from core.pusher import push_to_opensearch
from core.stixifier import bundle_indicators, create_stix_indicator
from utils.logger import setup_logger

log = setup_logger("main")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace with ``limit`` and ``no_push`` attrs.
    """
    parser = argparse.ArgumentParser(
        description="Cyber Threat Intelligence Pipeline",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Number of OTX pulses to fetch.",
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        default=False,
        help="Skip pushing to OpenSearch (enrich and stixify only).",
    )
    return parser.parse_args()


def run_pipeline(limit: int = 3, no_push: bool = False) -> None:
    """Execute the end-to-end threat intelligence pipeline.

    Args:
        limit: Number of OTX pulses to fetch.
        no_push: If True, skip the OpenSearch push step.
    """
    log.info("=" * 60)
    log.info("Threat Intelligence Pipeline — starting run")
    log.info("=" * 60)

    # ------------------------------------------------------------------
    # Step 1 — Fetch IOCs from AlienVault OTX
    # ------------------------------------------------------------------
    log.info("[1/4] Fetching IOCs from AlienVault OTX …")
    iocs = fetch_iocs_from_otx(limit=limit)

    if not iocs:
        log.warning("No IOCs retrieved. Pipeline exiting early.")
        return

    log.info(
        "Fetched %d IOC(s). Processing up to %d.",
        len(iocs),
        MAX_IOCS_PER_RUN,
    )

    # ------------------------------------------------------------------
    # Step 2 & 3 — Enrich + Convert to STIX
    # ------------------------------------------------------------------
    stix_indicators = []
    process_count = min(len(iocs), MAX_IOCS_PER_RUN)

    for idx, ioc in enumerate(iocs[:MAX_IOCS_PER_RUN], start=1):
        log.info(
            "[2/4] Enriching IOC %d/%d: %s",
            idx,
            process_count,
            ioc["indicator"],
        )
        enrichment = enrich_with_virustotal(ioc)

        log.info(
            "[3/4] Converting IOC to STIX 2.1: %s", ioc["indicator"]
        )
        indicator = create_stix_indicator(ioc, enrichment)

        if indicator:
            stix_indicators.append(indicator)

        # Rate-limit pause between API calls (skip after last IOC)
        if idx < process_count:
            log.info(
                "Rate-limiting: sleeping %ds …", RATE_LIMIT_SECONDS
            )
            time.sleep(RATE_LIMIT_SECONDS)

    if not stix_indicators:
        log.warning("No STIX indicators created. Pipeline exiting.")
        return

    # ------------------------------------------------------------------
    # Step 4 — Bundle and push
    # ------------------------------------------------------------------
    log.info(
        "[4/4] Bundling %d indicator(s) …", len(stix_indicators)
    )
    bundle = bundle_indicators(stix_indicators)

    if no_push:
        log.info("--no-push flag set. Skipping OpenSearch push.")
        log.info("STIX Bundle:\n%s", bundle.serialize(pretty=True))
        return

    success = push_to_opensearch(bundle)

    if success:
        log.info("Pipeline completed successfully.")
    else:
        log.error("Pipeline finished with push errors.")
        sys.exit(1)


def main() -> None:
    """CLI entry point for the pipeline."""
    args = parse_args()
    run_pipeline(limit=args.limit, no_push=args.no_push)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Pipeline interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        log.exception("Unhandled exception: %s", exc)
        sys.exit(1)
