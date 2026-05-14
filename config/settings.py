"""
config/settings.py
==================
Centralised configuration loader for the Threat Intelligence Pipeline.

All secrets are read from environment variables (populated via a .env file)
so that credentials never appear in source code.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load .env from project root (two levels up from this file)
# ---------------------------------------------------------------------------
_env_path: Path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_env_path)


# ---------------------------------------------------------------------------
# API Keys & Endpoints
# ---------------------------------------------------------------------------
OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
VT_API_KEY: str = os.getenv("VT_API_KEY", "")

# OpenSearch API endpoint (disabled by default - set to enable)
OPENSEARCH_URL: str = os.getenv("OPENSEARCH_URL", "")

# OpenSearch credentials (optional)
OPENSEARCH_USERNAME: str = os.getenv("OPENSEARCH_USERNAME", "")
OPENSEARCH_PASSWORD: str = os.getenv("OPENSEARCH_PASSWORD", "")

# ---------------------------------------------------------------------------
# Pipeline Tunables
# ---------------------------------------------------------------------------
# Maximum IOCs to enrich per run (keeps within free-tier rate limits)
MAX_IOCS_PER_RUN: int = int(os.getenv("MAX_IOCS_PER_RUN", "5"))

# Seconds to sleep between successive VirusTotal API calls
RATE_LIMIT_SECONDS: int = int(os.getenv("RATE_LIMIT_SECONDS", "15"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()


def _validate_log_level(level: str) -> str:
    """Validate the log level string against Python's logging module.

    Args:
        level: A string log level name (e.g. ``"INFO"``, ``"DEBUG"``).

    Returns:
        The validated, upper-cased log level string.

    Raises:
        ValueError: If *level* is not a recognised Python log level.
    """
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if level not in valid_levels:
        raise ValueError(
            f"Invalid LOG_LEVEL '{level}'. Must be one of {valid_levels}."
        )
    return level


# Validate on import so misconfigurations are caught early
LOG_LEVEL = _validate_log_level(LOG_LEVEL)
