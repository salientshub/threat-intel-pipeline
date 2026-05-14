# 🛡️ Threat Intelligence Pipeline

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](.)
[![Coverage](https://img.shields.io/badge/coverage-90%25-green)](.)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](.)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000)](.)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

> Automated Cyber Threat Intelligence (CTI) pipeline that fetches IOCs, enriches them, converts to STIX 2.1, and pushes to a SIEM — built for production-grade enterprise deployment.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Usage](#usage)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Extending the Pipeline](#extending-the-pipeline)
- [Troubleshooting](#troubleshooting)
- [CI/CD Integration](#cicd-integration)
- [License](#license)

---

## Overview

This project implements a **complete CTI lifecycle** in Python:

1. **Collection** — Fetches Indicators of Compromise (IOCs) from [AlienVault OTX](https://otx.alienvault.com/) pulse subscriptions.
2. **Enrichment** — Queries [VirusTotal](https://www.virustotal.com/) for reputation scoring (malicious / suspicious / harmless). Supports IPs, domains, and file hashes.
3. **Normalisation** — Converts enriched IOCs into **STIX 2.1** Indicator objects with dynamic MITRE ATT&CK kill-chain mapping.
4. **Dissemination** — Pushes the STIX bundle to **OpenSearch** as security events, or writes to local file in simulation mode.

---

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  AlienVault  │────▶│  VirusTotal  │────▶│   STIX 2.1   │────▶│  OpenSearch  │
│  OTX (OSINT) │     │  Enrichment  │     │  Conversion  │     │  SIEM Push   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
     fetcher.py          enricher.py         stixifier.py          pusher.py
        │                    │                    │                    │
        └────────────────────┴────────────────────┴────────────────────┘
                                    │
                               main.py
                          (CLI Orchestrator)
```

**Data flow:** `main.py` orchestrates each stage sequentially with configurable rate-limiting between VirusTotal calls. MITRE ATT&CK technique mapping is dynamically assigned based on enrichment severity.

### Dynamic MITRE ATT&CK Mapping

| Malicious Count | Technique | Phase |
|---|---|---|
| > 5 | T1071 — Application Layer Protocol | Command & Control |
| 1–5 | T1071.001 — Web Protocols | Command & Control |
| 0 | T1592 — Gather Victim Host Information | Reconnaissance |

### Severity Classification

| Malicious Count | Severity |
|---|---|
| > 10 | Critical |
| 6–10 | High |
| 1–5 | Medium |
| 0 | Low |

---

## Features

| Feature | Detail |
|---|---|
| **OSINT Collection** | AlienVault OTX pulse subscription API with retry logic |
| **Threat Enrichment** | VirusTotal v3 — IP, domain, & file hash reputation |
| **STIX 2.1 Compliance** | `stix2` library with custom properties |
| **MITRE ATT&CK Mapping** | Dynamic technique assignment based on severity |
| **SIEM Integration** | OpenSearch event ingestion with exponential backoff retry |
| **Simulation Mode** | Full demo without live credentials (writes to file) |
| **Structured Logging** | Console + rotating file (5 MB, 3 backups) |
| **Rate Limiting** | Configurable sleep + HTTP 429 handling |
| **CLI Interface** | `--limit` and `--no-push` flags via argparse |
| **Security** | Secrets via `.env`, never hard-coded |
| **Code Quality** | Black + Flake8 + pre-commit hooks |
| **Test Suite** | pytest with requests_mock, coverage reporting |

---

## Prerequisites

- **OS:** Ubuntu 22.04 / WSL2 (or any Linux)
- **Python:** 3.8+
- **pip:** Package manager
- **(Optional)** AlienVault OTX account — [sign up free](https://otx.alienvault.com/)
- **(Optional)** VirusTotal account — [sign up free](https://www.virustotal.com/)
- **(Optional)** OpenSearch instance

---

## Setup

### Quick Start (Makefile)

```bash
# Clone and enter project
git clone https://github.com/your-org/threat_intel_pipeline.git
cd threat_intel_pipeline

# One-command setup
make install

# Configure API keys
cp .env.example .env
nano .env    # Add your API keys (or leave blank for simulation)

# Verify everything works
make test

# Run the pipeline
make run
```

### Manual Setup

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env

# Optional: start OpenSearch locally
docker compose up -d opensearch

# Run
python main.py
```

---

## Usage

```bash
# Run with defaults (3 pulses, push enabled)
python main.py

# Fetch more pulses
python main.py --limit 10

# Enrich and stixify only (skip OpenSearch push)
python main.py --limit 5 --no-push
```

### Configuration

Override via `.env` or `config/settings.py`:

| Variable | Default | Description |
|---|---|---|
| `OTX_API_KEY` | *(empty)* | AlienVault OTX API key |
| `VT_API_KEY` | *(empty)* | VirusTotal API key |
| `OPENSEARCH_URL` | `http://localhost:9200` | OpenSearch endpoint URL |
| `MAX_IOCS_PER_RUN` | `5` | Cap IOCs processed per execution |
| `RATE_LIMIT_SECONDS` | `15` | Pause between VT API calls |
| `LOG_LEVEL` | `INFO` | Logging verbosity (DEBUG/INFO/WARNING/ERROR) |

---

## Testing

```bash
# Run full test suite with coverage
make test

# Or manually
pytest tests/ -v --tb=short --cov=core --cov=utils --cov-report=term-missing

# Lint checks
make lint

# Auto-format
make format
```

---

## Project Structure

```
threat_intel_pipeline/
├── .env.example              # API key template
├── .gitignore                # Git exclusions
├── .pre-commit-config.yaml   # Pre-commit hooks config
├── Makefile                  # Corporate convenience targets
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── setup.py                  # Installable package config
├── main.py                   # CLI orchestrator (entry point)
├── config/
│   └── settings.py           # Environment + constants loader
├── core/
│   ├── __init__.py
│   ├── fetcher.py            # AlienVault OTX collection
│   ├── enricher.py           # VirusTotal enrichment
│   ├── stixifier.py          # STIX 2.1 conversion + MITRE mapping
│   └── pusher.py             # OpenSearch event push
├── utils/
│   ├── __init__.py
│   └── logger.py             # Structured logging configuration
└── tests/
    ├── __init__.py
    ├── test_fetcher.py        # OTX fetcher unit tests
    ├── test_enricher.py       # VT enricher unit tests
    └── test_stixifier.py      # STIX conversion unit tests
```

---

## Extending the Pipeline

### Add a Dark Web Module

1. Create `core/darkweb.py` with a `fetch_from_tor()` function.
2. Register it in `main.py` as an additional fetch source.
3. Merge results with OTX IOCs before enrichment.

### Add More SIEMs (Splunk, Sentinel, etc.)

1. Create `core/pusher_splunk.py` implementing the same interface.
2. Add a `--siem` CLI flag in `main.py` to select the target.
3. Use a factory pattern to instantiate the correct pusher.

### Add More Enrichment Sources

1. Create `core/enricher_shodan.py` or similar.
2. Chain enrichments in `main.py` (VT → Shodan → AbuseIPDB).
3. Merge enrichment dicts before STIX conversion.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `OTX_API_KEY is not set` | Add your key to `.env` or run in simulation mode |
| `VT rate limit hit` | The pipeline auto-waits 60s on HTTP 429. Increase `RATE_LIMIT_SECONDS` to avoid hitting limits |
| `ModuleNotFoundError` | Activate your venv: `source venv/bin/activate` |
| `stix2` import errors | Ensure `pip install stix2` succeeded (requires Python 3.8+) |
| Tests fail with import errors | Run from project root: `pytest tests/` |
| `Permission denied` on logs | Ensure `logs/` directory is writable |
| OpenSearch push fails | Verify `OPENSEARCH_URL` is set and reachable, then retry |

---

## CI/CD Integration

### GitHub Actions (example)

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v --cov=core --cov-report=xml
      - run: black --check core/ utils/ config/ main.py tests/
      - run: flake8 core/ utils/ config/ main.py tests/ --max-line-length=88
```

---

## License

This project is open source and available under the [MIT License](LICENSE).

---

> Built with 🐍 Python | 🛡️ STIX 2.1 | 🔍 MITRE ATT&CK | 🌐 AlienVault OTX | 🦠 VirusTotal | 📡 OpenSearch
