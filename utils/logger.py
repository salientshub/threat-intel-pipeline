"""
utils/logger.py
===============
Configures a reusable logger with console and rotating file output.

Usage::

    from utils.logger import setup_logger
    log = setup_logger("my_module")
    log.info("Pipeline started")
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from config.settings import LOG_LEVEL


def setup_logger(
    name: str = "threat_intel_pipeline",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Return a configured :class:`logging.Logger` instance.

    The logger writes to **two** handlers:

    * **Console** (stdout) — output at the configured LOG_LEVEL.
    * **File** (``logs/pipeline.log`` or *log_file*) — rotated at 5 MB,
      keeps 3 backups.

    Args:
        name: Logger name (appears in every log line).
        log_file: Optional path to the log file.  Defaults to
            ``logs/pipeline.log`` relative to the project root.

    Returns:
        Ready-to-use logger instance.
    """
    logger = logging.getLogger(name)

    # Prevent duplicate handlers when setup_logger is called more than once
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ----- Formatter -----
    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ----- Console handler -----
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    # ----- File handler -----
    if log_file is None:
        log_dir = Path(__file__).resolve().parent.parent / "logs"
        log_dir.mkdir(exist_ok=True)
        log_file_path = log_dir / "pipeline.log"
    else:
        log_file_path = Path(log_file)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger
