"""Structured logging configuration."""

import logging

from pythonjsonlogger import jsonlogger


def configure_logging(level: str) -> None:
    """Configure process-wide JSON logging."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level.upper())

    if root_logger.handlers:
        return

    handler = logging.StreamHandler()
    handler.setFormatter(jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root_logger.addHandler(handler)

