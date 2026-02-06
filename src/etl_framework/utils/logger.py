"""
Simple logging utility.
"""
import logging
from typing import Optional


def setup_logger(
    name: str, log_level: int = logging.INFO, log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configure and return a logger.

    Args:
        name: Logger name.
        log_level: Logging level (default: INFO).
        log_file: Optional file path for file logging.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
