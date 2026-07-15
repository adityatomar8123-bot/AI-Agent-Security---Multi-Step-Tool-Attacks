"""Utility modules for the Attack Discovery Engine.

Provides timing (Timebox) and logging configurations.
"""

from __future__ import annotations

import logging
import time
from typing import Final

# Default log format for debugging output.
LOG_FORMAT: Final[str] = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_logger(name: str = "attack_discovery", level: int = logging.INFO) -> logging.Logger:
    """Configure and return a standard logger for the package.

    Args:
        name: Name of the logger.
        level: Logging level.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(LOG_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


class Timebox:
    """Tracks time budget for search algorithms.

    Allows the search to monitor when to stop branching and begin candidate finalization.
    """

    def __init__(self, limit_s: float) -> None:
        """Initialize the timebox.

        Args:
            limit_s: Time limit in seconds.
        """
        self.limit_s: float = max(0.1, limit_s)
        self.start_time: float = time.monotonic()

    def elapsed(self) -> float:
        """Return the elapsed time in seconds."""
        return time.monotonic() - self.start_time

    def remaining(self) -> float:
        """Return the remaining time in seconds."""
        return max(0.0, self.limit_s - self.elapsed())

    def expired(self, buffer_s: float = 2.0) -> bool:
        """Check if the timebox has expired, leaving a safety buffer.

        Args:
            buffer_s: Grace period in seconds to finalize candidates.
        """
        return self.remaining() <= buffer_s
