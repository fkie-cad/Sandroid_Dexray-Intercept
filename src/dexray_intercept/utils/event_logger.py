#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import Optional


class EventLogger:
    """Unified logger for dexray-intercept events with dual output modes.

    This logger provides clean terminal output (no timestamps/metadata) while
    maintaining detailed file logs. Designed to replace print() statements
    throughout dexray-intercept for better integration control.

    Terminal Output Format (CMD/DUAL modes):
        [*] Event message here

    File Output Format (always includes full context):
        2025-10-03 12:34:56 - INFO - dexray_intercept.events - [*] Event message here
    """

    def __init__(self, name: str = 'dexray_intercept.events'):
        """Initialize event logger.

        Args:
            name: Logger name (default: 'dexray_intercept.events')
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # Accept all levels, handlers filter
        self.logger.propagate = False  # Don't propagate to root logger (avoids duplicates)

        self._terminal_handler: Optional[logging.Handler] = None
        self._file_handler: Optional[logging.Handler] = None

    def setup_terminal_output(self, enabled: bool = True):
        """Configure terminal output (for CMD/DUAL modes).

        When enabled, events are printed to terminal with clean formatting
        (no timestamps, no file:line info) to match standalone behavior.

        Args:
            enabled: If True, enable terminal output. If False, disable.
        """
        if enabled and not self._terminal_handler:
            handler = logging.StreamHandler()
            # Clean format: just the message (looks like print())
            handler.setFormatter(logging.Formatter('%(message)s'))
            handler.setLevel(logging.INFO)
            self.logger.addHandler(handler)
            self._terminal_handler = handler
        elif not enabled and self._terminal_handler:
            self.logger.removeHandler(self._terminal_handler)
            self._terminal_handler = None

    def setup_file_output(self, filepath: str, level: int = logging.DEBUG):
        """Configure file output.

        File logs always include full context (timestamp, level, module, message)
        for debugging and analysis purposes.

        Args:
            filepath: Path to log file
            level: Minimum log level for file output (default: DEBUG)
        """
        if self._file_handler:
            # Remove existing file handler if present
            self.logger.removeHandler(self._file_handler)

        handler = logging.FileHandler(filepath)
        # Full context format for file logs
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
        ))
        handler.setLevel(level)
        self.logger.addHandler(handler)
        self._file_handler = handler

    def event(self, message: str):
        """Log an event at INFO level.

        This is the primary method for logging events - equivalent to the
        old print() statements but with proper logging architecture.

        Args:
            message: Event message to log
        """
        self.logger.info(message)

    def warning(self, message: str):
        """Log a warning message.

        Args:
            message: Warning message to log
        """
        self.logger.warning(message)

    def error(self, message: str):
        """Log an error message.

        Args:
            message: Error message to log
        """
        self.logger.error(message)

    def debug(self, message: str):
        """Log debug information.

        Debug messages are written to file but not shown on terminal
        unless terminal handler level is set to DEBUG.

        Args:
            message: Debug message to log
        """
        self.logger.debug(message)

    def close(self):
        """Close all handlers and clean up resources."""
        if self._terminal_handler:
            self.logger.removeHandler(self._terminal_handler)
            self._terminal_handler = None

        if self._file_handler:
            self._file_handler.close()
            self.logger.removeHandler(self._file_handler)
            self._file_handler = None
