"""
Simple structured logger — wraps standard logging, supports extra kwargs as inline text.
"""

import logging
import sys


class StructuredLogger:
    def __init__(self, name: str):
        self._logger = logging.getLogger(name)
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] %(levelname)s %(name)s — %(message)s",
                datefmt="%H:%M:%S",
            ))
            self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)

    def _fmt(self, msg: str, kwargs: dict) -> str:
        if not kwargs:
            return msg
        extra = " | ".join(f"{k}={v}" for k, v in kwargs.items())
        return f"{msg} | {extra}"

    def info(self, msg: str, **kwargs):
        self._logger.info(self._fmt(msg, kwargs))

    def warning(self, msg: str, **kwargs):
        self._logger.warning(self._fmt(msg, kwargs))

    def error(self, msg: str, **kwargs):
        self._logger.error(self._fmt(msg, kwargs))

    def debug(self, msg: str, **kwargs):
        self._logger.debug(self._fmt(msg, kwargs))


def get_logger(name: str) -> StructuredLogger:
    return StructuredLogger(name)