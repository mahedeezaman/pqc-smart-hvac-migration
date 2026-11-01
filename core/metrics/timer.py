"""High-resolution timing utilities."""

import time


def now_ns() -> int:
    return time.monotonic_ns()


def ns_to_ms(ns: int) -> float:
    return ns / 1_000_000.0


def sleep_ms(ms: float = 10):
    time.sleep(ms / 1000.0)
