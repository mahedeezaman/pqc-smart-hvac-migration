"""
BaseBenchmark — every benchmark extends this.
Adding a new benchmark = add one file, extend this class. Nothing else changes.
"""

from abc import ABC, abstractmethod
from infra.logger import get_logger
from infra.storage import save_json, save_csv
from core.metrics.memory import get_system_info, get_temperature
from infra.config import TEMP_THRESHOLD_C
import time
import sys


class BaseBenchmark(ABC):

    def __init__(self, name: str):
        self.name   = name
        self.logger = get_logger(name)

    def preflight(self):
        """Check temperature before running. Abort if too hot."""
        temp = get_temperature()
        if temp > TEMP_THRESHOLD_C:
            self.logger.error(f"Temperature {temp}°C exceeds threshold {TEMP_THRESHOLD_C}°C. Aborting.")
            sys.exit(1)
        if temp > 0:
            self.logger.info(f"Temperature: {temp}°C ✓")

    @abstractmethod
    def run(self) -> dict:
        """Execute benchmark. Return results dict."""
        ...

    def execute(self) -> dict:
        """Public entry point: preflight → run → return results."""
        self.logger.info(f"{'='*55}")
        self.logger.info(f"  {self.name.upper()}")
        self.logger.info(f"{'='*55}")
        self.preflight()
        t0      = time.time()
        results = self.run()
        elapsed = time.time() - t0
        self.logger.info(f"Completed in {elapsed:.1f}s")
        return results

    def save(self, results: dict, json_filename: str, csv_rows: list = None):
        """Save results to JSON (and optionally CSV)."""
        path = save_json(json_filename, {
            "system_info": get_system_info(),
            "results"    : results,
        })
        self.logger.info(f"Saved: {path}")
        if csv_rows:
            csv_path = save_json(json_filename.replace(".json", ".csv"), {})
            save_csv(json_filename.replace(".json", ".csv"), csv_rows)
