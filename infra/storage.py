"""Save/load JSON and CSV — all file I/O in one place."""

import json
import csv
from pathlib import Path
from infra.config import RESULTS_DIR


def save_json(filename: str, data: dict) -> Path:
    path = RESULTS_DIR / filename
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def load_json(filename: str) -> dict:
    path = RESULTS_DIR / filename
    with open(path) as f:
        return json.load(f)


def save_csv(filename: str, rows: list) -> Path:
    if not rows:
        return RESULTS_DIR / filename
    path = RESULTS_DIR / filename
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    return path
