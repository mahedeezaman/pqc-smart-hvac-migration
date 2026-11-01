"""Statistical computation — pure functions, no I/O."""

import statistics
from core.metrics.timer import ns_to_ms
from core.metrics.energy import estimate_energy_mj


def compute_stats(samples_ns: list) -> dict:
    samples_ms = [ns_to_ms(x) for x in samples_ns]
    sorted_ms  = sorted(samples_ms)
    n          = len(sorted_ms)
    mean_ms    = statistics.mean(samples_ms)
    return {
        "mean_ms"   : round(mean_ms, 4),
        "std_ms"    : round(statistics.stdev(samples_ms), 4),
        "min_ms"    : round(min(samples_ms), 4),
        "max_ms"    : round(max(samples_ms), 4),
        "p95_ms"    : round(sorted_ms[int(0.95 * n)], 4),
        "n_samples" : n,
        "energy_mj" : estimate_energy_mj(mean_ms),
    }
