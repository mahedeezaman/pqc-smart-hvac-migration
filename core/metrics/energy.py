"""
Software-based energy estimation.
Energy (mJ) = CPU_POWER_W x time_s x 1000
Model: ARM Cortex-A72 single core at 1500 MHz = 0.5W
"""

from infra.config import CPU_POWER_W


def estimate_energy_mj(mean_ms: float) -> float:
    return round(CPU_POWER_W * (mean_ms / 1000.0) * 1000.0, 6)
