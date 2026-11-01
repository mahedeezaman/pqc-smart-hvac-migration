"""
Central configuration — all constants live here.
Change anything benchmark-related in this one file only.
"""

from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT_DIR    = Path(__file__).parent.parent
RESULTS_DIR = ROOT_DIR / "results"
PLOTS_DIR   = ROOT_DIR / "plots"
LOGS_DIR    = ROOT_DIR / "logs"

for _d in [RESULTS_DIR, PLOTS_DIR, LOGS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# ── Benchmark parameters ──────────────────────────────────────────────────────
WARMUP_RUNS         = 50
MEASURED_RUNS       = 500
SLEEP_BETWEEN_MS    = 10        # ms sleep between individual runs
TEMP_THRESHOLD_C    = 72.0      # abort if Pi exceeds this

# ── Crypto algorithm configurations ──────────────────────────────────────────
KEM_CONFIGS = [
    ("ML-KEM-512",  "ML-DSA-44"),
    ("ML-KEM-768",  "ML-DSA-65"),   # ← proposed config (conference paper)
    ("ML-KEM-1024", "ML-DSA-87"),
]
PRIMARY_KEM = "ML-KEM-768"
PRIMARY_SIG = "ML-DSA-65"

HKDF_INFO  = b"HVAC-PQC-Proxy-AES256GCM-v1"
NONCE_SIZE = 12   # bytes — 96-bit GCM nonce

# ── Energy model ──────────────────────────────────────────────────────────────
# ARM Cortex-A72 single core at measured benchmark frequency (1800 MHz)
# Power scaled linearly from 0.5W at 1500 MHz reference:
# P(1800) = 0.5 * (1800/1500) = 0.60W
# Source: ARM Cortex-A72 TRM; Raspberry Pi Foundation Product Brief (2019)
CPU_POWER_W      = 0.6
CPU_FREQ_REF_MHZ = 1800

# ── Network simulation RTTs ───────────────────────────────────────────────────
NETWORK_RTTS_MS = [0, 20, 50, 100, 250]

# ── Stress test defaults ──────────────────────────────────────────────────────
STRESS_THREAD_COUNTS  = [1, 2, 4, 8, 16, 32]
STRESS_SESSIONS_TOTAL = 500     # sequential throughput test
STRESS_CONCURRENT     = 32      # peak concurrent sessions test

# ── Side-channel test parameters ─────────────────────────────────────────────
SC_TIMING_SAMPLES  = 50_000
SC_NONCE_COUNT     = 10_000
SC_VARIANT_SAMPLES = 5000
SC_TVLA_SAMPLES = 50_000

# ── Plot style ────────────────────────────────────────────────────────────────
PLOT_COLORS = ["#2196F3", "#4CAF50", "#FF9800", "#F44336"]
PLOT_DPI    = 300
