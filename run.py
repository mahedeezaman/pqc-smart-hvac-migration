"""
HVAC PQC Benchmark Suite — Master CLI
======================================
Usage:
  python3 run.py all                          # full suite
  python3 run.py test                         # integration tests only
  python3 run.py benchmark operations         # operation benchmarks
  python3 run.py benchmark e2e                # end-to-end handshake
  python3 run.py benchmark network            # network latency
  python3 run.py benchmark stress             # stress + throughput
  python3 run.py benchmark stress --threads 32 --sessions 500
  python3 run.py analysis sidechannel         # side-channel tests
  python3 run.py analysis esp32               # ESP32 infeasibility check
  python3 run.py output plots                 # generate all plots
  python3 run.py output tables                # generate LaTeX tables
"""

import sys
import time

# ── Make project root importable ─────────────────────────────────────────────
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))


def header(msg):
    print(f"\n{'='*60}\n  {msg}\n{'='*60}")


def run_tests():
    header("INTEGRATION TESTS")
    from tests.test_pqc_handshake import test_full_handshake
    from tests.test_ecdh_baseline import test_ecdh_baseline
    test_full_handshake()
    test_ecdh_baseline()
    print("\n  ✔  All integration tests passed.")


def run_benchmark(name: str, args: list):
    from infra.config import STRESS_THREAD_COUNTS, STRESS_SESSIONS_TOTAL

    if name == "operations":
        header("OPERATION BENCHMARKS")
        from benchmarks.operations import OperationsBenchmark
        OperationsBenchmark().execute()

    elif name == "e2e":
        header("END-TO-END HANDSHAKE BENCHMARK")
        from benchmarks.e2e import E2EBenchmark
        E2EBenchmark().execute()

    elif name == "network":
        header("NETWORK LATENCY BENCHMARK")
        from benchmarks.network import NetworkBenchmark
        NetworkBenchmark().execute()

    elif name == "stress":
        header("STRESS TEST")
        # Override defaults from CLI args
        if "--threads" in args:
            idx = args.index("--threads")
            from infra import config
            config.STRESS_CONCURRENT = int(args[idx + 1])
            config.STRESS_THREAD_COUNTS = list(range(1, config.STRESS_CONCURRENT + 1,
                                                      max(1, config.STRESS_CONCURRENT // 6)))
        if "--sessions" in args:
            idx = args.index("--sessions")
            from infra import config
            config.STRESS_SESSIONS_TOTAL = int(args[idx + 1])
        from benchmarks.stress import StressBenchmark
        StressBenchmark().execute()

    else:
        print(f"Unknown benchmark: {name}")
        print("Available: operations, e2e, network, stress")
        sys.exit(1)


def run_analysis(name: str):
    if name == "sidechannel":
        header("SIDE-CHANNEL ANALYSIS")
        from analysis.sidechannel import run_sidechannel_analysis
        run_sidechannel_analysis()

    elif name == "esp32":
        header("ESP32 INFEASIBILITY CHECK")
        from analysis.esp32 import validate_esp32_results
        result = validate_esp32_results()
        print(f"\n  {result.get('interpretation', 'No result.')}")

    else:
        print(f"Unknown analysis: {name}")
        print("Available: sidechannel, esp32")
        sys.exit(1)


def run_output(name: str):
    if name == "plots":
        header("GENERATING PLOTS")
        from analysis.plots import generate_all_plots
        generate_all_plots()

    elif name == "tables":
        header("GENERATING LATEX TABLES")
        from output.tables import generate_all_tables
        generate_all_tables()

    else:
        print(f"Unknown output: {name}")
        print("Available: plots, tables")
        sys.exit(1)


def run_all():
    header("HVAC PQC — FULL BENCHMARK SUITE")
    t_start = time.time()

    steps = [
        ("Integration Tests",         run_tests),
        ("Operation Benchmarks",      lambda: run_benchmark("operations", [])),
        ("End-to-End Handshake",      lambda: run_benchmark("e2e", [])),
        ("Network Latency",           lambda: run_benchmark("network", [])),
        ("Stress Test",               lambda: run_benchmark("stress", [])),
        ("Side-Channel Analysis",     lambda: run_analysis("sidechannel")),
        ("ESP32 Infeasibility Check", lambda: run_analysis("esp32")),
        ("Generate Plots",            lambda: run_output("plots")),
        ("Generate LaTeX Tables",     lambda: run_output("tables")),
    ]

    for label, fn in steps:
        t0 = time.time()
        try:
            fn()
            print(f"\n  ✔  {label} ({time.time()-t0:.1f}s)")
        except Exception as e:
            print(f"\n  ✖  {label} FAILED: {e}")
            raise

    elapsed = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"  COMPLETE — {elapsed/60:.1f} minutes total")
    print(f"{'='*60}\n")


def main():
    args = sys.argv[1:]

    if not args or args[0] == "all":
        run_all()

    elif args[0] == "test":
        run_tests()

    elif args[0] == "benchmark":
        if len(args) < 2:
            print("Usage: python3 run.py benchmark <name>")
            sys.exit(1)
        run_benchmark(args[1], args[2:])

    elif args[0] == "analysis":
        if len(args) < 2:
            print("Usage: python3 run.py analysis <name>")
            sys.exit(1)
        run_analysis(args[1])

    elif args[0] == "output":
        if len(args) < 2:
            print("Usage: python3 run.py output <name>")
            sys.exit(1)
        run_output(args[1])

    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
