"""
Stress test benchmark.
Tests concurrent sessions, throughput, and memory leak detection.
Answers: how many simultaneous HVAC devices can the proxy handle?
"""

import time
import threading
import gc
from benchmarks.base import BaseBenchmark
from core.crypto.pqc_proxy import PQCProxy, MobileAppSimulator
from core.stats import compute_stats
from core.metrics.timer import now_ns
from core.metrics.memory import get_memory_kb
from infra.config import (STRESS_THREAD_COUNTS, STRESS_SESSIONS_TOTAL,
                           STRESS_CONCURRENT)


class StressBenchmark(BaseBenchmark):

    def __init__(self):
        super().__init__("stress_benchmark")

    def _run_single_session(self, proxy: PQCProxy) -> float:
        """Run one complete handshake. Returns duration in ms."""
        client = MobileAppSimulator(proxy.dsa_public_key)
        t0     = now_ns()
        nonce  = client.initiate_session()
        hs     = proxy.run_handshake(nonce)
        pub    = hs["kem_public_key"]
        client._kem_public_key_received = pub
        ct, _, _ = client.encapsulate(pub)
        decap  = proxy.decapsulate(ct)
        client.verify_and_derive(ct, decap["signature"])
        proxy.end_session()
        return (now_ns() - t0) / 1_000_000.0

    # ── Test 1: Sequential throughput ────────────────────────────────────────
    def _test_throughput(self) -> dict:
        """
        Run STRESS_SESSIONS_TOTAL sessions sequentially as fast as possible.
        Measures: sessions/second, mean latency, memory growth.
        """
        self.logger.info(f"Throughput test: {STRESS_SESSIONS_TOTAL} sequential sessions")
        proxy  = PQCProxy()
        times  = []
        mem_samples = []

        t_wall_start = time.time()
        for i in range(STRESS_SESSIONS_TOTAL):
            times.append(self._run_single_session(proxy))
            if i % 50 == 0:
                mem_samples.append(get_memory_kb())
                self.logger.info(f"  {i}/{STRESS_SESSIONS_TOTAL} | "
                                 f"mem: {mem_samples[-1]:.0f} KB")

        wall_time_s      = time.time() - t_wall_start
        sessions_per_sec = STRESS_SESSIONS_TOTAL / wall_time_s

        # Memory leak check: compare first and last 10% of memory samples
        mem_start = sum(mem_samples[:max(1, len(mem_samples)//5)]) / max(1, len(mem_samples)//5)
        mem_end   = sum(mem_samples[-max(1, len(mem_samples)//5):]) / max(1, len(mem_samples)//5)
        mem_growth_kb = mem_end - mem_start

        stats = compute_stats([int(t * 1_000_000) for t in times])

        return {
            "sessions"           : STRESS_SESSIONS_TOTAL,
            "wall_time_s"        : round(wall_time_s, 2),
            "sessions_per_second": round(sessions_per_sec, 1),
            "latency"            : stats,
            "memory": {
                "start_kb"   : round(mem_start, 1),
                "end_kb"     : round(mem_end, 1),
                "growth_kb"  : round(mem_growth_kb, 1),
                "leak_detected": mem_growth_kb > 5120,  # > 5MB growth = concern
            },
        }

    # ── Test 2: Concurrent sessions ───────────────────────────────────────────
    def _test_concurrent(self, n_threads: int) -> dict:
        self.logger.info(f"Concurrent test: {n_threads} simultaneous sessions")

        # One proxy per thread — correct production model.
        # Each client connection gets its own handler in real deployment.
        # Long-term DSA keypair is generated once and shared (read-only).
        shared_proxy    = PQCProxy()
        shared_dsa_pub  = shared_proxy.dsa_public_key
        shared_dsa_priv = shared_proxy.dsa_private_key

        results = [None] * n_threads
        errors  = [None] * n_threads

        def worker(idx):
            try:
                # Each thread gets its own proxy instance with shared DSA keypair
                thread_proxy = PQCProxy.__new__(PQCProxy)
                thread_proxy.kem_alg            = shared_proxy.kem_alg
                thread_proxy.sig_alg            = shared_proxy.sig_alg
                thread_proxy.dsa_public_key     = shared_dsa_pub
                thread_proxy.dsa_private_key    = shared_dsa_priv
                thread_proxy.session_key        = None
                thread_proxy.session_nonce_registry = set()
                results[idx] = self._run_single_session(thread_proxy)
            except Exception as e:
                errors[idx] = str(e)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(n_threads)]

        t0 = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall_ms = (time.time() - t0) * 1000.0

        successful  = [r for r in results if r is not None]
        failed      = [e for e in errors  if e is not None]
        success_pct = len(successful) / n_threads * 100

        if successful:
            import statistics as st
            mean_ms = round(st.mean(successful), 3)
            max_ms  = round(max(successful), 3)
        else:
            mean_ms = max_ms = 0.0

        throughput = len(successful) / (wall_ms / 1000.0) if wall_ms > 0 else 0

        return {
            "threads"           : n_threads,
            "successful"        : len(successful),
            "failed"            : len(failed),
            "success_rate_pct"  : round(success_pct, 1),
            "mean_latency_ms"   : mean_ms,
            "max_latency_ms"    : max_ms,
            "wall_time_ms"      : round(wall_ms, 1),
            "throughput_per_sec": round(throughput, 1),
            "errors"            : failed[:5],  # first 5 errors only
        }

    # ── Test 3: Extrapolation ─────────────────────────────────────────────────
    def _extrapolate(self, throughput_result: dict) -> dict:
        """
        Given measured sessions/second on Pi 4B (4 cores),
        extrapolate to cloud deployment scenarios.
        """
        sps_single_core = throughput_result["sessions_per_second"] / 4
        return {
            "pi4b_single_core_sps"     : round(sps_single_core, 1),
            "pi4b_all_cores_sps"       : round(sps_single_core * 4, 1),
            "cloud_8core_instance_sps" : round(sps_single_core * 8, 1),
            "cloud_32core_instance_sps": round(sps_single_core * 32, 1),
            "note": (
                "Extrapolation assumes linear scaling per core. "
                "Cloud instances use horizontal scaling; "
                "actual throughput depends on network I/O and load balancer."
            ),
        }

    def run(self) -> dict:
        results = {}

        # Test 1: Throughput
        self.logger.info("\n── Test 1: Sequential Throughput ──")
        results["throughput"] = self._test_throughput()
        self.logger.info(
            f"  ✔ {results['throughput']['sessions_per_second']} sessions/sec | "
            f"mem growth: {results['throughput']['memory']['growth_kb']:.1f} KB"
        )

        # Test 2: Concurrent sessions at each thread count
        self.logger.info("\n── Test 2: Concurrent Sessions ──")
        results["concurrent"] = {}
        for n in STRESS_THREAD_COUNTS:
            r = self._test_concurrent(n)
            results["concurrent"][f"{n}_threads"] = r
            self.logger.info(
                f"  {n:>2} threads: {r['success_rate_pct']}% success | "
                f"{r['mean_latency_ms']:.2f}ms mean | "
                f"{r['throughput_per_sec']:.1f} sess/s"
            )

        # Test 3: Extrapolation
        self.logger.info("\n── Test 3: Cloud Extrapolation ──")
        results["extrapolation"] = self._extrapolate(results["throughput"])
        self.logger.info(
            f"  Pi 4B (4 cores): {results['extrapolation']['pi4b_all_cores_sps']} sess/s"
        )
        self.logger.info(
            f"  Cloud 32-core:   {results['extrapolation']['cloud_32core_instance_sps']} sess/s"
        )

        self.save(results, "stress_benchmarks.json")
        return results
