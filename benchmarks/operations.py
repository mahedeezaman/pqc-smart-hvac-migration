"""
Individual operation benchmarks — KEM, DSA, ECDH.
Latency + memory + energy + artifact sizes.
"""

import os
import gc
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from benchmarks.base import BaseBenchmark
from core.stats import compute_stats
from core.metrics.timer import now_ns, sleep_ms
from core.metrics.memory import get_memory_kb, get_temperature
from infra.config import WARMUP_RUNS, MEASURED_RUNS, SLEEP_BETWEEN_MS, KEM_CONFIGS
import statistics
import time


class OperationsBenchmark(BaseBenchmark):

    def __init__(self):
        super().__init__("operations_benchmark")

    def _check_temp(self):
        t = get_temperature()
        if t > 75:
            self.logger.warning(f"Temp {t}°C — pausing 30s")
            time.sleep(30)

    def _bench_kem(self, kem_alg: str) -> dict:
        self.logger.info(f"  KEM: {kem_alg}")
        raw = {"keygen": [], "encap": [], "decap": []}
        mem = {"keygen": [], "encap": [], "decap": []}

        for _ in range(WARMUP_RUNS):
            k = oqs.KeyEncapsulation(kem_alg)
            p = k.generate_keypair()
            ct, _ = k.encap_secret(p)
            k.decap_secret(ct)

        for i in range(MEASURED_RUNS):
            self._check_temp()

            gc.collect(); m0 = get_memory_kb(); t0 = now_ns()
            k = oqs.KeyEncapsulation(kem_alg); p = k.generate_keypair()
            raw["keygen"].append(now_ns() - t0)
            mem["keygen"].append(max(0.0, get_memory_kb() - m0))
            sleep_ms(SLEEP_BETWEEN_MS)

            gc.collect(); m0 = get_memory_kb(); t0 = now_ns()
            ct, ss = k.encap_secret(p)
            raw["encap"].append(now_ns() - t0)
            mem["encap"].append(max(0.0, get_memory_kb() - m0))
            sleep_ms(SLEEP_BETWEEN_MS)

            gc.collect(); m0 = get_memory_kb(); t0 = now_ns()
            k.decap_secret(ct)
            raw["decap"].append(now_ns() - t0)
            mem["decap"].append(max(0.0, get_memory_kb() - m0))
            sleep_ms(SLEEP_BETWEEN_MS)

            if (i + 1) % 20 == 0:
                self.logger.info(f"    {i+1}/{MEASURED_RUNS}")

        return {
            op: {**compute_stats(raw[op]),
                 "mem_delta_kb": round(statistics.mean(mem[op]), 2)}
            for op in raw
        }

    def _bench_dsa(self, sig_alg: str) -> dict:
        self.logger.info(f"  DSA: {sig_alg}")
        raw = {"sign": [], "verify": []}
        mem = {"sign": [], "verify": []}

        with oqs.Signature(sig_alg) as s:
            pub_key  = s.generate_keypair()
            priv_key = s.export_secret_key()
        message = os.urandom(32 + 1184 + 1088)

        for _ in range(WARMUP_RUNS):
            with oqs.Signature(sig_alg, priv_key) as s:
                sig = s.sign(message)
            with oqs.Signature(sig_alg) as v:
                v.verify(message, sig, pub_key)

        for i in range(MEASURED_RUNS):
            gc.collect(); m0 = get_memory_kb(); t0 = now_ns()
            with oqs.Signature(sig_alg, priv_key) as s:
                sig = s.sign(message)
            raw["sign"].append(now_ns() - t0)
            mem["sign"].append(max(0.0, get_memory_kb() - m0))
            sleep_ms(SLEEP_BETWEEN_MS)

            gc.collect(); m0 = get_memory_kb(); t0 = now_ns()
            with oqs.Signature(sig_alg) as v:
                v.verify(message, sig, pub_key)
            raw["verify"].append(now_ns() - t0)
            mem["verify"].append(max(0.0, get_memory_kb() - m0))
            sleep_ms(SLEEP_BETWEEN_MS)

            if (i + 1) % 20 == 0:
                self.logger.info(f"    {i+1}/{MEASURED_RUNS}")

        return {
            op: {**compute_stats(raw[op]),
                 "mem_delta_kb": round(statistics.mean(mem[op]), 2)}
            for op in raw
        }

    def _bench_ecdh(self) -> dict:
        self.logger.info("  ECDH baseline")
        raw = {"keygen": [], "exchange": [], "sign": [], "verify": []}
        mem = {"keygen": [], "exchange": [], "sign": [], "verify": []}

        signing_key = Ed25519PrivateKey.generate()
        verify_key  = signing_key.public_key()
        message     = os.urandom(96)

        for _ in range(WARMUP_RUNS):
            sk = X25519PrivateKey.generate()
            pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ck = X25519PrivateKey.generate()
            ck.exchange(sk.public_key())
            sig = signing_key.sign(message)
            verify_key.verify(sig, message)

        for i in range(MEASURED_RUNS):
            gc.collect(); m0 = get_memory_kb(); t0 = now_ns()
            sp = X25519PrivateKey.generate()
            sb = sp.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            raw["keygen"].append(now_ns() - t0)
            mem["keygen"].append(max(0.0, get_memory_kb() - m0))
            sleep_ms(SLEEP_BETWEEN_MS)

            gc.collect(); m0 = get_memory_kb(); t0 = now_ns()
            cp = X25519PrivateKey.generate()
            cp.exchange(X25519PublicKey.from_public_bytes(sb))
            raw["exchange"].append(now_ns() - t0)
            mem["exchange"].append(max(0.0, get_memory_kb() - m0))
            sleep_ms(SLEEP_BETWEEN_MS)

            gc.collect(); m0 = get_memory_kb(); t0 = now_ns()
            sig = signing_key.sign(message)
            raw["sign"].append(now_ns() - t0)
            mem["sign"].append(max(0.0, get_memory_kb() - m0))
            sleep_ms(SLEEP_BETWEEN_MS)

            gc.collect(); m0 = get_memory_kb(); t0 = now_ns()
            verify_key.verify(sig, message)
            raw["verify"].append(now_ns() - t0)
            mem["verify"].append(max(0.0, get_memory_kb() - m0))
            sleep_ms(SLEEP_BETWEEN_MS)

            if (i + 1) % 20 == 0:
                self.logger.info(f"    {i+1}/{MEASURED_RUNS}")

        return {
            op: {**compute_stats(raw[op]),
                 "mem_delta_kb": round(statistics.mean(mem[op]), 2)}
            for op in raw
        }

    def _measure_sizes(self, kem_alg: str, sig_alg: str) -> dict:
        k = oqs.KeyEncapsulation(kem_alg)
        p = k.generate_keypair()
        ct, ss = k.encap_secret(p)
        with oqs.Signature(sig_alg) as s:
            sp   = s.generate_keypair()
            sprv = s.export_secret_key()
        with oqs.Signature(sig_alg, sprv) as s:
            sig = s.sign(os.urandom(100))
        return {
            "kem_pk_bytes" : len(p),
            "kem_ct_bytes" : len(ct),
            "kem_ss_bytes" : len(ss),
            "dsa_pk_bytes" : len(sp),
            "dsa_sig_bytes": len(sig),
        }

    def run(self) -> dict:
        import psutil, os as _os
        proc = psutil.Process(_os.getpid())

        def peak_rss_kb():
            return proc.memory_info().rss / 1024.0

        all_results = {}

        self.logger.info("\nECDH Baseline:")
        rss_before = peak_rss_kb()
        all_results["ECDH-X25519+Ed25519"] = self._bench_ecdh()
        all_results["ECDH-X25519+Ed25519"]["peak_rss_kb"] = round(peak_rss_kb() - rss_before, 1)

        for kem_alg, sig_alg in KEM_CONFIGS:
            name = f"{kem_alg}+{sig_alg}"
            self.logger.info(f"\n{name}:")
            rss_before = peak_rss_kb()
            all_results[name] = {
                **self._bench_kem(kem_alg),
                **self._bench_dsa(sig_alg),
                "sizes": self._measure_sizes(kem_alg, sig_alg),
            }
            all_results[name]["peak_rss_kb"] = round(peak_rss_kb() - rss_before, 1)
            self.logger.info(f"  Peak RSS delta: {all_results[name]['peak_rss_kb']} KB")

        self.save(all_results, "operation_benchmarks.json")

        # CSV rows
        rows = []
        for config, ops in all_results.items():
            for op, stats in ops.items():
                if isinstance(stats, dict) and "mean_ms" in stats:
                    rows.append({"config": config, "operation": op, **stats})
        from infra.storage import save_csv
        save_csv("operation_benchmarks.csv", rows)

        return all_results
