"""Network latency simulation benchmark."""

import time
from benchmarks.base import BaseBenchmark
from core.crypto.pqc_proxy import PQCProxy, MobileAppSimulator
from core.stats import compute_stats
from core.metrics.timer import now_ns, sleep_ms
from infra.config import WARMUP_RUNS, MEASURED_RUNS, SLEEP_BETWEEN_MS, NETWORK_RTTS_MS


class NetworkBenchmark(BaseBenchmark):

    def __init__(self):
        super().__init__("network_benchmark")

    def _run_with_rtt(self, rtt_ms: float) -> list:
        proxy     = PQCProxy()
        client    = MobileAppSimulator(proxy.dsa_public_key)
        one_way_s = (rtt_ms / 2) / 1000.0
        times     = []

        def one_session():
            t0    = now_ns()
            nonce = client.initiate_session()
            time.sleep(one_way_s)

            hs  = proxy.run_handshake(nonce)
            pub = hs["kem_public_key"]
            time.sleep(one_way_s)
            client._kem_public_key_received = pub

            ct, _, _ = client.encapsulate(pub)
            time.sleep(one_way_s)

            decap = proxy.decapsulate(ct)
            time.sleep(one_way_s)

            client.verify_and_derive(ct, decap["signature"])
            t_total = now_ns() - t0
            proxy.end_session()
            return t_total

        for _ in range(WARMUP_RUNS):
            one_session()
            proxy  = PQCProxy()
            client = MobileAppSimulator(proxy.dsa_public_key)

        for i in range(MEASURED_RUNS):
            times.append(one_session())
            proxy  = PQCProxy()
            client = MobileAppSimulator(proxy.dsa_public_key)
            sleep_ms(SLEEP_BETWEEN_MS)
            if (i + 1) % 20 == 0:
                self.logger.info(f"  RTT={rtt_ms}ms: {i+1}/{MEASURED_RUNS}")

        return times

    def run(self) -> dict:
        results = {}
        for rtt in NETWORK_RTTS_MS:
            self.logger.info(f"\nRTT: {rtt} ms")
            stats = compute_stats(self._run_with_rtt(rtt))
            results[f"rtt_{rtt}ms"] = {"network_rtt_ms": rtt, **stats}

        self.save(results, "network_benchmarks.json")
        return results
