"""End-to-end handshake benchmark — Steps 1-9."""

from benchmarks.base import BaseBenchmark
from core.crypto.pqc_proxy import PQCProxy, MobileAppSimulator
from core.crypto.ecdh_baseline import ECDHBaseline, ECDHClientSimulator
from core.stats import compute_stats
from core.metrics.timer import now_ns, sleep_ms
from infra.config import WARMUP_RUNS, MEASURED_RUNS, SLEEP_BETWEEN_MS


class E2EBenchmark(BaseBenchmark):

    def __init__(self):
        super().__init__("e2e_benchmark")

    def _run_pqc_session(self, proxy: PQCProxy, client: MobileAppSimulator) -> tuple:
        t0    = now_ns()
        nonce = client.initiate_session()
        hs    = proxy.run_handshake(nonce)
        pub   = hs["kem_public_key"]
        client._kem_public_key_received = pub
        ct, _, _ = client.encapsulate(pub)
        decap = proxy.decapsulate(ct)
        client.verify_and_derive(ct, decap["signature"])
        t_hs = now_ns() - t0

        t0 = now_ns()
        cmd_nonce, cmd_ct = client.encrypt_command("SET_TEMP:22")
        t_enc = now_ns() - t0

        t0 = now_ns()
        proxy.decrypt_command(cmd_nonce, cmd_ct)
        t_dec = now_ns() - t0

        proxy.end_session()
        return t_hs, t_enc, t_dec

    def _run_ecdh_session(self, server: ECDHBaseline,
                          client: ECDHClientSimulator) -> tuple:
        t0     = now_ns()
        nonce  = client.initiate_session()
        sp, _  = server.keygen()
        cp, _, _ = client.client_keygen_and_exchange(sp)
        result = server.compute_shared_secret(cp, nonce, sp)
        client.verify_and_derive(result["signature"])
        t_hs = now_ns() - t0

        t0 = now_ns()
        cmd_nonce, cmd_ct = client.encrypt_command("SET_TEMP:22")
        t_enc = now_ns() - t0

        t0 = now_ns()
        server.decrypt_command(cmd_nonce, cmd_ct)
        t_dec = now_ns() - t0

        return t_hs, t_enc, t_dec

    def _bench_pqc(self) -> dict:
        self.logger.info("PQC handshake (ML-KEM-768 + ML-DSA-65)...")
        proxy  = PQCProxy()
        client = MobileAppSimulator(proxy.dsa_public_key)
        hs_t, enc_t, dec_t = [], [], []

        for _ in range(WARMUP_RUNS):
            self._run_pqc_session(proxy, client)
            client = MobileAppSimulator(proxy.dsa_public_key)

        for i in range(MEASURED_RUNS):
            th, te, td = self._run_pqc_session(proxy, client)
            hs_t.append(th); enc_t.append(te); dec_t.append(td)
            client = MobileAppSimulator(proxy.dsa_public_key)
            sleep_ms(SLEEP_BETWEEN_MS)
            if (i + 1) % 20 == 0:
                self.logger.info(f"  {i+1}/{MEASURED_RUNS}")

        return {
            "handshake_steps1to6": compute_stats(hs_t),
            "command_encrypt"    : compute_stats(enc_t),
            "command_decrypt"    : compute_stats(dec_t),
        }

    def _bench_ecdh(self) -> dict:
        self.logger.info("ECDH handshake (baseline)...")
        server = ECDHBaseline()
        client = ECDHClientSimulator(server.verify_key)
        hs_t, enc_t, dec_t = [], [], []

        for _ in range(WARMUP_RUNS):
            self._run_ecdh_session(server, client)
            client = ECDHClientSimulator(server.verify_key)

        for i in range(MEASURED_RUNS):
            th, te, td = self._run_ecdh_session(server, client)
            hs_t.append(th); enc_t.append(te); dec_t.append(td)
            client = ECDHClientSimulator(server.verify_key)
            sleep_ms(SLEEP_BETWEEN_MS)
            if (i + 1) % 20 == 0:
                self.logger.info(f"  {i+1}/{MEASURED_RUNS}")

        return {
            "handshake_steps1to6": compute_stats(hs_t),
            "command_encrypt"    : compute_stats(enc_t),
            "command_decrypt"    : compute_stats(dec_t),
        }

    def run(self) -> dict:
        results = {
            "note"             : "Long-term DSA keypair persists. Session state resets per run.",
            "ECDH_baseline"    : self._bench_ecdh(),
            "ML-KEM-768_proxy" : self._bench_pqc(),
        }
        self.save(results, "e2e_benchmarks.json")
        return results
