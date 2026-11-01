"""Integration test — ECDH baseline."""

from core.crypto.ecdh_baseline import ECDHBaseline, ECDHClientSimulator
from infra.logger import get_logger

logger = get_logger("test_ecdh")


def test_ecdh_baseline():
    logger.info("=== Integration Test: ECDH Baseline ===")
    server = ECDHBaseline()
    client = ECDHClientSimulator(server.verify_key)

    nonce = client.initiate_session()
    sp, kg_ns = server.keygen()
    logger.info(f"KeyGen ✓ | {kg_ns/1e6:.3f} ms | {len(sp)} bytes")

    cp, ss_client, exc_ns = client.client_keygen_and_exchange(sp)
    logger.info(f"Exchange ✓ | {exc_ns/1e6:.3f} ms")

    result = server.compute_shared_secret(cp, nonce, sp)
    logger.info(f"Sign ✓ | {result['sign_ns']/1e6:.3f} ms")
    assert ss_client == result["shared_secret"], "Shared secret mismatch!"

    sk_client, ver_ns = client.verify_and_derive(result["signature"])
    logger.info(f"Verify ✓ | {ver_ns/1e6:.3f} ms")
    assert sk_client == result["session_key"], "Session key mismatch!"

    cmd_nonce, cmd_ct = client.encrypt_command("SET_TEMP:22")
    assert server.decrypt_command(cmd_nonce, cmd_ct) == b"SET_TEMP:22"

    resp_nonce, resp_ct = server.encrypt_response(b"ACK:22")
    assert client.decrypt_response(resp_nonce, resp_ct) == "ACK:22"

    logger.info("=== ECDH BASELINE ALL PASSED ✓ ===")


if __name__ == "__main__":
    test_ecdh_baseline()
