"""Integration test — full 9-step PQC handshake."""

from core.crypto.pqc_proxy import PQCProxy, MobileAppSimulator
from infra.logger import get_logger

logger = get_logger("test_pqc")


def test_full_handshake():
    logger.info("=== Integration Test: Full 9-Step PQC Handshake ===")
    proxy  = PQCProxy()
    client = MobileAppSimulator(proxy.dsa_public_key)

    nonce = client.initiate_session()
    logger.info(f"Step 1 ✓ | nonce: {len(nonce)} bytes")

    hs  = proxy.run_handshake(nonce)
    pub = hs["kem_public_key"]
    logger.info(f"Step 2 ✓ | pk: {len(pub)} B | KeyGen: {hs['keygen_ns']/1e6:.3f} ms")

    client._kem_public_key_received = pub
    ct, ss_client, enc_ns = client.encapsulate(pub)
    logger.info(f"Step 3 ✓ | ct: {len(ct)} B | Encap: {enc_ns/1e6:.3f} ms")

    decap = proxy.decapsulate(ct)
    logger.info(f"Step 4 ✓ | Decap: {decap['decap_ns']/1e6:.3f} ms")
    logger.info(f"Step 5 ✓ | sig: {len(decap['signature'])} B | Sign: {decap['sign_ns']/1e6:.3f} ms")

    assert ss_client == decap["shared_secret"], "Shared secret mismatch!"
    logger.info("Shared secret match ✓")

    sk_client, ver_ns = client.verify_and_derive(ct, decap["signature"])
    logger.info(f"Step 6 ✓ | Verify: {ver_ns/1e6:.3f} ms")
    assert sk_client == decap["session_key"], "Session key mismatch!"
    logger.info("Session key match ✓")

    cmd_nonce, cmd_ct = client.encrypt_command("SET_TEMP:22")
    logger.info(f"Step 7 ✓ | cmd ct: {len(cmd_ct)} bytes")

    plaintext = proxy.decrypt_command(cmd_nonce, cmd_ct)
    assert plaintext == b"SET_TEMP:22", "Command decrypt failed!"
    logger.info(f"Step 8 ✓ | decrypted: {plaintext.decode()}")

    resp_nonce, resp_ct = proxy.encrypt_response(b"ACK:22")
    response = client.decrypt_response(resp_nonce, resp_ct)
    assert response == "ACK:22", "Response decrypt failed!"
    logger.info(f"Step 9 ✓ | response: {response}")

    proxy.end_session()
    logger.info("\n=== ALL 9 STEPS PASSED ✓ ===")


if __name__ == "__main__":
    test_full_handshake()
