"""ESP32 infeasibility result reader and validator."""

from infra.logger import get_logger
from infra.storage import load_json

logger = get_logger("esp32_analysis")


def validate_esp32_results() -> dict:
    logger.info("ESP32-S3 Infeasibility Check")
    try:
        esp = load_json("esp32_results.json")
    except FileNotFoundError:
        logger.warning("esp32_results.json not found. Deploy Arduino sketch first.")
        return {"available": False}

    free_kb     = esp.get("free_heap_bytes", 0) / 1024
    required_kb = esp.get("mlkem768_required_bytes", 921600) / 1024
    feasible    = esp.get("mlkem768_feasible", True)
    malloc_ok   = esp.get("malloc_900kb_succeeded", True)
    confirmed   = not feasible and not malloc_ok

    aes_ms  = esp.get("aes128_mean_ms", None)
    ecdh_ms = esp.get("ecdh_keygen_mean_ms", None)

    logger.info(f"  Free heap      : {free_kb:.1f} KB")
    logger.info(f"  ML-KEM-768     : {required_kb:.1f} KB required")
    logger.info(f"  malloc(900KB)  : {'succeeded' if malloc_ok else 'FAILED'}")
    logger.info(f"  Infeasibility  : {'confirmed' if confirmed else 'NOT confirmed'}")
    if aes_ms:
        logger.info(f"  AES-128 mean   : {aes_ms:.4f} ms (device CAN do this)")
    if ecdh_ms:
        logger.info(f"  ECDH keygen    : {ecdh_ms:.4f} ms (device CAN do this)")

    return {
        "available"              : True,
        "platform"               : esp.get("platform", "ESP32-S3"),
        "cpu_mhz"                : esp.get("cpu_mhz"),
        "sram_bytes"             : esp.get("sram_bytes"),
        "psram_bytes"            : esp.get("psram_bytes", 0),
        "free_heap_bytes"        : esp.get("free_heap_bytes"),
        "free_heap_kb"           : round(free_kb, 1),
        "mlkem768_required_bytes": esp.get("mlkem768_required_bytes", 921600),
        "mlkem768_required_kb"   : round(required_kb, 1),
        "malloc_900kb_succeeded" : malloc_ok,
        "mlkem768_feasible"      : feasible,
        "infeasibility_confirmed": confirmed,
        "classical_crypto": {
            "aes128_mean_ms"     : aes_ms,
            "ecdh_keygen_mean_ms": ecdh_ms,
            "note": (
                "Device successfully runs AES-128 and ECDH — confirming it handles "
                "classical cryptography. ML-KEM-768 failure is memory-specific, "
                "not a general compute limitation."
            ),
        },
        "interpretation": (
            "ML-KEM-768 infeasibility on ESP32-S3 confirmed. "
            f"Device has {free_kb:.0f} KB free heap; "
            f"ML-KEM-768 requires {required_kb:.0f} KB. "
            "malloc(900KB) failed. Device successfully runs AES-128 and ECDH, "
            "confirming the constraint is memory-specific. "
            "Empirically validates conference paper claim."
            if confirmed else
            "Unexpected result — review esp32_results.json manually."
        ),
    }
