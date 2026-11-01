"""
PQC Proxy Layer and Mobile App Simulator.
Pure crypto logic — no I/O, no logging, no config reads.
"""

import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from core.metrics.timer import now_ns, ns_to_ms
from infra.config import HKDF_INFO, NONCE_SIZE, PRIMARY_KEM, PRIMARY_SIG


def _zero_bytearray(ba: bytearray) -> None:
    """Overwrite every byte of a bytearray in place with zero."""
    if ba is None:
        return
    for i in range(len(ba)):
        ba[i] = 0


class PQCProxy:
    """
    Represents the PQC proxy layer.
    Long-term ML-DSA signing keypair is generated once at startup.
    Per-session: fresh ML-KEM keypair generated each time.
    """

    def __init__(self, kem_alg: str = PRIMARY_KEM, sig_alg: str = PRIMARY_SIG):
        self.kem_alg = kem_alg
        self.sig_alg = sig_alg
        with oqs.Signature(sig_alg) as signer:
            self.dsa_public_key  = signer.generate_keypair()
            self.dsa_private_key = signer.export_secret_key()
        self._reset_session()

    def _reset_session(self):
        self.session_key            = None
        self.session_nonce_registry = set()

    def run_handshake(self, client_nonce: bytes) -> dict:
        """Step 2: KeyGen — returns public key and timing."""
        t0  = now_ns()
        kem = oqs.KeyEncapsulation(self.kem_alg)
        pub = kem.generate_keypair()
        keygen_ns = now_ns() - t0
        self._kem            = kem
        self._kem_public_key = pub
        self._client_nonce   = client_nonce
        return {"kem_public_key": pub, "keygen_ns": keygen_ns}

    def decapsulate(self, ciphertext: bytes) -> dict:
        """Steps 4+5: Decapsulate + Sign + Derive session key."""
        t0            = now_ns()
        shared_secret = self._kem.decap_secret(ciphertext)
        decap_ns      = now_ns() - t0

        transcript = self._client_nonce + self._kem_public_key + ciphertext
        t0 = now_ns()
        with oqs.Signature(self.sig_alg, self.dsa_private_key) as signer:
            signature = signer.sign(transcript)
        sign_ns = now_ns() - t0

        derived_key = HKDF(
            algorithm=SHA256(), length=32,
            salt=self._client_nonce, info=HKDF_INFO,
            backend=default_backend()
        ).derive(shared_secret)

        # Store as bytearray (mutable) so end_session() can zero it in place.
        # HKDF.derive() returns immutable bytes, so we copy into a bytearray here.
        self.session_key            = bytearray(derived_key)
        self.session_nonce_registry = set()

        return {
            "shared_secret": shared_secret,
            "signature"    : signature,
            "session_key"  : bytes(self.session_key),  # caller gets a plain-bytes view
            "decap_ns"     : decap_ns,
            "sign_ns"      : sign_ns,
        }

    def decrypt_command(self, nonce: bytes, ciphertext: bytes) -> bytes:
        if self.session_key is None:
            raise RuntimeError("No session established.")
        if nonce in self.session_nonce_registry:
            raise ValueError("Replay detected.")
        self.session_nonce_registry.add(nonce)
        # AESGCM requires bytes; this creates a transient copy for the
        # duration of the call. The long-lived buffer (self.session_key)
        # remains the bytearray that end_session() can zero.
        return AESGCM(bytes(self.session_key)).decrypt(nonce, ciphertext, None)

    def encrypt_response(self, plaintext: bytes) -> tuple:
        if self.session_key is None:
            raise RuntimeError("No session established.")
        nonce = os.urandom(NONCE_SIZE)
        return nonce, AESGCM(bytes(self.session_key)).encrypt(nonce, plaintext, None)

    def end_session(self):
        """Zero the session key buffer in place, release the ML-KEM keypair
        object, then reset session state. DSA keypair is preserved."""
        _zero_bytearray(self.session_key)
        if hasattr(self, "_kem") and self._kem is not None:
            self._kem = None
        self._kem_public_key = None
        self._client_nonce = None
        self._reset_session()


class MobileAppSimulator:
    """Simulates the mobile application client."""

    def __init__(self, proxy_dsa_public_key: bytes,
                 kem_alg: str = PRIMARY_KEM,
                 sig_alg: str = PRIMARY_SIG):
        self.proxy_dsa_public_key = proxy_dsa_public_key
        self.kem_alg   = kem_alg
        self.sig_alg   = sig_alg
        self.session_key = None

    def initiate_session(self) -> bytes:
        self._nonce = os.urandom(32)
        return self._nonce

    def encapsulate(self, kem_public_key: bytes) -> tuple:
        """Step 3: Encapsulate — returns (ciphertext, shared_secret, encap_ns)."""
        t0 = now_ns()
        with oqs.KeyEncapsulation(self.kem_alg) as kem:
            ciphertext, shared_secret = kem.encap_secret(kem_public_key)
        encap_ns = now_ns() - t0
        self._shared_secret             = shared_secret
        self._kem_public_key_received   = kem_public_key
        return ciphertext, shared_secret, encap_ns

    def verify_and_derive(self, ciphertext: bytes, signature: bytes) -> tuple:
        """Step 6: Verify ML-DSA signature and derive session key."""
        transcript = self._nonce + self._kem_public_key_received + ciphertext
        t0 = now_ns()
        with oqs.Signature(self.sig_alg) as verifier:
            valid = verifier.verify(transcript, signature, self.proxy_dsa_public_key)
        verify_ns = now_ns() - t0
        if not valid:
            raise ValueError("ML-DSA verification FAILED. Possible MITM.")
        derived_key = HKDF(
            algorithm=SHA256(), length=32,
            salt=self._nonce, info=HKDF_INFO,
            backend=default_backend()
        ).derive(self._shared_secret)
        self.session_key = bytearray(derived_key)
        return bytes(self.session_key), verify_ns

    def encrypt_command(self, command: str) -> tuple:
        nonce = os.urandom(NONCE_SIZE)
        return nonce, AESGCM(bytes(self.session_key)).encrypt(nonce, command.encode(), None)

    def decrypt_response(self, nonce: bytes, ciphertext: bytes) -> str:
        return AESGCM(bytes(self.session_key)).decrypt(nonce, ciphertext, None).decode()

    def end_session(self):
        """Zero the client-side session key buffer in place."""
        _zero_bytearray(self.session_key)
        self.session_key = None