"""
Classical ECDH + Ed25519 baseline.
Mirror structure of PQCProxy for fair comparison.
"""

import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from core.metrics.timer import now_ns
from infra.config import NONCE_SIZE

HKDF_INFO = b"HVAC-Classical-AES256GCM-v1"


class ECDHBaseline:
    def __init__(self):
        self.signing_key            = Ed25519PrivateKey.generate()
        self.verify_key             = self.signing_key.public_key()
        self.session_key            = None
        self.session_nonce_registry = set()

    def keygen(self) -> tuple:
        t0 = now_ns()
        self._ephemeral_private = X25519PrivateKey.generate()
        pub_bytes = self._ephemeral_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        keygen_ns = now_ns() - t0
        return pub_bytes, keygen_ns

    def compute_shared_secret(self, client_pub_bytes: bytes,
                               client_nonce: bytes,
                               server_pub_bytes: bytes) -> dict:
        t0 = now_ns()
        shared = self._ephemeral_private.exchange(
            X25519PublicKey.from_public_bytes(client_pub_bytes))
        ecdh_ns = now_ns() - t0

        transcript = client_nonce + server_pub_bytes + client_pub_bytes
        t0 = now_ns()
        signature = self.signing_key.sign(transcript)
        sign_ns = now_ns() - t0

        self.session_key = HKDF(
            algorithm=SHA256(), length=32,
            salt=client_nonce, info=HKDF_INFO,
            backend=default_backend()
        ).derive(shared)
        self.session_nonce_registry = set()
        return {
            "shared_secret": shared,
            "signature"    : signature,
            "session_key"  : self.session_key,
            "ecdh_ns"      : ecdh_ns,
            "sign_ns"      : sign_ns,
        }

    def decrypt_command(self, nonce: bytes, ciphertext: bytes) -> bytes:
        if nonce in self.session_nonce_registry:
            raise ValueError("Replay detected.")
        self.session_nonce_registry.add(nonce)
        return AESGCM(self.session_key).decrypt(nonce, ciphertext, None)

    def encrypt_response(self, plaintext: bytes) -> tuple:
        nonce = os.urandom(NONCE_SIZE)
        return nonce, AESGCM(self.session_key).encrypt(nonce, plaintext, None)


class ECDHClientSimulator:
    def __init__(self, server_verify_key):
        self.server_verify_key = server_verify_key
        self.session_key       = None

    def initiate_session(self) -> bytes:
        self._nonce = os.urandom(32)
        return self._nonce

    def client_keygen_and_exchange(self, server_pub_bytes: bytes) -> tuple:
        t0 = now_ns()
        client_priv      = X25519PrivateKey.generate()
        client_pub_bytes = client_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        shared = client_priv.exchange(
            X25519PublicKey.from_public_bytes(server_pub_bytes))
        exchange_ns = now_ns() - t0
        self._shared           = shared
        self._client_pub_bytes = client_pub_bytes
        self._server_pub_bytes = server_pub_bytes
        return client_pub_bytes, shared, exchange_ns

    def verify_and_derive(self, signature: bytes) -> tuple:
        transcript = self._nonce + self._server_pub_bytes + self._client_pub_bytes
        t0 = now_ns()
        self.server_verify_key.verify(signature, transcript)
        verify_ns = now_ns() - t0
        self.session_key = HKDF(
            algorithm=SHA256(), length=32,
            salt=self._nonce, info=HKDF_INFO,
            backend=default_backend()
        ).derive(self._shared)
        return self.session_key, verify_ns

    def encrypt_command(self, command: str) -> tuple:
        nonce = os.urandom(NONCE_SIZE)
        return nonce, AESGCM(self.session_key).encrypt(nonce, command.encode(), None)

    def decrypt_response(self, nonce: bytes, ciphertext: bytes) -> str:
        return AESGCM(self.session_key).decrypt(nonce, ciphertext, None).decode()
