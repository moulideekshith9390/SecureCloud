"""AES-256-GCM encryption/decryption module for SecureCloud Database Proxy."""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

NONCE_SIZE = 12  # 96-bit nonce for AES-GCM
KEY_SIZE = 32    # 256-bit key
SALT_SIZE = 16   # 128-bit salt


class AESGCMCipher:
      """AES-256-GCM cipher for encrypting and decrypting query payloads.

          Each encryption call uses a unique random nonce. The returned bytes
              include the nonce prefix and GCM authentication tag, so both
                  confidentiality and integrity are guaranteed.
                      """

    def __init__(self, master_key: bytes):
              if len(master_key) != KEY_SIZE:
                            raise ValueError(f"Key must be {KEY_SIZE} bytes")
                        self._master_key = master_key

    @classmethod
    def from_password(cls, password: str, salt: bytes = None):
              """Derive an AES-256 key from a password using PBKDF2-HMAC-SHA256."""
        if salt is None:
                      salt = os.urandom(SALT_SIZE)
                  kdf = PBKDF2HMAC(
                                algorithm=hashes.SHA256(),
                                length=KEY_SIZE,
                                salt=salt,
                                iterations=600_000,
                                backend=default_backend()
                  )
        key = kdf.derive(password.encode("utf-8"))
        instance = cls(key)
        instance._salt = salt
        return instance

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
              """Encrypt plaintext. Returns nonce + ciphertext + auth_tag."""
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(self._master_key)
        ct = aesgcm.encrypt(nonce, plaintext, aad or None)
        return nonce + ct

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
              """Decrypt ciphertext. Raises InvalidTag on authentication failure."""
        if len(data) < NONCE_SIZE + 16:
                      raise ValueError("Ciphertext too short")
                  nonce, ct = data[:NONCE_SIZE], data[NONCE_SIZE:]
        aesgcm = AESGCM(self._master_key)
        return aesgcm.decrypt(nonce, ct, aad or None)


def derive_session_key(master_key: bytes, session_id: str) -> bytes:
      """Derive a per-session encryption key using PBKDF2."""
    return hashlib.pbkdf2_hmac(
              "sha256", master_key, session_id.encode("utf-8"),
              iterations=100_000, dklen=KEY_SIZE
    )
