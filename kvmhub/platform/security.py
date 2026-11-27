"""Password hashing and credential encryption for the control plane."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

import bcrypt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12
BCRYPT_ROUNDS = 12


def _prehash(password: str) -> bytes:
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def _key_id(key: bytes | None) -> str:
    if key is None:
        return ""
    return hashlib.sha256(key).hexdigest()[:16]


def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("password must have at least 8 characters")
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    if not isinstance(password, str) or not isinstance(hashed, str):
        return False
    try:
        return bcrypt.checkpw(_prehash(password), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


class CredentialCipher:

    def __init__(self, key: bytes | None, previous_key: bytes | None = None):
        if key is not None and len(key) != 32:
            raise ValueError("credential key must be 32 bytes")
        if previous_key is not None and len(previous_key) != 32:
            raise ValueError("previous credential key must be 32 bytes")
        self._aead = AESGCM(key) if key is not None else None
        self._previous = AESGCM(previous_key) if previous_key is not None else None
        self.version = 2 if previous_key is not None else 1
        self.key_id = _key_id(key)
        self.previous_key_id = _key_id(previous_key)

    @property
    def available(self) -> bool:
        return self._aead is not None

    def encrypt(self, plaintext: str, *, aad: str) -> bytes:
        if self._aead is None:
            raise RuntimeError("credential master key is not configured")
        if not isinstance(plaintext, str):
            raise ValueError("plaintext must be str")
        nonce = secrets.token_bytes(NONCE_BYTES)
        return nonce + self._aead.encrypt(nonce, plaintext.encode("utf-8"),
                                          aad.encode("utf-8"))

    def decrypt_current(self, blob: bytes, *, aad: str) -> str:
        if self._aead is None:
            raise RuntimeError("credential master key is not configured")
        raw = bytes(blob)
        return self._aead.decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:],
                                  aad.encode("utf-8")).decode("utf-8")

    def decrypt(self, blob: bytes, *, aad: str) -> str:
        if self._aead is None:
            raise RuntimeError("credential master key is not configured")
        if not isinstance(blob, (bytes, bytearray)) or len(blob) <= NONCE_BYTES + 16:
            raise ValueError("ciphertext is truncated")
        raw = bytes(blob)
        try:
            plaintext = self._aead.decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:],
                                           aad.encode("utf-8"))
        except InvalidTag:
            if self._previous is None:
                raise
            plaintext = self._previous.decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:],
                                                aad.encode("utf-8"))
        return plaintext.decode("utf-8")
