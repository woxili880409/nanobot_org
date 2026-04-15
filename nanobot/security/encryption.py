"""AES-256-GCM encryption for session data and message bus transport."""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    pass

_NONCE_SIZE = 12  # 96-bit nonce recommended for AES-GCM
_KEY_SIZE = 32    # 256-bit key


class AESGCMCipher:
    """Low-level AES-256-GCM encrypt/decrypt primitive."""

    def __init__(self, key_b64: str) -> None:
        raw = base64.b64decode(key_b64.strip())
        if len(raw) != _KEY_SIZE:
            raise ValueError(
                f"Encryption key must be {_KEY_SIZE} bytes ({_KEY_SIZE * 8} bits), "
                f"got {len(raw)} bytes. "
                f"Generate one with: python -c \"import secrets,base64; "
                f"print(base64.b64encode(secrets.token_bytes({_KEY_SIZE})).decode())\""
            )
        self._aesgcm = AESGCM(raw)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext* and return a base64-encoded token (nonce + ciphertext+tag)."""
        nonce = os.urandom(_NONCE_SIZE)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + ct).decode("ascii")

    def decrypt(self, token: str) -> str:
        """Decrypt a token produced by :meth:`encrypt` and return the original plaintext."""
        raw = base64.b64decode(token)
        nonce, ct = raw[:_NONCE_SIZE], raw[_NONCE_SIZE:]
        return self._aesgcm.decrypt(nonce, ct, None).decode("utf-8")


class SessionEncryption:
    """Encrypt/decrypt individual messages stored in a conversation session.

    Only ``user`` and ``assistant`` role messages are encrypted;
    ``system`` messages remain in plain text for easier debugging.
    """

    ENCRYPTED_ROLES: frozenset[str] = frozenset({"user", "assistant"})

    def __init__(self, security_config: Any) -> None:
        self._enabled = False
        self._cipher: AESGCMCipher | None = None

        if security_config is None or not getattr(security_config, "enable_session_encryption", False):
            return

        key = os.environ.get("NANOBOT_ENCRYPTION_KEY") or getattr(security_config, "encryption_key", "")
        if not key:
            return

        try:
            self._cipher = AESGCMCipher(key)
            self._enabled = True
        except Exception as exc:
            raise RuntimeError(f"Failed to initialise session encryption: {exc}") from exc

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _should_encrypt(self, msg: dict[str, Any]) -> bool:
        return self._enabled and msg.get("role") in self.ENCRYPTED_ROLES

    def encrypt_message(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Return an encrypted copy of *msg* (only content is encrypted)."""
        if not self._should_encrypt(msg) or self._cipher is None:
            return msg

        content = msg.get("content")
        if not content or not isinstance(content, str):
            return msg

        copy = dict(msg)
        copy["content"] = self._cipher.encrypt(content)
        copy["_encrypted"] = True
        copy["_encryption_version"] = "1.0"
        return copy

    def decrypt_message(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Return a decrypted copy of *msg*, stripping internal encryption fields."""
        if not msg.get("_encrypted") or self._cipher is None:
            return msg

        content = msg.get("content")
        if not content or not isinstance(content, str):
            return msg

        copy = dict(msg)
        try:
            copy["content"] = self._cipher.decrypt(content)
        except Exception:
            # If decryption fails (wrong key / corrupt data), return as-is so
            # the session is still loadable — just with garbled content.
            return msg

        copy.pop("_encrypted", None)
        copy.pop("_encryption_version", None)
        return copy


class TransportEncryption:
    """Encrypt/decrypt messages flowing through the :class:`MessageBus`.

    The encrypted payload is stored in ``content``; a metadata flag
    ``_transport_encrypted`` marks whether the message is encrypted so
    that :meth:`decrypt_message` can safely skip unencrypted messages.
    """

    _META_FLAG = "_transport_encrypted"

    def __init__(self, security_config: Any) -> None:
        self._enabled = False
        self._cipher: AESGCMCipher | None = None

        if security_config is None or not getattr(security_config, "enable_transport_encryption", False):
            return

        key = os.environ.get("NANOBOT_TRANSPORT_KEY") or getattr(security_config, "transport_key", "")
        if not key:
            return

        try:
            self._cipher = AESGCMCipher(key)
            self._enabled = True
        except Exception as exc:
            raise RuntimeError(f"Failed to initialise transport encryption: {exc}") from exc

    @property
    def enabled(self) -> bool:
        return self._enabled

    def encrypt_message(self, content: str, metadata: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Encrypt *content* and mark *metadata* with the encrypted flag."""
        if not self._enabled or self._cipher is None:
            return content, metadata

        encrypted_content = self._cipher.encrypt(content)
        updated_metadata = dict(metadata)
        updated_metadata[self._META_FLAG] = True
        return encrypted_content, updated_metadata

    def decrypt_message(self, content: str, metadata: dict[str, Any]) -> str:
        """Decrypt *content* if it was encrypted, otherwise return as-is."""
        if not self._enabled or self._cipher is None:
            return content
        if not metadata.get(self._META_FLAG):
            return content

        try:
            return self._cipher.decrypt(content)
        except Exception:
            return content
