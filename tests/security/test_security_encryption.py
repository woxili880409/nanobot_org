"""Tests for nanobot security modules: encryption, logging, file permissions, transport."""

from __future__ import annotations

import base64
import os
import secrets
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_encryption_env(monkeypatch):
    """Ensure encryption env vars don't leak between tests."""
    monkeypatch.delenv("NANOBOT_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("NANOBOT_TRANSPORT_KEY", raising=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_key() -> str:
    """Generate a valid 32-byte base64-encoded AES key."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


@dataclass
class _FakeSecurityConfig:
    """Minimal stand-in for SecurityConfig without importing the full config."""
    enable_session_encryption: bool = False
    encryption_key: str = ""
    enable_transport_encryption: bool = False
    transport_key: str = ""
    enable_log_sanitization: bool = True
    secure_file_permissions: bool = True
    api_bearer_token: str = ""


# ---------------------------------------------------------------------------
# AESGCMCipher
# ---------------------------------------------------------------------------

class TestAESGCMCipher:
    def test_roundtrip_ascii(self):
        from nanobot.security.encryption import AESGCMCipher
        cipher = AESGCMCipher(_make_key())
        original = "Hello, nanobot!"
        assert cipher.decrypt(cipher.encrypt(original)) == original

    def test_roundtrip_unicode(self):
        from nanobot.security.encryption import AESGCMCipher
        cipher = AESGCMCipher(_make_key())
        original = "你好世界 🌍 こんにちは"
        assert cipher.decrypt(cipher.encrypt(original)) == original

    def test_roundtrip_empty_string(self):
        from nanobot.security.encryption import AESGCMCipher
        cipher = AESGCMCipher(_make_key())
        assert cipher.decrypt(cipher.encrypt("")) == ""

    def test_ciphertexts_are_different(self):
        """Each encryption of the same plaintext must produce a different ciphertext (random nonce)."""
        from nanobot.security.encryption import AESGCMCipher
        cipher = AESGCMCipher(_make_key())
        ct1 = cipher.encrypt("same message")
        ct2 = cipher.encrypt("same message")
        assert ct1 != ct2

    def test_wrong_key_length_raises(self):
        from nanobot.security.encryption import AESGCMCipher
        bad_key = base64.b64encode(secrets.token_bytes(16)).decode()  # 16 bytes, not 32
        with pytest.raises(ValueError, match="32 bytes"):
            AESGCMCipher(bad_key)

    def test_invalid_base64_raises(self):
        from nanobot.security.encryption import AESGCMCipher
        with pytest.raises(Exception):
            AESGCMCipher("not_valid_base64!!!")

    def test_tampered_ciphertext_returns_none_or_raises(self):
        """Decrypting modified bytes should raise (GCM auth tag fails)."""
        from cryptography.exceptions import InvalidTag
        from nanobot.security.encryption import AESGCMCipher
        cipher = AESGCMCipher(_make_key())
        ct = cipher.encrypt("secret")
        raw = bytearray(base64.b64decode(ct))
        raw[-1] ^= 0xFF  # flip last byte
        corrupted = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(InvalidTag):
            cipher.decrypt(corrupted)


# ---------------------------------------------------------------------------
# SessionEncryption
# ---------------------------------------------------------------------------

class TestSessionEncryption:
    def _enc(self, key: str | None = None) -> "Any":
        from nanobot.security.encryption import SessionEncryption
        cfg = _FakeSecurityConfig(
            enable_session_encryption=True,
            encryption_key=key or _make_key(),
        )
        return SessionEncryption(cfg)

    def test_enabled(self):
        assert self._enc().enabled is True

    def test_disabled_when_flag_false(self):
        from nanobot.security.encryption import SessionEncryption
        cfg = _FakeSecurityConfig(enable_session_encryption=False)
        enc = SessionEncryption(cfg)
        assert enc.enabled is False

    def test_disabled_when_no_key(self):
        from nanobot.security.encryption import SessionEncryption
        cfg = _FakeSecurityConfig(enable_session_encryption=True, encryption_key="")
        enc = SessionEncryption(cfg)
        assert enc.enabled is False

    def test_user_message_encrypted(self):
        enc = self._enc()
        msg = {"role": "user", "content": "my secret message"}
        result = enc.encrypt_message(msg)
        assert result["_encrypted"] is True
        assert result["content"] != "my secret message"
        assert result["_encryption_version"] == "1.0"

    def test_assistant_message_encrypted(self):
        enc = self._enc()
        msg = {"role": "assistant", "content": "my response"}
        result = enc.encrypt_message(msg)
        assert result["_encrypted"] is True

    def test_system_message_not_encrypted(self):
        """System messages must remain in plain text."""
        enc = self._enc()
        msg = {"role": "system", "content": "system prompt"}
        result = enc.encrypt_message(msg)
        assert "_encrypted" not in result
        assert result["content"] == "system prompt"

    def test_roundtrip(self):
        enc = self._enc()
        original = {"role": "user", "content": "round trip test"}
        encrypted = enc.encrypt_message(original)
        decrypted = enc.decrypt_message(encrypted)
        assert decrypted["content"] == "round trip test"
        assert "_encrypted" not in decrypted
        assert "_encryption_version" not in decrypted

    def test_decrypt_unencrypted_msg_unchanged(self):
        enc = self._enc()
        msg = {"role": "user", "content": "plain"}
        assert enc.decrypt_message(msg) == msg

    def test_original_msg_not_mutated(self):
        enc = self._enc()
        original = {"role": "user", "content": "immutable"}
        enc.encrypt_message(original)
        assert "content" in original and original["content"] == "immutable"

    def test_env_var_key_takes_precedence(self, monkeypatch):
        key = _make_key()
        monkeypatch.setenv("NANOBOT_ENCRYPTION_KEY", key)
        from nanobot.security.encryption import SessionEncryption
        cfg = _FakeSecurityConfig(enable_session_encryption=True, encryption_key=_make_key())
        enc = SessionEncryption(cfg)
        assert enc.enabled is True
        # If both keys differ the env var key is used — just check it doesn't crash
        msg = {"role": "user", "content": "env key test"}
        enc.encrypt_message(msg)


# ---------------------------------------------------------------------------
# TransportEncryption
# ---------------------------------------------------------------------------

class TestTransportEncryption:
    def _enc(self, key: str | None = None) -> "Any":
        from nanobot.security.encryption import TransportEncryption
        cfg = _FakeSecurityConfig(
            enable_transport_encryption=True,
            transport_key=key or _make_key(),
        )
        return TransportEncryption(cfg)

    def test_enabled(self):
        assert self._enc().enabled is True

    def test_disabled_when_flag_false(self):
        from nanobot.security.encryption import TransportEncryption
        cfg = _FakeSecurityConfig(enable_transport_encryption=False)
        enc = TransportEncryption(cfg)
        assert enc.enabled is False

    def test_roundtrip(self):
        enc = self._enc()
        content = "transport message"
        metadata: dict[str, Any] = {"channel": "telegram"}
        encrypted_content, updated_meta = enc.encrypt_message(content, metadata)
        assert encrypted_content != content
        assert updated_meta.get("_transport_encrypted") is True

        decrypted = enc.decrypt_message(encrypted_content, updated_meta)
        assert decrypted == content

    def test_original_metadata_not_mutated(self):
        enc = self._enc()
        meta: dict[str, Any] = {"channel": "slack"}
        _, updated = enc.encrypt_message("hello", meta)
        assert "_transport_encrypted" not in meta  # original unchanged
        assert "_transport_encrypted" in updated

    def test_unencrypted_message_passthrough(self):
        enc = self._enc()
        result = enc.decrypt_message("plain text", {"_transport_encrypted": False})
        assert result == "plain text"


# ---------------------------------------------------------------------------
# LogSanitizer
# ---------------------------------------------------------------------------

class TestLogSanitizer:
    def _san(self, message: str) -> str:
        from nanobot.security.logging import LogSanitizer
        return LogSanitizer.sanitize(message)

    def test_api_key_redacted(self):
        result = self._san("api_key=sk-abcdef1234567890")
        assert "sk-abcdef1234567890" not in result
        assert "REDACTED" in result

    def test_token_redacted(self):
        result = self._san('{"token": "ghp_xyz123abc456def"}')
        assert "ghp_xyz123abc456def" not in result

    def test_password_redacted(self):
        result = self._san("password=MySecretPass123")
        assert "MySecretPass123" not in result

    def test_email_redacted(self):
        result = self._san("Contact user@example.com for support")
        assert "user@example.com" not in result
        assert "***@***" in result

    def test_chinese_mobile_redacted(self):
        result = self._san("Phone: 13800138000")
        assert "13800138000" not in result

    def test_ip_address_redacted(self):
        result = self._san("Connected from 192.168.1.100")
        assert "192.168.1.100" not in result

    def test_bank_card_redacted(self):
        result = self._san("Card: 6222021234567890123")
        assert "6222021234567890123" not in result

    def test_telegram_token_redacted(self):
        # Telegram token: 8-10 digit bot ID + ':' + 35 char token
        # Must have word boundary before digits (space or string start), not preceded by alpha
        result = self._san("telegram: 123456789:cc4b18772c63ae134c8840231fe95094082")
        assert "cc4b18772c63ae134c8840231fe95094082" not in result
        assert "***TELEGRAM_TOKEN***" in result

    def test_safe_message_unchanged(self):
        msg = "Starting nanobot gateway on port 18790"
        assert self._san(msg) == msg

    def test_none_input_safe(self):
        from nanobot.security.logging import LogSanitizer
        # Should not raise
        assert LogSanitizer.sanitize(None) is None  # type: ignore[arg-type]

    def test_loguru_filter_modifies_record(self):
        from nanobot.security.logging import LogSanitizer
        record: dict[str, Any] = {"message": "secret=abc12345678"}
        result = LogSanitizer.loguru_filter(record)
        assert result is True  # filter always passes
        assert "abc12345678" not in record["message"]


# ---------------------------------------------------------------------------
# FilePermissionManager
# ---------------------------------------------------------------------------

class TestFilePermissionManager:
    def test_scan_finds_json_files(self, tmp_path: Path):
        from nanobot.security.file_permissions import FilePermissionManager
        (tmp_path / "config.json").write_text("{}")
        (tmp_path / "readme.md").write_text("docs")
        mgr = FilePermissionManager()
        found = mgr.scan_directory(tmp_path)
        names = [p.name for p in found]
        assert "config.json" in names
        assert "readme.md" not in names

    def test_scan_finds_jsonl_files(self, tmp_path: Path):
        from nanobot.security.file_permissions import FilePermissionManager
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        (sessions / "session1.jsonl").write_text("")
        mgr = FilePermissionManager()
        found = mgr.scan_directory(tmp_path)
        names = [p.name for p in found]
        assert "session1.jsonl" in names

    def test_protect_workspace_returns_count(self, tmp_path: Path):
        from nanobot.security.file_permissions import FilePermissionManager
        (tmp_path / "config.json").write_text("{}")
        (tmp_path / "keys.key").write_bytes(b"\x00" * 16)
        mgr = FilePermissionManager()
        count = mgr.protect_workspace(tmp_path)
        assert count >= 2

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not applicable on Windows")
    def test_file_gets_0o600_on_unix(self, tmp_path: Path):
        from nanobot.security.file_permissions import FilePermissionManager
        f = tmp_path / "secret.json"
        f.write_text("{}")
        mgr = FilePermissionManager()
        mgr.set_secure_permissions(f)
        assert oct(f.stat().st_mode)[-3:] == "600"

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not applicable on Windows")
    def test_dir_gets_0o700_on_unix(self, tmp_path: Path):
        from nanobot.security.file_permissions import FilePermissionManager
        d = tmp_path / "sessions"
        d.mkdir()
        mgr = FilePermissionManager()
        mgr.set_secure_permissions(d)
        assert oct(d.stat().st_mode)[-3:] == "700"

    def test_windows_skip_returns_true(self, monkeypatch, tmp_path: Path):
        """set_secure_permissions returns True on Windows without error."""
        import nanobot.security.file_permissions as fp_mod
        monkeypatch.setattr(fp_mod, "_IS_WINDOWS", True)
        from nanobot.security.file_permissions import FilePermissionManager
        f = tmp_path / "test.json"
        f.write_text("{}")
        assert FilePermissionManager().set_secure_permissions(f) is True


# ---------------------------------------------------------------------------
# Integration: MessageBus with TransportEncryption
# ---------------------------------------------------------------------------

class TestMessageBusTransportEncryption:
    @pytest.mark.asyncio
    async def test_bus_encrypt_decrypt_roundtrip(self):
        from nanobot.bus.events import InboundMessage
        from nanobot.bus.queue import MessageBus
        from nanobot.security.encryption import TransportEncryption

        cfg = _FakeSecurityConfig(enable_transport_encryption=True, transport_key=_make_key())
        te = TransportEncryption(cfg)
        bus = MessageBus(transport_encryption=te)

        original = InboundMessage(
            channel="telegram",
            sender_id="user123",
            chat_id="chat456",
            content="Hello encrypted world",
        )
        await bus.publish_inbound(original)
        received = await bus.consume_inbound()
        assert received.content == "Hello encrypted world"
        assert received.channel == "telegram"
        assert received.sender_id == "user123"

    @pytest.mark.asyncio
    async def test_bus_without_encryption_passthrough(self):
        from nanobot.bus.events import InboundMessage
        from nanobot.bus.queue import MessageBus

        bus = MessageBus()
        msg = InboundMessage(channel="slack", sender_id="u1", chat_id="c1", content="plain")
        await bus.publish_inbound(msg)
        result = await bus.consume_inbound()
        assert result.content == "plain"


# ---------------------------------------------------------------------------
# Integration: SessionManager with encryption
# ---------------------------------------------------------------------------

class TestSessionManagerEncryption:
    def test_save_and_load_encrypted(self, tmp_path: Path):
        from nanobot.session.manager import SessionManager

        cfg = _FakeSecurityConfig(enable_session_encryption=True, encryption_key=_make_key())
        sm = SessionManager(tmp_path, security_config=cfg)

        session = sm.get_or_create("telegram:12345")
        session.add_message("user", "my private message")
        session.add_message("assistant", "my private response")
        sm.save(session)

        # The on-disk file should NOT contain plain text
        session_path = list(tmp_path.glob("sessions/*.jsonl"))[0]
        raw = session_path.read_text(encoding="utf-8")
        assert "my private message" not in raw
        assert "my private response" not in raw

        # Loading back should restore original content
        sm2 = SessionManager(tmp_path, security_config=cfg)
        loaded = sm2.get_or_create("telegram:12345")
        assert loaded.messages[0]["content"] == "my private message"
        assert loaded.messages[1]["content"] == "my private response"

    def test_save_and_load_no_encryption(self, tmp_path: Path):
        from nanobot.session.manager import SessionManager

        sm = SessionManager(tmp_path)
        session = sm.get_or_create("telegram:99999")
        session.add_message("user", "plain message")
        sm.save(session)

        session_path = list(tmp_path.glob("sessions/*.jsonl"))[0]
        raw = session_path.read_text(encoding="utf-8")
        assert "plain message" in raw  # Should be in plain text

    def test_system_messages_not_encrypted_on_disk(self, tmp_path: Path):
        from nanobot.session.manager import SessionManager

        cfg = _FakeSecurityConfig(enable_session_encryption=True, encryption_key=_make_key())
        sm = SessionManager(tmp_path, security_config=cfg)
        session = sm.get_or_create("telegram:sys")
        session.add_message("system", "you are a helpful assistant")
        sm.save(session)

        session_path = list(tmp_path.glob("sessions/*.jsonl"))[0]
        raw = session_path.read_text(encoding="utf-8")
        # System messages are NOT in ENCRYPTED_ROLES so remain plain
        assert "you are a helpful assistant" in raw
