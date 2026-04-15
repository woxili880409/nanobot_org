"""Async message queue for decoupled channel-agent communication."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from nanobot.bus.events import InboundMessage, OutboundMessage

if TYPE_CHECKING:
    from nanobot.security.encryption import TransportEncryption


class MessageBus:
    """
    Async message bus that decouples chat channels from the agent core.

    Channels push messages to the inbound queue, and the agent processes
    them and pushes responses to the outbound queue.

    Optional *transport_encryption* wraps all inbound message content with
    AES-256-GCM so that messages at rest in the queue are opaque.
    """

    def __init__(self, transport_encryption: TransportEncryption | None = None) -> None:
        self.inbound: asyncio.Queue[InboundMessage] = asyncio.Queue()
        self.outbound: asyncio.Queue[OutboundMessage] = asyncio.Queue()
        self.transport_encryption = transport_encryption

    async def publish_inbound(self, msg: InboundMessage) -> None:
        """Publish a message from a channel to the agent (encrypts if configured)."""
        if self.transport_encryption and self.transport_encryption.enabled:
            encrypted_content, updated_metadata = self.transport_encryption.encrypt_message(
                msg.content, msg.metadata.copy() if msg.metadata else {}
            )
            msg = InboundMessage(
                channel=msg.channel,
                sender_id=msg.sender_id,
                chat_id=msg.chat_id,
                content=encrypted_content,
                timestamp=msg.timestamp,
                media=msg.media,
                metadata=updated_metadata,
                session_key_override=msg.session_key_override,
            )
        await self.inbound.put(msg)

    async def consume_inbound(self) -> InboundMessage:
        """Consume the next inbound message (decrypts if configured)."""
        msg = await self.inbound.get()
        if self.transport_encryption and self.transport_encryption.enabled:
            decrypted_content = self.transport_encryption.decrypt_message(
                msg.content, msg.metadata or {}
            )
            if decrypted_content != msg.content:
                msg = InboundMessage(
                    channel=msg.channel,
                    sender_id=msg.sender_id,
                    chat_id=msg.chat_id,
                    content=decrypted_content,
                    timestamp=msg.timestamp,
                    media=msg.media,
                    metadata=msg.metadata,
                    session_key_override=msg.session_key_override,
                )
        return msg

    async def publish_outbound(self, msg: OutboundMessage) -> None:
        """Publish a response from the agent to channels."""
        await self.outbound.put(msg)

    async def consume_outbound(self) -> OutboundMessage:
        """Consume the next outbound message (blocks until available)."""
        return await self.outbound.get()

    @property
    def inbound_size(self) -> int:
        """Number of pending inbound messages."""
        return self.inbound.qsize()

    @property
    def outbound_size(self) -> int:
        """Number of pending outbound messages."""
        return self.outbound.qsize()
