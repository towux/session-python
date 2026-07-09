import os
import time
import random
import binascii
import uuid
import hashlib
from typing import List, Dict, Any, Union, Optional
import nacl.signing
import nacl.public
import nacl.exceptions
from cryptography.hazmat.primitives import hashes

from .network import SessionNetwork
from .crypto import (
    SessionKeys,
    add_message_padding,
    remove_message_padding,
    encrypt_using_session_protocol,
    decrypt_with_session_protocol,
    wrap_envelope,
    encrypt_attachment,
    decrypt_attachment,
    remove_prefix_if_needed
)
from .protobuf.signalservice_pb2 import Content, Envelope, WebSocketMessage, WebSocketRequestMessage
from .mnemonic import decode as decode_mnemonic, encode as encode_mnemonic

class Session:
    def __init__(self, proxy: Optional[str] = None):
        self.network = SessionNetwork(proxy=proxy)
        self.mnemonic: Optional[str] = None
        self.keys: Optional[SessionKeys] = None
        self.session_id: Optional[str] = None
        self.display_name: Optional[str] = None
        self.avatar: Optional[dict] = None
        self.snodes: Optional[list] = None
        self.our_swarms: Optional[list] = None
        self.our_swarm: Optional[dict] = None
        self.last_hashes: Dict[int, str] = {}
        self.swarms_cache: Dict[str, list] = {}

    @staticmethod
    def generate_mnemonic() -> str:
        """
        Generates a new random 13-word mnemonic phrase for creating a new account.
        """
        import os
        import binascii
        from .mnemonic import encode as encode_mnemonic
        seed_hex = binascii.hexlify(os.urandom(16)).decode('utf-8')
        return encode_mnemonic(seed_hex)

    def close(self):
        """
        Closes HTTP session connection pool.
        """
        if hasattr(self, 'network') and self.network.session:
            self.network.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        
    def set_mnemonic(self, mnemonic: str, display_name: Optional[str] = None):
        """
        Sets mnemonic for this instance and derives keys.
        """
        self.mnemonic = mnemonic
        seed_hex = decode_mnemonic(mnemonic)
        self.keys = SessionKeys(seed_hex)
        # Session ID is X25519 public key (starts with 05)
        self.session_id = self.keys.x25519.public_key.hex()
        
        if display_name:
            self.display_name = display_name
            
    def get_session_id(self) -> str:
        if not self.session_id:
            raise ValueError("Session client not initialized with mnemonic.")
        return self.session_id

    def get_snodes(self) -> list:
        if not self.snodes:
            self.snodes = self.network.get_snodes_from_seeds()
        return self.snodes

    def get_swarms_for(self, session_id: str) -> list:
        if session_id in self.swarms_cache:
            return self.swarms_cache[session_id]
            
        snodes = self.get_snodes()
        if not snodes:
            raise ValueError("No service nodes available.")
            
        # Try a few snodes in case of 421 errors
        for _ in range(5):
            snode = random.choice(snodes)
            try:
                results = self.network.snode_batch_request(
                    snode=snode,
                    requests_list=[{
                        "method": "get_swarm",
                        "params": {"pubkey": session_id}
                    }]
                )
                if results and results[0].get("code") == 200:
                    swarms = results[0]["body"]["snodes"]
                    self.swarms_cache[session_id] = swarms
                    return swarms
            except Exception:
                continue
                
        raise ValueError("Failed to get swarms for " + session_id)

    def get_our_swarm(self) -> dict:
        session_id = self.get_session_id()
        if self.our_swarm:
            return self.our_swarm
            
        self.our_swarms = self.get_swarms_for(session_id)
        if not self.our_swarms:
            raise ValueError("No swarms found for this account.")
            
        self.our_swarm = random.choice(self.our_swarms)
        return self.our_swarm

    def _store_message(self, recipient: str, data64: str, timestamp: int, namespace: int = 0) -> str:
        """
        Sends store request to recipient's swarm with retries/failover.
        """
        swarms = list(self.get_swarms_for(recipient))
        while swarms:
            swarm = random.choice(swarms)
            try:
                res = self.network.snode_batch_request(
                    snode={
                        "public_ip": swarm["ip"],
                        "storage_port": int(swarm["port"])
                    },
                    requests_list=[{
                        "method": "store",
                        "params": {
                            "pubkey": recipient,
                            "ttl": 14 * 24 * 60 * 60 * 1000,
                            "timestamp": timestamp,
                            "data": data64,
                            "namespace": namespace
                        }
                    }],
                    timeout=5
                )
                if res and res[0].get("code") == 200:
                    return res[0]["body"]["hash"]
            except Exception:
                swarms.remove(swarm)
                if not swarms:
                    raise
        raise ValueError("Failed to store message (empty results)")

    def send_message(
        self, 
        to: str, 
        text: Optional[str] = None, 
        attachments: Optional[List[dict]] = None
    ) -> Dict[str, Any]:
        """
        Sends a message to a recipient.
        to: Recipient Session ID (starts with 05)
        text: Message text
        attachments: List of dicts, e.g. [{'data': b'...', 'name': 'file.jpg', 'content_type': 'image/jpeg'}]
        """
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
            
        if len(to) != 66 or not to.startswith("05"):
            raise ValueError("Invalid recipient Session ID.")

        attachment_pointers = []
        if attachments:
            for att in attachments:
                enc = encrypt_attachment(att["data"])
                # Upload ciphertext
                res = self.network.upload_attachment(enc["ciphertext"])
                attachment_pointers.append({
                    "id": res["id"],
                    "url": res["url"],
                    "key": enc["key"],
                    "digest": enc["digest"],
                    "fileName": att.get("name", "file"),
                    "contentType": att.get("content_type", "application/octet-stream"),
                    "size": len(att["data"])
                })

        timestamp = int(time.time() * 1000)
        
        # Build visible message for recipient
        msg_content = Content()
        msg_content.dataMessage.body = text or ""
        msg_content.dataMessage.timestamp = timestamp
        
        if self.display_name:
            msg_content.dataMessage.profile.displayName = self.display_name
            
        # Add attachments
        for att_ptr in attachment_pointers:
            ptr = msg_content.dataMessage.attachments.add()
            ptr.id = att_ptr["id"]
            ptr.url = att_ptr["url"]
            ptr.key = att_ptr["key"]
            ptr.digest = att_ptr["digest"]
            ptr.fileName = att_ptr["fileName"]
            ptr.contentType = att_ptr["contentType"]
            ptr.size = att_ptr["size"]

        # Build sync message for self
        sync_content = Content()
        sync_content.dataMessage.body = text or ""
        sync_content.dataMessage.timestamp = timestamp
        sync_content.dataMessage.syncTarget = to
        
        for att_ptr in attachment_pointers:
            ptr = sync_content.dataMessage.attachments.add()
            ptr.id = att_ptr["id"]
            ptr.url = att_ptr["url"]
            ptr.key = att_ptr["key"]
            ptr.digest = att_ptr["digest"]
            ptr.fileName = att_ptr["fileName"]
            ptr.contentType = att_ptr["contentType"]
            ptr.size = att_ptr["size"]

        # Encrypt messages
        raw_msg_bytes = msg_content.SerializeToString()
        padded_raw = add_message_padding(raw_msg_bytes)
        ciphertext = encrypt_using_session_protocol(self.keys, to, padded_raw)
        
        raw_sync_bytes = sync_content.SerializeToString()
        padded_sync = add_message_padding(raw_sync_bytes)
        sync_ciphertext = encrypt_using_session_protocol(self.keys, self.session_id, padded_sync)

        # Build envelopes
        envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=timestamp,
            content=ciphertext
        )
        
        sync_envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=timestamp,
            content=sync_ciphertext
        )

        # Wrap envelopes inside WebSocket messages
        websocket_bytes = wrap_envelope(envelope.SerializeToString())
        sync_websocket_bytes = wrap_envelope(sync_envelope.SerializeToString())

        data64 = binascii.b2a_base64(websocket_bytes, newline=False).decode('utf-8')
        sync_data64 = binascii.b2a_base64(sync_websocket_bytes, newline=False).decode('utf-8')

        # Store recipient message & sync copy
        message_hash = self._store_message(to, data64, timestamp, namespace=0)
        sync_message_hash = self._store_message(self.session_id, sync_data64, timestamp, namespace=0)

        return {
            "messageHash": message_hash,
            "syncMessageHash": sync_message_hash,
            "timestamp": timestamp
        }

    def get_file(self, att_ptr: dict) -> bytes:
        """
        Downloads and decrypts attachment from Session file server using the attachment pointer dict.
        att_ptr: dict representing attachment pointer, containing:
                 'id', 'key', 'digest', 'size'
        """
        enc_data = self.network.download_attachment(att_ptr["id"])
        return decrypt_attachment(
            data=enc_data,
            key=att_ptr["key"],
            digest=att_ptr["digest"],
            size=att_ptr.get("size")
        )

    # --- Message Reactions ---

    def add_reaction(self, message_timestamp: int, message_author: str, emoji: str):
        """
        Adds emoji reaction to specific message.
        """
        self._send_reaction_message(message_timestamp, message_author, emoji, action=0)

    def remove_reaction(self, message_timestamp: int, message_author: str, emoji: str):
        """
        Removes emoji reaction from specific message.
        """
        self._send_reaction_message(message_timestamp, message_author, emoji, action=1)

    def _send_reaction_message(self, message_timestamp: int, message_author: str, emoji: str, action: int):
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
            
        timestamp = int(time.time() * 1000)
        
        # Build visible reaction content
        content = Content()
        content.dataMessage.timestamp = timestamp
        content.dataMessage.reaction.id = message_timestamp
        content.dataMessage.reaction.action = action
        content.dataMessage.reaction.author = message_author
        content.dataMessage.reaction.emoji = emoji
        if self.display_name:
            content.dataMessage.profile.displayName = self.display_name

        # Build sync copy
        sync_content = Content()
        sync_content.dataMessage.timestamp = timestamp
        sync_content.dataMessage.reaction.id = message_timestamp
        sync_content.dataMessage.reaction.action = action
        sync_content.dataMessage.reaction.author = message_author
        sync_content.dataMessage.reaction.emoji = emoji
        sync_content.dataMessage.syncTarget = message_author

        # Encrypt and wrap
        raw_msg_bytes = content.SerializeToString()
        padded_raw = add_message_padding(raw_msg_bytes)
        ciphertext = encrypt_using_session_protocol(self.keys, message_author, padded_raw)

        raw_sync_bytes = sync_content.SerializeToString()
        padded_sync = add_message_padding(raw_sync_bytes)
        sync_ciphertext = encrypt_using_session_protocol(self.keys, self.session_id, padded_sync)

        envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=timestamp,
            content=ciphertext
        )
        sync_envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=timestamp,
            content=sync_ciphertext
        )

        data64 = binascii.b2a_base64(wrap_envelope(envelope.SerializeToString()), newline=False).decode('utf-8')
        sync_data64 = binascii.b2a_base64(wrap_envelope(sync_envelope.SerializeToString()), newline=False).decode('utf-8')

        self._store_message(message_author, data64, timestamp, namespace=0)
        self._store_message(self.session_id, sync_data64, timestamp, namespace=0)

    # --- Typing Indicators ---

    def show_typing_indicator(self, conversation: str):
        """
        Sends typing started event.
        """
        self._update_typing_indicator(conversation, is_typing=True)

    def hide_typing_indicator(self, conversation: str):
        """
        Sends typing stopped event.
        """
        self._update_typing_indicator(conversation, is_typing=False)

    def _update_typing_indicator(self, conversation: str, is_typing: bool):
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
            
        timestamp = int(time.time() * 1000)
        content = Content()
        content.typingMessage.timestamp = timestamp
        content.typingMessage.action = 0 if is_typing else 1 # STARTED = 0, STOPPED = 1

        raw_msg_bytes = content.SerializeToString()
        padded_raw = add_message_padding(raw_msg_bytes)
        ciphertext = encrypt_using_session_protocol(self.keys, conversation, padded_raw)

        envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=timestamp,
            content=ciphertext
        )
        data64 = binascii.b2a_base64(wrap_envelope(envelope.SerializeToString()), newline=False).decode('utf-8')
        self._store_message(conversation, data64, timestamp, namespace=0)

    # --- Read Receipts ---

    def mark_messages_as_read(self, conversation: str, timestamps: List[int], read_at: Optional[int] = None):
        """
        Marks messages with specified timestamps as read.
        """
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
            
        timestamp = read_at or int(time.time() * 1000)
        content = Content()
        content.receiptMessage.type = 1 # READ = 1
        content.receiptMessage.timestamp.extend(timestamps)

        raw_msg_bytes = content.SerializeToString()
        padded_raw = add_message_padding(raw_msg_bytes)
        ciphertext = encrypt_using_session_protocol(self.keys, conversation, padded_raw)

        envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=timestamp,
            content=ciphertext
        )
        data64 = binascii.b2a_base64(wrap_envelope(envelope.SerializeToString()), newline=False).decode('utf-8')
        self._store_message(conversation, data64, timestamp, namespace=0)

    # --- Message Deletion / Unsends ---

    def delete_message(self, conversation: str, timestamp: int, hash_val: str):
        """
        Deletes a single sent message locally and sends an unsend command.
        """
        self.delete_messages([{"to": conversation, "timestamp": timestamp, "hash": hash_val}])

    def delete_messages(self, messages: List[dict]):
        """
        Deletes multiple sent messages.
        messages: List of dicts: [{'to': '...', 'timestamp': ..., 'hash': '...'}]
        """
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
            
        hashes = [m["hash"] for m in messages]
        
        # 1. Permanently delete from our own swarm
        verification_data = f"delete{''.join(hashes)}"
        signature = self.keys.signing_key.sign(verification_data.encode('utf-8')).signature
        signature_b64 = binascii.b2a_base64(signature, newline=False).decode('utf-8')
        
        our_swarms = list(self.get_swarms_for(self.session_id))
        while our_swarms:
            our_swarm = random.choice(our_swarms)
            try:
                res = self.network.snode_batch_request(
                    snode={
                        "public_ip": our_swarm["ip"],
                        "storage_port": int(our_swarm["port"])
                    },
                    requests_list=[{
                        "method": "delete",
                        "params": {
                            "messages": hashes,
                            "pubkey": self.session_id,
                            "pubkey_ed25519": self.keys.ed25519.public_key.hex(),
                            "signature": signature_b64
                        }
                    }],
                    timeout=5
                )
                if res and res[0].get("code") == 200:
                    break
            except Exception:
                our_swarms.remove(our_swarm)
                if not our_swarms:
                    raise

        # 2. Propagate Unsend command to recipients
        timestamp = int(time.time() * 1000)
        for m in messages:
            unsend_content = Content()
            unsend_content.unsendMessage.timestamp = m["timestamp"]
            unsend_content.unsendMessage.author = self.session_id
            
            raw_msg_bytes = unsend_content.SerializeToString()
            padded_raw = add_message_padding(raw_msg_bytes)
            ciphertext = encrypt_using_session_protocol(self.keys, m["to"], padded_raw)
            sync_ciphertext = encrypt_using_session_protocol(self.keys, self.session_id, padded_raw)

            envelope = Envelope(
                type=Envelope.Type.SESSION_MESSAGE,
                timestamp=timestamp,
                content=ciphertext
            )
            sync_envelope = Envelope(
                type=Envelope.Type.SESSION_MESSAGE,
                timestamp=timestamp,
                content=sync_ciphertext
            )

            data64 = binascii.b2a_base64(wrap_envelope(envelope.SerializeToString()), newline=False).decode('utf-8')
            sync_data64 = binascii.b2a_base64(wrap_envelope(sync_envelope.SerializeToString()), newline=False).decode('utf-8')

            self._store_message(m["to"], data64, timestamp, namespace=0)
            self._store_message(self.session_id, sync_data64, timestamp, namespace=0)

    # --- SOGS / Open Groups Blinding (Matching session.js empty blinding implementation) ---

    def blind_session_id(self, server_pk: str) -> str:
        raise NotImplementedError("Blinding is not implemented yet in the original session.js library.")

    def sign_sogs_request(
        self,
        server_pk: str,
        timestamp: int,
        endpoint: str,
        nonce: bytes,
        method: str,
        body: Optional[Union[str, bytes]] = None
    ) -> bytes:
        """
        Signs HTTP requests to SOGS.
        """
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
            
        pk = binascii.unhexlify(server_pk)
        to_sign = pk + nonce + str(timestamp).encode('utf-8') + method.encode('utf-8') + endpoint.encode('utf-8')
        if body:
            body_bytes = body.encode('utf-8') if isinstance(body, str) else body
            body_hashed = hashlib.blake2b(body_bytes, digest_size=64).digest()
            to_sign += body_hashed
            
        # SOGS signature is ed25519 sign
        return self.keys.signing_key.sign(to_sign).signature

    def send_sogs_request(
        self,
        host: str,
        server_pk: str,
        endpoint: str,
        method: str,
        body: Optional[Union[str, bytes]] = None
    ) -> dict:
        """
        Sends requests to SOGS (Open Groups).
        """
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
            
        nonce = os.urandom(16)
        timestamp = int(time.time())
        req_sig = self.sign_sogs_request(server_pk, timestamp, endpoint, nonce, method, body)
        
        pubkey = "00" + self.keys.ed25519.public_key.hex()
        
        content_type = None
        if body is not None:
            content_type = "application/octet-stream" if isinstance(body, bytes) else "application/json"
            
        headers = {
            "X-SOGS-Pubkey": pubkey,
            "X-SOGS-Timestamp": str(timestamp),
            "X-SOGS-Nonce": binascii.b2a_base64(nonce, newline=False).decode('utf-8'),
            "X-SOGS-Signature": binascii.b2a_base64(req_sig, newline=False).decode('utf-8')
        }
        if content_type:
            headers["Content-Type"] = content_type
            
        return self.network.sogs_request(
            host=host,
            endpoint=endpoint,
            method=method,
            body=body,
            headers=headers
        )

    def encode_sogs_message(self, text: str) -> dict:
        raise NotImplementedError("SOGS message encoding is not implemented in the original session.js library.")

    def get_mnemonic(self) -> Optional[str]:
        """
        Returns mnemonic string of this instance.
        """
        return self.mnemonic

    def get_display_name(self) -> Optional[str]:
        """
        Returns cached display name of this instance.
        """
        return self.display_name

    def get_avatar(self) -> Optional[dict]:
        """
        Returns cached avatar profile dict.
        """
        return self.avatar

    def get_keys(self) -> Optional[SessionKeys]:
        """
        Returns derived cryptographic keys.
        """
        return self.keys

    def download_avatar(self, avatar: dict) -> bytes:
        """
        Downloads and decrypts avatar image using Profile.avatar dictionary containing 'url' and 'key'.
        """
        file_server_url = "http://filev2.getsession.org/file/"
        url = avatar["url"]
        if not url.startswith(file_server_url):
            raise ValueError("Avatar must be hosted on Session file server")
        file_id = url[len(file_server_url):]
        raw_bytes = self.network.download_attachment(file_id)
        from .crypto import decrypt_profile
        return decrypt_profile(raw_bytes, avatar["key"])

    def upload_avatar(self, avatar_data: bytes) -> dict:
        """
        Encrypts and uploads avatar data to Session file server.
        """
        profile_key = os.urandom(32)
        from .crypto import encrypt_profile
        ciphertext = encrypt_profile(avatar_data, profile_key)
        res = self.network.upload_attachment(ciphertext)
        return {
            "profileKey": profile_key,
            "avatarPointer": res["url"]
        }

    def set_avatar(self, avatar_data: bytes):
        """
        Uploads, encrypts and sets avatar.
        """
        res = self.upload_avatar(avatar_data)
        self.avatar = {
            "key": res["profileKey"],
            "url": res["avatarPointer"]
        }
        
        config_content = Content()
        if self.display_name:
            config_content.configurationMessage.displayName = self.display_name
        config_content.configurationMessage.profilePicture = self.avatar["url"]
        config_content.configurationMessage.profileKey = self.avatar["key"]
        
        raw_msg_bytes = config_content.SerializeToString()
        padded_raw = add_message_padding(raw_msg_bytes)
        sync_ciphertext = encrypt_using_session_protocol(self.keys, self.session_id, padded_raw)
        
        envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=int(time.time() * 1000),
            content=sync_ciphertext
        )
        data64 = binascii.b2a_base64(wrap_envelope(envelope.SerializeToString()), newline=False).decode('utf-8')
        self._store_message(self.session_id, data64, envelope.timestamp, namespace=0)

    def set_display_name(self, display_name: str):
        """
        Sets display name and propagates ConfigurationMessage sync copy.
        """
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
        if len(display_name) > 64 or len(display_name) == 0:
            raise ValueError("Display name must be between 1 and 64 characters.")
            
        self.display_name = display_name
        
        config_content = Content()
        config_content.configurationMessage.displayName = self.display_name
        if self.avatar:
            config_content.configurationMessage.profilePicture = self.avatar["url"]
            config_content.configurationMessage.profileKey = self.avatar["key"]
            
        raw_msg_bytes = config_content.SerializeToString()
        padded_raw = add_message_padding(raw_msg_bytes)
        sync_ciphertext = encrypt_using_session_protocol(self.keys, self.session_id, padded_raw)
        
        envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=int(time.time() * 1000),
            content=sync_ciphertext
        )
        data64 = binascii.b2a_base64(wrap_envelope(envelope.SerializeToString()), newline=False).decode('utf-8')
        self._store_message(self.session_id, data64, envelope.timestamp, namespace=0)

    def notify_screenshot_taken(self, conversation: str):
        """
        Sends screenshot taken notification to conversation.
        """
        self._send_data_extraction_notification(conversation, action=1, timestamp=int(time.time() * 1000))

    def notify_media_saved(self, conversation: str, saved_message_timestamp: int):
        """
        Sends media saved notification to conversation.
        """
        self._send_data_extraction_notification(conversation, action=2, timestamp=saved_message_timestamp)

    def _send_data_extraction_notification(self, conversation: str, action: int, timestamp: int):
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
            
        content = Content()
        content.dataExtractionNotification.type = action # SCREENSHOT = 1, MEDIA_SAVED = 2
        content.dataExtractionNotification.timestamp = timestamp

        raw_msg_bytes = content.SerializeToString()
        padded_raw = add_message_padding(raw_msg_bytes)
        ciphertext = encrypt_using_session_protocol(self.keys, conversation, padded_raw)

        envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=int(time.time() * 1000),
            content=ciphertext
        )
        data64 = binascii.b2a_base64(wrap_envelope(envelope.SerializeToString()), newline=False).decode('utf-8')
        self._store_message(conversation, data64, envelope.timestamp, namespace=0)

    def accept_conversation_request(self, conversation: str):
        """
        Accepts conversation request from another Session ID.
        """
        if not self.keys or not self.session_id:
            raise ValueError("Session client not initialized.")
            
        content = Content()
        content.messageRequestResponse.isApproved = True
        if self.avatar:
            content.messageRequestResponse.profileKey = self.avatar["key"]
            content.messageRequestResponse.profile.profilePicture = self.avatar["url"]
        if self.display_name:
            content.messageRequestResponse.profile.displayName = self.display_name

        raw_msg_bytes = content.SerializeToString()
        padded_raw = add_message_padding(raw_msg_bytes)
        ciphertext = encrypt_using_session_protocol(self.keys, conversation, padded_raw)

        envelope = Envelope(
            type=Envelope.Type.SESSION_MESSAGE,
            timestamp=int(time.time() * 1000),
            content=ciphertext
        )
        data64 = binascii.b2a_base64(wrap_envelope(envelope.SerializeToString()), newline=False).decode('utf-8')
        self._store_message(conversation, data64, envelope.timestamp, namespace=0)
