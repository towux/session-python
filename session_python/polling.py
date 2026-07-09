import time
import binascii
import json
from typing import List, Dict, Any, Optional
from .client import Session
from .crypto import (
    remove_message_padding,
    decrypt_with_session_protocol,
    remove_prefix_if_needed
)
from .protobuf.signalservice_pb2 import WebSocketMessage, Envelope, Content

def namespace_priority(namespace: int) -> int:
    if namespace == 0:
        return 10
    return 1

def max_size_map(namespaces: List[int]) -> List[Dict[str, Any]]:
    priorities = {}
    for ns in namespaces:
        p = namespace_priority(ns)
        if p not in priorities:
            priorities[p] = []
        priorities[p].append(ns)
        
    sorted_priorities = sorted(priorities.keys(), reverse=True)
    if not sorted_priorities:
        return []
    lowest_priority = sorted_priorities[-1]
    
    size_map = []
    last_split = 1
    for p in sorted_priorities:
        padding = 0 if p == lowest_priority else 1
        splits = padding + len(priorities[p])
        last_split *= splits
        for ns in priorities[p]:
            size_map.append({"namespace": ns, "maxSize": -last_split})
            
    return size_map

def get_snode_signature_params(keys, method: str, namespace: int) -> dict:
    timestamp = int(time.time() * 1000)
    if namespace == 0:
        msg = f"{method}{timestamp}"
    else:
        msg = f"{method}{namespace}{timestamp}"
        
    signature = keys.signing_key.sign(msg.encode('utf-8')).signature
    signature_b64 = binascii.b2a_base64(signature, newline=False).decode('utf-8')
    pubkey_ed25519 = binascii.hexlify(keys.ed25519.public_key).decode('utf-8')
    
    return {
        "timestamp": timestamp,
        "signature": signature_b64,
        "pubkey_ed25519": pubkey_ed25519
    }

class Poller:
    def __init__(self, session: Session, namespaces: Optional[List[int]] = None):
        self.session = session
        self.namespaces = namespaces if namespaces is not None else [0, 2, 3, 4, 5]
        
    def poll(self) -> List[Dict[str, Any]]:
        if not self.session.keys or not self.session.session_id:
            raise ValueError("Session client not initialized.")
            
        our_swarm = self.session.get_our_swarm()
        snode = {
            "public_ip": our_swarm["ip"],
            "storage_port": int(our_swarm["port"])
        }
        
        size_mappings = max_size_map(self.namespaces)
        
        # Prepare retrieve subrequests
        subrequests = []
        for ns in self.namespaces:
            last_hash = self.session.last_hashes.get(ns, "")
            
            # Signature for authenticate retrieve
            sig = get_snode_signature_params(self.session.keys, "retrieve", ns)
            
            # Find maxSize
            max_size = -1
            for mapping in size_mappings:
                if mapping["namespace"] == ns:
                    max_size = mapping["maxSize"]
                    break
                    
            subrequests.append({
                "method": "retrieve",
                "params": {
                    "pubkey": self.session.session_id,
                    "lastHash": last_hash,
                    "namespace": ns,
                    "maxSize": max_size,
                    "timestamp": sig["timestamp"],
                    "signature": sig["signature"],
                    "pubkey_ed25519": sig["pubkey_ed25519"]
                }
            })
            
        results = self.session.network.snode_batch_request(
            snode=snode,
            requests_list=subrequests
        )
        
        decrypted_messages = []
        
        for idx, result in enumerate(results):
            ns = self.namespaces[idx]
            if result.get("code") != 200:
                continue
                
            body_val = result.get("body", "{}")
            if isinstance(body_val, str):
                try:
                    body_data = json.loads(body_val)
                except Exception:
                    body_data = {}
            else:
                body_data = body_val
                
            if isinstance(body_data, dict):
                messages_list = body_data.get("messages", [])
            else:
                messages_list = []
                
            if not messages_list:
                continue
                
            for m in messages_list:
                msg_hash = m.get("hash")
                data_b64 = m.get("data")
                if not data_b64:
                    continue
                    
                try:
                    # Extract envelope
                    data_bytes = binascii.a2b_base64(data_b64)
                    ws_msg = WebSocketMessage.FromString(data_bytes)
                    
                    if ws_msg.type != WebSocketMessage.Type.REQUEST or not ws_msg.request.body:
                        continue
                        
                    envelope_bytes = ws_msg.request.body
                    envelope = Envelope.FromString(envelope_bytes)
                    
                    if not envelope.content:
                        continue
                        
                    # Decrypt Envelope
                    plaintext_padded, sender_id = decrypt_with_session_protocol(
                        self.session.keys,
                        envelope.content
                    )
                    
                    # Unpad plaintext
                    plaintext = remove_message_padding(plaintext_padded)
                    
                    # Parse Content protobuf
                    content = Content.FromString(plaintext)
                    
                    # Map to friendly dict
                    mapped_msg = {
                        "hash": msg_hash,
                        "namespace": ns,
                        "timestamp": envelope.timestamp,
                        "from": sender_id,
                        "type": "unknown",
                        "body": None,
                        "attachments": [],
                        "syncTarget": None
                    }
                    
                    if content.HasField("dataMessage"):
                        mapped_msg["type"] = "data"
                        mapped_msg["body"] = content.dataMessage.body
                        if content.dataMessage.syncTarget:
                            mapped_msg["syncTarget"] = content.dataMessage.syncTarget
                            
                        # Parse attachments
                        for att in content.dataMessage.attachments:
                            mapped_msg["attachments"].append({
                                "id": att.id,
                                "url": att.url,
                                "key": att.key,
                                "digest": att.digest,
                                "name": att.fileName,
                                "contentType": att.contentType,
                                "size": att.size
                            })
                            
                    elif content.HasField("typingMessage"):
                        mapped_msg["type"] = "typing"
                        mapped_msg["isTyping"] = (content.typingMessage.action == 0) # STARTED = 0
                        
                    elif content.HasField("unsendMessage"):
                        mapped_msg["type"] = "unsend"
                        mapped_msg["targetTimestamp"] = content.unsendMessage.timestamp
                        mapped_msg["author"] = content.unsendMessage.author
                        
                    elif content.HasField("receiptMessage"):
                        mapped_msg["type"] = "receipt"
                        mapped_msg["targetTimestamps"] = list(content.receiptMessage.timestamp)
                        
                    elif content.HasField("messageRequestResponse"):
                        mapped_msg["type"] = "request_response"
                        mapped_msg["isApproved"] = content.messageRequestResponse.isApproved
                        
                    decrypted_messages.append(mapped_msg)
                    
                except Exception as e:
                    # Decryption or parsing error for a single message shouldn't crash the loop
                    continue
            
            # Update lastHash for this namespace to the hash of the last message
            if messages_list:
                self.session.last_hashes[ns] = messages_list[-1]["hash"]
                
        return decrypted_messages
