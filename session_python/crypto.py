import os
import hashlib
import binascii
import nacl.signing
import nacl.public
import nacl.exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Optional
from .protobuf.signalservice_pb2 import WebSocketMessage, WebSocketRequestMessage, Envelope

def remove_prefix_if_needed(val):
    if isinstance(val, str):
        if val.startswith("05"):
            return val[2:]
    elif isinstance(val, (bytes, bytearray)):
        if len(val) > 0 and val[0] == 5:
            return val[1:]
    return val

def add_prefix_if_needed(val: bytes) -> bytes:
    if len(val) == 32:
        return b'\x05' + val
    return val

class KeyPair:
    def __init__(self, key_type: str, private_key: bytes, public_key: bytes):
        self.key_type = key_type
        self.private_key = private_key
        self.public_key = public_key

class SessionKeys:
    def __init__(self, seed_hex: str):
        if len(seed_hex) != 64:
            seed_hex = (seed_hex + "0" * 32)[:64]
        
        self.seed = binascii.unhexlify(seed_hex)
        
        # Ed25519 KeyPair
        self.signing_key = nacl.signing.SigningKey(self.seed)
        self.verify_key = self.signing_key.verify_key
        
        self.ed25519 = KeyPair(
            key_type="ed25519",
            private_key=self.seed,
            public_key=self.verify_key.encode()
        )
        
        # X25519 KeyPair
        self.x25519_private = self.signing_key.to_curve25519_private_key()
        self.x25519_public = self.verify_key.to_curve25519_public_key()
        
        prepended_public = b'\x05' + self.x25519_public.encode()
        
        self.x25519 = KeyPair(
            key_type="x25519",
            private_key=self.x25519_private.encode(),
            public_key=prepended_public
        )

def crypto_box_seal(message: bytes, recipient_pk: bytes) -> bytes:
    recipient_pk_clean = remove_prefix_if_needed(recipient_pk)
    if len(recipient_pk_clean) != 32:
        raise ValueError(f"Recipient public key must be 32 bytes, got {len(recipient_pk_clean)}")
        
    pk = nacl.public.PublicKey(recipient_pk_clean)
    box = nacl.public.SealedBox(pk)
    return box.encrypt(message)

def crypto_box_seal_open(sealed: bytes, recipient_sk: bytes) -> bytes:
    if len(recipient_sk) != 32:
        raise ValueError(f"Recipient secret key must be 32 bytes, got {len(recipient_sk)}")
        
    sk = nacl.public.PrivateKey(recipient_sk)
    box = nacl.public.SealedBox(sk)
    try:
        return box.decrypt(sealed)
    except nacl.exceptions.CryptoError:
        raise ValueError("Decryption failed (crypto_box_seal_open)")

def add_message_padding(message_bytes: bytes) -> bytes:
    orig_len = len(message_bytes)
    target_len = (((orig_len + 2 + 159) // 160) * 160) - 1
    padded = bytearray(target_len)
    padded[:orig_len] = message_bytes
    padded[orig_len] = 0x80
    return bytes(padded)

def remove_message_padding(padded_bytes: bytes) -> bytes:
    for i in range(len(padded_bytes) - 1, -1, -1):
        if padded_bytes[i] == 0x80:
            return padded_bytes[:i]
        if padded_bytes[i] != 0x00:
            return padded_bytes
    raise ValueError("Invalid padding")

def encrypt_using_session_protocol(sender_keys: SessionKeys, recipient: str, plaintext: bytes) -> bytes:
    recipient_pk = binascii.unhexlify(remove_prefix_if_needed(recipient))
    verification_data = plaintext + sender_keys.ed25519.public_key + recipient_pk
    signature = sender_keys.signing_key.sign(verification_data).signature
    plaintext_with_metadata = plaintext + sender_keys.ed25519.public_key + signature
    return crypto_box_seal(plaintext_with_metadata, recipient_pk)

def decrypt_with_session_protocol(recipient_keys: SessionKeys, envelope_content: bytes) -> tuple[bytes, str]:
    recipient_x25519_pk = remove_prefix_if_needed(recipient_keys.x25519.public_key)
    
    plaintext_with_metadata = crypto_box_seal_open(
        envelope_content,
        recipient_keys.x25519.private_key
    )
    
    signature_size = 64
    ed25519_public_key_size = 32
    min_size = signature_size + ed25519_public_key_size
    
    if len(plaintext_with_metadata) <= min_size:
        raise ValueError("Decrypted content too short")
        
    signature_start = len(plaintext_with_metadata) - signature_size
    signature = plaintext_with_metadata[signature_start:]
    
    pubkey_start = len(plaintext_with_metadata) - min_size
    pubkey_end = len(plaintext_with_metadata) - signature_size
    sender_ed25519_pubkey = plaintext_with_metadata[pubkey_start:pubkey_end]
    
    plainTextEnd = len(plaintext_with_metadata) - min_size
    plaintext = plaintext_with_metadata[:plainTextEnd]
    
    verification_data = plaintext + sender_ed25519_pubkey + recipient_x25519_pk
    verify_key = nacl.signing.VerifyKey(sender_ed25519_pubkey)
    
    try:
        verify_key.verify(verification_data, signature)
    except nacl.exceptions.BadSignatureError:
        raise ValueError("Invalid message signature")
        
    sender_x25519_pubkey = verify_key.to_curve25519_public_key().encode()
    sender_session_id = "05" + binascii.hexlify(sender_x25519_pubkey).decode()
    
    return plaintext, sender_session_id

def wrap_envelope(envelope_bytes: bytes) -> bytes:
    request = WebSocketRequestMessage(
        id=0,
        body=envelope_bytes,
        verb="PUT",
        path="/api/v1/message"
    )
    
    websocket = WebSocketMessage(
        type=WebSocketMessage.Type.REQUEST,
        request=request
    )
    return websocket.SerializeToString()

# --- Attachment encryption and decryption ---

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding length")
    for b in data[-pad_len:]:
        if b != pad_len:
            raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad_len]

def add_attachment_padding(data: bytes) -> bytes:
    import math
    orig_len = len(data)
    # Math.max(541, Math.floor(Math.pow(1.05, Math.ceil(Math.log(orig_len) / Math.log(1.05)))))
    if orig_len == 0:
        padded_size = 541
    else:
        log_len = math.log(orig_len)
        log_base = math.log(1.05)
        padded_size = int(max(541, math.floor(math.pow(1.05, math.ceil(log_len / log_base)))))
        
    max_attachment_size = 15 * 1024 * 1024 # 15MB
    if padded_size > max_attachment_size and orig_len <= max_attachment_size:
        padded_size = max_attachment_size
        
    padded = bytearray(padded_size)
    padded[:orig_len] = data
    return bytes(padded)

def encrypt_attachment_data(plaintext: bytes, keys: bytes, iv: bytes) -> tuple[bytes, bytes]:
    if len(keys) != 64:
        raise ValueError("Attachment key must be 64 bytes")
    if len(iv) != 16:
        raise ValueError("Attachment IV must be 16 bytes")
        
    aes_key = keys[:32]
    mac_key = keys[32:]
    
    # Pad plaintext for AES-CBC
    padded_plaintext = pkcs7_pad(plaintext, 16)
    
    # AES-CBC encrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # ivAndCiphertext = iv || ciphertext
    iv_and_ciphertext = iv + ciphertext
    
    # Compute MAC
    h = crypto_hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv_and_ciphertext)
    mac = h.finalize()
    
    # final payload: iv || ciphertext || mac
    encrypted_bin = iv_and_ciphertext + mac
    
    # digest: sha256 of encrypted_bin
    digest = hashlib.sha256(encrypted_bin).digest()
    
    return encrypted_bin, digest

def encrypt_attachment(data: bytes, add_padding: bool = True) -> dict:
    pointer_key = os.urandom(64)
    iv = os.urandom(16)
    padded = add_attachment_padding(data) if add_padding else data
    ciphertext, digest = encrypt_attachment_data(padded, pointer_key, iv)
    return {
        "ciphertext": ciphertext,
        "digest": digest,
        "key": pointer_key
    }

def decrypt_attachment(data: bytes, key: bytes, digest: bytes, size: Optional[int] = None) -> bytes:
    if len(key) != 64:
        raise ValueError("Attachment key must be 64 bytes")
    if len(data) < 48:
        raise ValueError("Attachment data too short")
        
    aes_key = key[:32]
    mac_key = key[32:]
    
    iv = data[:16]
    ciphertext = data[16:-32]
    iv_and_ciphertext = data[:-32]
    mac = data[-32:]
    
    # Verify MAC
    h = crypto_hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv_and_ciphertext)
    calculated_mac = h.finalize()
    if calculated_mac != mac:
        raise ValueError("Bad attachment MAC")
        
    # Verify Digest
    calculated_digest = hashlib.sha256(data).digest()
    if calculated_digest != digest:
        raise ValueError("Bad attachment digest")
        
    # AES-CBC decrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    decrypted = pkcs7_unpad(decrypted_padded)
    
    # If size is specified, truncate the padding added by add_attachment_padding
    if size is not None:
        if size <= len(decrypted):
            decrypted = decrypted[:size]
        else:
            raise ValueError("Decrypted attachment size mismatch")
            
    return decrypted

# --- Profile GCM Encryption/Decryption ---

def encrypt_profile(data: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Profile key must be 32 bytes")
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data, None) # returns ciphertext + 16-byte tag appended
    return iv + ciphertext

def decrypt_profile(data: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Profile key must be 32 bytes")
    if len(data) < 29: # 12 bytes IV + 16 bytes tag + at least 1 byte ciphertext
        raise ValueError("Profile data too short")
    iv = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(iv, ciphertext, None)
    except Exception:
        raise ValueError("Failed to decrypt profile data")
