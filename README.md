# session-python

[![PyPI version](https://img.shields.io/pypi/v/session-python.svg)](https://pypi.org/project/session-python/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A pure Python implementation of the **Session Messenger** programmatic client protocol.

This library is a 1-to-1 port of the official `@session.js` (Bun) client modules to Python, allowing you to build Session bots, send encrypted messages, upload/download attachments, handle read receipts, typing indicators, message reactions, and unsends natively in Python, **without** wrapping any Node/Bun subprocesses.

---

## 🚀 Features

*   **Zero JS Subprocesses**: Natively implemented in Python using PyNaCl, Cryptography, and Protobuf.
*   **Oxen Mnemonics**: Ported 13-word Electrum/Monero style mnemonic decoder & encoder (Oxen standard) with CRC32 checksums.
*   **Session Protocol Encryption**: SealedBox encryption, sender identity signatures, envelope wrapping, and 160-byte block size padding.
*   **Proxy Support**: SOCKS5 and HTTP proxy support out of the box (uses `socks5h://` to perform remote DNS resolution for high privacy).
*   **Redundant Node Routing**: Swarm lookup and node rotation (automatically retries other nodes in the swarm if a connection fails).
*   **In-Memory Swarm Cache**: Caches resolved swarms to reduce network calls and decrease message sending latency by up to 4x.
*   **Attachments Support**: Encrypts (AES-CBC + HMAC-SHA256) and uploads/downloads attachments to the Session file server.
*   **Typing Indicators**: Show or hide typing indicators (`show_typing_indicator`, `hide_typing_indicator`).
*   **Message Reactions**: React to messages with emojis (`add_reaction`, `remove_reaction`).
*   **Read Receipts**: Mark messages as read (`mark_messages_as_read`).
*   **Message Deletion (Unsend)**: Delete messages locally and propagate deletion commands (`delete_message`, `delete_messages`).
*   **SOGS Support**: Sign and send requests to SOGS (Open Groups) (`send_sogs_request`, `sign_sogs_request`).
*   **Pythonic Interface**: Exposes context managers (`with Session() as s:`) and static generators (`Session.generate_mnemonic()`).

---

## 📦 Installation

To install `session-python` along with its dependencies:

```bash
pip install pynacl cryptography protobuf requests pysocks
```

---

## 🛠️ Quick Start

### 1. Basic Send Message

```python
from session_python import Session

# Initialize with SOCKS5 proxy
PROXY = "socks5h://user:pass@host:port"
RECIPIENT_ID = "059ce57868de2b93dc56e3bce3780db7a7aadc91d8e236f4a8f972f92e609ab609"

with Session(proxy=PROXY) as session:
    # Set your account mnemonic or generate a new one
    mnemonic = Session.generate_mnemonic()
    print(f"Generated new mnemonic: {mnemonic}")
    
    session.set_mnemonic(mnemonic, display_name="Python Bot")
    print(f"Your Session ID: {session.get_session_id()}")

    # Send a text message
    result = session.send_message(to=RECIPIENT_ID, text="Hello from Python!")
    print(f"Message Hash: {result['messageHash']}")
```

### 2. Polling for Messages

```python
from session_python import Session, Poller

with Session(proxy=PROXY) as session:
    session.set_mnemonic("your 13 word mnemonic here...")
    
    poller = Poller(session)
    print("Listening for messages...")
    
    while True:
        messages = poller.poll()
        for msg in messages:
            if msg["type"] == "data":
                print(f"Received from {msg['from']}: {msg['body']}")
        time.sleep(5)
```

### 3. File Attachments

```python
with Session(proxy=PROXY) as session:
    session.set_mnemonic(mnemonic)

    # 1. Send file attachment
    with open("photo.jpg", "rb") as f:
        file_bytes = f.read()

    attachments = [{
        "data": file_bytes,
        "name": "photo.jpg",
        "content_type": "image/jpeg"
    }]
    session.send_message(to=RECIPIENT_ID, text="Here is a file!", attachments=attachments)

    # 2. Download and decrypt attachment from a polled message pointer
    # file_ptr is extracted from incoming messages: msg["attachments"][0]
    decrypted_file = session.get_file(file_ptr)
    with open("downloaded_photo.jpg", "wb") as f:
        f.write(decrypted_file)
```

### 4. Advanced Chat Operations

```python
with Session(proxy=PROXY) as session:
    session.set_mnemonic(mnemonic)
    
    # Typing Indicators
    session.show_typing_indicator(RECIPIENT_ID)
    time.sleep(2)
    session.hide_typing_indicator(RECIPIENT_ID)
    
    # Message Reactions
    session.add_reaction(message_timestamp=1783586415070, message_author=RECIPIENT_ID, emoji="🔥")
    session.remove_reaction(message_timestamp=1783586415070, message_author=RECIPIENT_ID, emoji="🔥")
    
    # Read Receipts
    session.mark_messages_as_read(conversation=RECIPIENT_ID, timestamps=[1783586415070])
    
    # Delete / Unsend Messages
    session.delete_message(conversation=RECIPIENT_ID, timestamp=1783586415070, hash_val="IXFgLeoj...")
```

---

## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
