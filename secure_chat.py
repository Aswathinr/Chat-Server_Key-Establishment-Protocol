# secure_chat.py

import os, time, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Encrypt a plaintext string using AES-GCM and return the full packet
def encrypt_message(aesgcm: AESGCM, plaintext: str) -> bytes:
    nonce = os.urandom(12)
    payload = {
        "timestamp": int(time.time()),
        "message": plaintext
    }
    data = json.dumps(payload).encode()
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

# Decrypt a packet using AES-GCM and return the string message
def decrypt_message(aesgcm: AESGCM, packet: bytes) -> str:
    nonce = packet[:12]
    ciphertext = packet[12:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext.decode())
        if abs(time.time() - data["timestamp"]) > 60:
            print("⚠️ Warning: Message timestamp is old.")
        return data["message"]
    except Exception as e:
        print("❌ Decryption error:", e)
        return None
