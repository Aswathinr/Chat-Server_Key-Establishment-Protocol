# ===========================
# 🔐 Encrypted Client for A (with Certificate-based Key Loading)
# ===========================
import socket, threading, json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from key_exchange import (
    load_my_key_pair, generate_nonce, sign_nonce, derive_kabc
)
from secure_chat import encrypt_message, decrypt_message
from key_manager import load_certificate

CLIENT_ID = "A"
PEERS = ["A", "B", "C"]
PEERS.remove(CLIENT_ID)
SERVER_ADDR = ("localhost", 5555)

def recv_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode().strip()

def load_peer_public_key_from_cert(peer_id):
    cert = load_certificate(f"Certs/cert_{peer_id}.pem")
    return cert.public_key()

def encrypt_nonce_for_peer(nonce: bytes, peer_pub):
    return peer_pub.encrypt(
        nonce,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_nonce_from_peer(ciphertext: bytes, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def main():
    print(f"\n🔐 [{CLIENT_ID}] Connecting to server and starting secure handshake...")
    sock = socket.socket()
    sock.connect(SERVER_ADDR)
    sock.send(CLIENT_ID.encode())

    r_self = generate_nonce()
    priv_key, _ = load_my_key_pair(CLIENT_ID)

    encrypted_payloads = {}
    for peer in PEERS:
        peer_pub = load_peer_public_key_from_cert(peer)
        encrypted_nonce = encrypt_nonce_for_peer(r_self, peer_pub)
        encrypted_payloads[peer] = base64.b64encode(encrypted_nonce).decode()

    hash_input = r_self + b"".join([peer.encode() for peer in sorted([CLIENT_ID] + PEERS)])
    sig_self = sign_nonce(hash_input, priv_key)

    payload = {
        "id": CLIENT_ID,
        "payloads": encrypted_payloads,
        "sig": base64.b64encode(sig_self).decode()
    }
    sock.sendall((json.dumps(payload) + "\n").encode())

    peer_nonces = {}
    for _ in range(2):
        peer_data = json.loads(recv_line(sock))
        peer_id = peer_data["id"]
        enc_nonce = base64.b64decode(peer_data["payloads"][CLIENT_ID])
        peer_sig = base64.b64decode(peer_data["sig"])
        peer_nonce = decrypt_nonce_from_peer(enc_nonce, priv_key)

        hash_input = peer_nonce + b"".join([id.encode() for id in sorted([CLIENT_ID] + PEERS)])
        peer_pub = load_peer_public_key_from_cert(peer_id)
        peer_pub.verify(
            peer_sig,
            hash_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        peer_nonces[peer_id] = peer_nonce

    peer_nonces[CLIENT_ID] = r_self
    kabc = derive_kabc([peer_nonces[i] for i in sorted(peer_nonces)])
    aesgcm = AESGCM(kabc)
    print(f"✅ [{CLIENT_ID}] Secure session key established.")

    def receive():
        while True:
            try:
                data = sock.recv(4096)
                msg = decrypt_message(aesgcm, data)
                if msg:
                    print(f"\n📥 {msg}\n> ", end="")
            except:
                break

    threading.Thread(target=receive, daemon=True).start()

    while True:
        try:
            msg = input(" > ")
            sock.send(encrypt_message(aesgcm, msg))
        except:
            break

if __name__ == "__main__":
    main()