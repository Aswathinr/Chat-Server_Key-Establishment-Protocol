# key_exchange.py

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
from key_manager import load_private_key, load_public_key

# Constants
NONCE_SIZE = 16
HKDF_SALT_SIZE = 16
HKDF_KEY_SIZE = 32

# Generate a 16-byte secure nonce
def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)

# Sign any message with RSA-PSS
def sign_nonce(message: bytes, private_key) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Load private/public key pair from PEM files
def load_my_key_pair(role: str):
    priv_path = f"Keys/{role}_priv.pem"
    pub_path = f"Keys/{role}_pub.pem"
    return load_private_key(priv_path), load_public_key(pub_path)

# Derive shared session key Kabc from 3 nonces using HKDF
def derive_kabc(nonces: list[bytes]) -> bytes:
    if len(nonces) != 3:
        raise ValueError("Exactly 3 nonces required to derive Kabc")
    for nonce in nonces:
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Each nonce must be {NONCE_SIZE} bytes")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"".join(nonces))
    salt = digest.finalize()[:HKDF_SALT_SIZE]
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_KEY_SIZE,
        salt=salt,
        info=b'kabc-derivation'
    )
    return hkdf.derive(b"".join(nonces))
