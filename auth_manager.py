import os
import secrets
import hashlib
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key
)
from cryptography.exceptions import InvalidSignature

class AuthManager:
    def __init__(self, entity_name: str, priv_key_path: str, peer_pub_key_path: Optional[str] = None):
        self.entity = entity_name
        self.priv_key = self._load_private_key(priv_key_path)
        self.peer_pub_key = self._load_public_key(peer_pub_key_path) if peer_pub_key_path else None
        self._verify_key_pair()

    def _load_private_key(self, path: str) -> rsa.RSAPrivateKey:
        print(f"🔑 Loading private key from {path}...")
        with open(path, "rb") as f:
            key_data = f.read()
            key = load_pem_private_key(key_data, password=None)
            print(f"✅ Private key loaded successfully from {path}")
            return key

    def _load_public_key(self, path: str) -> rsa.RSAPublicKey:
        print(f"🔑 Loading public key from {path}...")
        with open(path, "rb") as f:
            key_data = f.read()
            key = load_pem_public_key(key_data)
            print(f"✅ Public key loaded successfully from {path}")
            return key

    def _verify_key_pair(self):
        test_msg = b"KEY PAIR VALIDATION TEST MESSAGE"
        signature = self._sign_with_pss(test_msg)
        try:
            self._verify_with_pss(test_msg, signature, self.priv_key.public_key())
            print(f"✅ Key pair validation successful for {self.entity}")
        except Exception as e:
            print(f"❌ Key pair validation failed: {e}")
            raise

    def _sign_with_pss(self, message: bytes) -> bytes:
        return self.priv_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    def _verify_with_pss(self, message: bytes, signature: bytes, public_key: rsa.RSAPublicKey):
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    def sign(self, message: bytes) -> bytes:
        return self._sign_with_pss(message)

    def verify(self, message: bytes, signature: bytes, peer_pub_key_path: Optional[str] = None) -> bool:
        try:
            pub_key = self._load_public_key(peer_pub_key_path) if peer_pub_key_path else self.peer_pub_key
            self._verify_with_pss(message, signature, pub_key)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"❌ Verification error: {str(e)}")
            return False

    def generate_nonce(self) -> bytes:
        return secrets.token_bytes(16) + hashlib.sha256(self.entity.encode()).digest()[:8]

    def perform_handshake(self, peer_pub_key_path: str) -> Tuple[bool, str]:
        try:
            print(f"\n🔐 [{self.entity}] Starting handshake...")
            our_nonce = self.generate_nonce()
            our_sig = self.sign(our_nonce)
            print(f"[{self.entity}] Generated nonce: {our_nonce.hex()[:12]}...")
            print(f"[{self.entity}] Created signature: {our_sig.hex()[:16]}...")

            # Determine peer role based on self
            if self.entity in ["A", "B", "C"]:
                peer_entity = "S"
                peer_priv_path = "Keys/S_priv.pem"
                verification_key_path = f"Keys/{self.entity}_pub.pem"
            else:
                # Get entity name from pub key file path like Keys/B_pub.pem
                peer_entity = os.path.basename(peer_pub_key_path).split("_")[0]
                peer_priv_path = f"Keys/{peer_entity}_priv.pem"
                verification_key_path = "Keys/S_pub.pem"

            print(f"[{self.entity}] Initializing peer ({peer_entity}) authentication...")
            print(f"[{self.entity}] Verifying our signature with peer...")
            verification_pub_key = self._load_public_key(verification_key_path)
            verification_pub_key.verify(
                our_sig,
                our_nonce,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print(f"[{self.entity}] Our signature verified successfully by peer")

            print(f"[{self.entity}] Generating peer nonce and signature...")
            peer_auth = AuthManager(peer_entity, priv_key_path=peer_priv_path, peer_pub_key_path=peer_pub_key_path)
            peer_nonce = peer_auth.generate_nonce()
            peer_sig = peer_auth.sign(peer_nonce)
            print(f"[{self.entity}] Received peer nonce: {peer_nonce.hex()[:12]}...")
            print(f"[{self.entity}] Peer signature: {peer_sig.hex()[:16]}...")

            if not self.verify(peer_nonce, peer_sig, peer_pub_key_path):
                return False, "Failed to verify peer's signature"

            print(f"[{self.entity}] Handshake completed successfully")
            return True, "Success"

        except Exception as e:
            return False, f"Handshake error: {e}"


if __name__ == "__main__":
    print("🔍 Starting the authentication manager script...")

    try:
        print("\n=== Testing Client Authentication ===")
        client_auth = AuthManager(
            entity_name="B",
            priv_key_path="Keys/B_priv.pem",
            peer_pub_key_path="Keys/S_pub.pem"
        )
        success, msg = client_auth.perform_handshake("Keys/S_pub.pem")
        print("✅ Client authentication succeeded!" if success else f"❌ {msg}")

        print("\n=== Testing Server Authentication ===")
        server_auth = AuthManager(
            entity_name="S",
            priv_key_path="Keys/S_priv.pem",
            peer_pub_key_path="Keys/B_pub.pem"
        )
        success, msg = server_auth.perform_handshake("Keys/B_pub.pem")
        print("✅ Server authentication succeeded!" if success else f"❌ {msg}")

    except Exception as e:
        print(f"❌ An error occurred: {str(e)}")
