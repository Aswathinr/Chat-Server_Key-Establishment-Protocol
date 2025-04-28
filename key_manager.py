# key_manager.py
# Secure Chat Project - Key and Certificate Management Module
# Created by Josna (Member 1)

# 📦 Import required libraries
import os
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, 
    load_pem_public_key
)
from cryptography.x509 import load_pem_x509_certificate

# ========================
# 🏗️ SETUP FUNCTIONS
# ========================

def initialize_folders():
    """Create Keys/ and Certs/ directories if they don't exist"""
    os.makedirs("Keys", exist_ok=True)
    os.makedirs("Certs", exist_ok=True)

# ========================
# 🔑 KEY GENERATION
# ========================

def generate_rsa_keypair():
    """
    Generates an RSA key pair (2048-bit)
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()

# ========================
# 💾 SAVE FUNCTIONS
# ========================

def save_private_key(key, filename):
    """Save private key to PEM file"""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def save_public_key(public_key, filename):
    """Save public key to PEM file"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def save_certificate(cert, filename):
    """Save certificate to PEM file"""
    with open(filename, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# ========================
# 📜 CERTIFICATE CREATION
# ========================

def generate_self_signed_cert(name, public_key, private_key):
    """
    Create a self-signed X.509 certificate
    Args:
        name: Common Name (e.g., "A", "B")
        public_key: The subject's public key
        private_key: The issuer's private key
    Returns:
        x509.Certificate
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name)
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(private_key, hashes.SHA256()))
    return cert

# ========================
# 🔄 LOAD FUNCTIONS (For Team)
# ========================

def load_private_key(path):
    """
    Load private key from PEM file
    Args:
        path: Path to .pem file
    Returns:
        RSAPrivateKey
    """
    with open(path, 'rb') as f:
        return load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key(path):
    """
    Load public key from PEM file
    Args:
        path: Path to .pem file
    Returns:
        RSAPublicKey
    """
    with open(path, 'rb') as f:
        return load_pem_public_key(f.read(), backend=default_backend())

def load_certificate(path):
    """
    Load X.509 certificate from PEM file
    Args:
        path: Path to .pem file
    Returns:
        x509.Certificate
    """
    with open(path, 'rb') as f:
        return load_pem_x509_certificate(f.read(), backend=default_backend())

# ========================
# 🚀 MAIN EXECUTION
# ========================

def generate_all_entities():
    """Generate keys and certificates for all entities (A, B, C, S)"""
    initialize_folders()

    for name in ['A', 'B', 'C', 'S']:
        print(f"\n🔐 Generating keys and cert for {name}...")

        # Generate and save keys
        priv_key, pub_key = generate_rsa_keypair()
        save_private_key(priv_key, f"Keys/{name}_priv.pem")
        save_public_key(pub_key, f"Keys/{name}_pub.pem")

        # Generate and save certificate
        cert = generate_self_signed_cert(name, pub_key, priv_key)
        save_certificate(cert, f"Certs/cert_{name}.pem")

    print("\n✅ All keys and certificates generated successfully!")

if __name__ == "__main__":
    generate_all_entities()