# Chat-Server_Key-Establishment-Protocol
📜 Description
This project implements a Secure Group Chat System where three clients (A, B, C) establish a shared session key (Kabc) securely using RSA encryption, digital signatures, and public key certificates.

The system ensures:

Confidentiality of all exchanged data.

Authentication of participants.

Integrity of all critical communications.

No trust required in the relay server.

🔒 Key Features
Certificate-based public key infrastructure: Each entity (A, B, C, Server S) uses X.509 certificates.

Secure key establishment: Random nonces are encrypted and authenticated between clients.

Session key derivation (Kabc): Derived using HKDF-SHA256 from verified nonces.

Secure group chat: AES-GCM is used for end-to-end encrypted messaging.

Server S acts only as a blind relay and certificate provider.

🛠️ Technologies Used
Python 3

Cryptography (RSA, AES-GCM, HKDF, Digital Signatures)

Sockets (TCP networking)

JSON for data encoding

Base64 encoding for binary data transmission

⚙️ How It Works
Key Exchange:

Each client generates a random nonce.

Nonces are encrypted individually for each peer using their public key.

A digital signature (RSA-PSS) over nonce + IDs is generated.

Encrypted nonces and signatures are sent to the server.

Payload Verification:

Each client decrypts received nonces using its private key.

Reconstructs hash input (nonce + IDs) and verifies sender's signature.

On successful verification, nonces are collected.

Session Key Derivation:

Clients use HKDF-SHA256 to derive a common shared key (Kabc).

The server cannot reconstruct Kabc or see any random nonce.

Secure Chat:

Messages are encrypted with AES-GCM using Kabc.

Only clients who have correctly derived Kabc can decrypt messages.
