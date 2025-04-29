# Chat-Server_Key-Establishment-Protocol
Design a key establishment protocol that will allow a Mutually Agreed Session key (Kabc) to be established between three entities A, B and C. This key can then be used to secure a chat between the three entities.

This project implements a Secure Group Chat System where three clients (A, B, C) establish a shared session key (Kabc) securely using public key certificates and RSA-based encryption and signatures.

✅ Key Features:

Authenticated key exchange using RSA and digital signatures (RSA-PSS).

Confidential transfer of nonces via RSA-OAEP encryption.

Session key (Kabc) derived from verified nonces.

AES-GCM encryption for secure chat messaging after key establishment.

Server acts only as a relay — cannot decrypt or tamper with messages.

End-to-end integrity and confidentiality ensured for all communications.

Built with:

Python 3

cryptography library

Socket programming

Certificate-based trust model
