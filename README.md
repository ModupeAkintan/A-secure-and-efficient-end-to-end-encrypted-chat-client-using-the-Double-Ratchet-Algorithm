# A-secure-and-efficient-end-to-end-encrypted-chat-client-using-the-Double-Ratchet-Algorithm

In this repository, I was tasked with implementing a secure and efficient end-to-end encrypted chat client using the Double Ratchet Algorithm. The Double Ratchet Algorithm is a popular session setup protocol utilized by real-world chat systems such as Signal and WhatsApp. Additionally, the implementation includes considerations for government surveillance, where all messages must be encrypted with a fixed public key issued by the government.

The chat client utilizes the Double Ratchet Algorithm to provide end-to-end encrypted communications. The implementation adheres to the specifications outlined in the Signal documentation, with necessary modifications and clarifications. Key components include the utilization of various cryptographic primitives such as key exchange, public key encryption, digital signatures, and authenticated encryption. 

The implementation uses the SubtleCrypto library for cryptographic operations, generates and distributes ElGamal key pairs for Diffie-Hellman key exchange, encrypts messages using AES-GCM symmetric encryption algorithm, and includes the government's public key encryption in message headers. It also implements Forward Secrecy and Break-in Recovery properties.
