# Architecture

## Overall security level
A minimal security level of 256 bits has been defined. This is equivalent to a level 5 in post-quantum as defined by the NIST.

## Cryptographic primitives

**Argon2id:** Hash function used for password derivation (files/directories and key wrapping) into cryptographically secure keys. Intrinsically resistant to Shor's algorithm; only Grover's algorithm could have posed a threat to this construction. However, the chosen output size and its highly memory-intensive construction make it computationally impossible to brute force. Chosen because it is ideal as a KDF with low-entropy inputs.

- **Memory cost:** 65536 KiB (64 MiB)
- **Iterations:** 3
- **Parallelism:** 1
- **Output size:** 32 bytes
  - To maintain the overall security level at 256 bits as previously stated.
- **Salt size:** 32 bytes

These parameters were chosen by following the recommendations of [this article](https://www.ciphertools.org/blogs/how-to-choose-the-right-parameters-for-argon2).

---

**HKDF:** Hash function for deriving paths into usable cryptographic material for generating words associated with those paths, as well as for deriving the shared secret in asymmetric encryption into a cryptographically secure key. Enables domain separation to ensure that a key used in one context cannot be reused in another. This function guarantees post-quantum resistance because hash functions are not susceptible to Shor's algorithm, and a 256-bit output still provides more than sufficient security against Grover's algorithm. Chosen because it is ideal as a KDF for high-entropy inputs (tied to the primitive used).

- **Hash primitive:** SHA3-256
  - The 256-bit variant was again chosen to maintain the same security level.
- **Salt:**
  - For path derivation: `"qrypto-word-derivation"`
  - For shared secret derivation: `"qrypto-session-key"`
- **Input Key Material:**
  - For path derivation: 32 bytes, a unique global salt used for all word generation
  - For shared secret derivation: 32 bytes, the shared secret generated during the ML-KEM process
- **Output size:** 32 bytes, the key size for XChaCha20-Poly1305

---

**ML-KEM-1024:** Asymmetric encryption algorithm used for client–server communication. Based on lattices and specifically on the LWE problem, making it computationally secure against a quantum computer at the corresponding security level. Unlike RSA, the public key is not used directly to encrypt content (typically a symmetric key); instead, it provides a shared secret (a random seed) which is then used to encrypt content (no new symmetric key is needed — it is derived from this seed). The private key is used to decrypt this shared secret and thereby decrypt the content. Chosen as the primitive for asymmetric encryption because it is already standardized by FIPS, unlike HQC, which does not provide a verified Rust implementation.

- **Private key size:** 3168 bytes
- **Public key size:** 1568 bytes
- **Shared secret size:** 32 bytes
  - Satisfies the defined security level.
- **Ciphertext size:** 1568 bytes
  - This ciphertext corresponds to the shared secret encrypted with the public key.

These values guarantee security level 5 (according to NIST guidelines), which is equivalent to AES-256.

---

**ML-DSA-87:** Signature algorithm guaranteeing the authenticity of all data transmitted between the client and server, also known as Crystals-Dilithium. Based on the LWE and SIS problems on lattices, it is not susceptible to Shor's algorithm and is only partially susceptible to Grover's algorithm depending on signature sizes. Chosen for its smaller signature sizes and faster signing speed compared to SLH-DSA.

- **Signature size:** 4627 bytes
- **Signing key size:** 4896 bytes
- **Verification key size:** 2592 bytes

These values guarantee a security level at minimum equivalent to AES-256.

---

**XChaCha20-Poly1305:** Authenticated symmetric encryption algorithm used for encrypting files, data in metadata tables, and requests and responses exchanged between the client and server. To ensure post-quantum security, it is sufficient to double the key size (up to 256 bits), which weakens or entirely negates the effect of Grover's algorithm. Shor's algorithm does not apply to this non-linear construction. XChaCha20-Poly1305 is a better option for symmetric file encryption than AES-GCM-256 in this context, because it allows encrypting larger files with the same key/nonce pair (64 GB for AES-GCM versus theoretically unlimited for XChaCha20), is generally faster regardless of hardware, and executes naturally in constant time, protecting it against possible timing attacks.

- **Symmetric key size:** 32 bytes
  - Satisfies the minimum defined security level.
- **Nonce size:** 24 bytes
  - Constrained by the standard; the only bottleneck where 256-bit security is not achievable.
  - Random and unique for each piece of encrypted data.

---

**HMAC:** Guarantees the integrity of metadata tables; post-quantum resistant for the same reasons as HKDF. Chosen to remain consistent with the use of SHA3, but primarily because unlike Poly1305 or GMAC, it does not require a nonce.

- **Hash primitive:** SHA3-256
  - The 256-bit variant was again chosen to maintain the same security level.
- **Output size:** 32 bytes
  - Guarantees the 256-bit security level.


