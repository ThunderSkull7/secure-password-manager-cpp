# Security Architecture & Cryptographic Primitives

This document outlines the cryptographic standards, memory security designs, parameters, and threat model considerations implemented in the Secure Password Manager cryptographic security layer (Batch 4).

> **Notice:** This batch establishes the cryptographic primitives (`CryptoService`, `SecureKey`, `SecureBuffer`). A complete encrypted file-based vault and user authentication workflow are implemented in subsequent batches.

---

## 1. Cryptographic Algorithms and Standards

The cryptographic layer exclusively utilizes [libsodium](https://doc.libsodium.org/) (v1.0.22) primitives. Custom or non-standard cryptographic implementations are strictly avoided.

| Component | Standard / Algorithm | Primitive / API | Size |
|---|---|---|---|
| **Key Derivation** | Argon2id v1.3 | `crypto_pwhash` (`crypto_pwhash_ALG_ARGON2ID13`) | 256-bit key output |
| **KDF Salt** | CSPRNG Random Salt | `randombytes_buf` | 16 bytes (128 bits) |
| **Authenticated Encryption** | XChaCha20-Poly1305-IETF | `crypto_aead_xchacha20poly1305_ietf_encrypt` | Stream cipher + MAC |
| **Nonce** | Extended Random Nonce | `randombytes_buf` | 24 bytes (192 bits) |
| **Authentication Tag** | Poly1305 MAC | Integrated within AEAD construction | 16 bytes (128 bits) |
| **Zeroization** | Constant-time Memory Scrubbing | `sodium_memzero` & `sodium_free` | Dynamic |

---

## 2. Key Derivation (Argon2id v1.3)

### Parameters
Key derivation transforms the user's master password into a 256-bit encryption key (`SecureKey`) using the Argon2id v1.3 algorithm:

- **Algorithm**: `crypto_pwhash_ALG_ARGON2ID13`
- **Salt Length**: 16 bytes (`crypto_pwhash_SALTBYTES`), generated randomly for each vault via `randombytes_buf`. Salts are never hardcoded or reused across vaults.
- **Operations Limit (`ops_limit`)**: `crypto_pwhash_OPSLIMIT_INTERACTIVE` (2 iterations).
- **Memory Limit (`mem_limit`)**: `crypto_pwhash_MEMLIMIT_INTERACTIVE` (67,108,864 bytes / 64 MiB).
- **Output Key Length**: 32 bytes (`crypto_aead_xchacha20poly1305_ietf_KEYBYTES`).

### Security Properties
- **Side-Channel & GPU Resistance**: Argon2id combines Argon2d (data-dependent indexing for GPU/ASIC resistance) and Argon2i (data-independent indexing for side-channel attack resistance).
- **Parameter Validation**: All KDF inputs are strictly verified against libsodium lower/upper bounds. Malformed or unsupported parameter requests are rejected before execution.

---

## 3. Authenticated Encryption (XChaCha20-Poly1305-IETF)

### Extended Nonce Advantage
Standard ChaCha20-Poly1305 uses a 96-bit (12-byte) nonce, requiring careful state tracking to avoid nonce reuse collisions. XChaCha20 extends the nonce size to **192 bits (24 bytes)** using the HChaCha20 subkey derivation block. At 192 bits, nonces can be generated completely randomly (`randombytes_buf`) for every encryption operation without risk of collision under practical operational volumes.

### Integrity & Additional Authenticated Data (AAD)
- **Tag Validation**: Ciphertext incorporates a 128-bit Poly1305 authentication tag appended to the ciphertext stream.
- **AAD Integrity**: The encryption and decryption APIs support Additional Authenticated Data (AAD). AAD is non-secret plaintext metadata (e.g., format version, salt, KDF parameters) whose integrity is mathematically bound to the ciphertext. Any modification to AAD causes immediate authentication failure.
- **No Unauthenticated Output**: `CryptoService::decrypt()` verifies the Poly1305 MAC before returning decrypted data. If authentication fails, no plaintext is ever returned or leaked.

### Payload Limits
To prevent memory exhaustion and integer overflow attacks, payloads are constrained to a maximum of **16 MiB** (`CryptoConstants::MAX_PAYLOAD_BYTES`), which comfortably accommodates local password vault databases.

---

## 4. Memory Security Design

### `SecureKey`
- **Ownership**: Move-only (`non-copyable`). Copy construction and copy assignment are deleted at compile-time.
- **Zeroization**: The underlying 32-byte key buffer is wiped using `sodium_memzero` upon destruction.
- **Safe Move Semantics**: Moving a `SecureKey` transfers ownership and immediately zeroes out the source object's memory, marking the moved-from key as invalid.
- **Non-printable**: No `std::string` conversions or stream output operators exist for `SecureKey`.

### `SecureBuffer`
- **Page-Protected Memory**: Allocations utilize `sodium_malloc()`, which provides:
  - Guard pages placed immediately before and after the allocated region to trap buffer overflows and underflows.
  - Canaries to detect memory corruption.
- **Destruction**: Deallocation uses `sodium_free()`, which securely zeroes the allocated memory before releasing virtual address pages back to the operating system.
- **Move-Only**: Strict move-only semantics ensure single ownership and prevent accidental duplication in unmanaged buffers.

### Memory Limitations & Considerations
- Standard `std::string` or `std::string_view` arguments passed into `CryptoService` (such as the initial master password string from user input) do not guarantee automatic memory zeroization upon destruction by the runtime. Secure wiping wrappers for user input will be integrated alongside interactive terminal handling.

---

## 5. Threat Model Considerations

1. **Tampering & Bit-Flipping**: Protected by Poly1305 MAC. Modifying even 1 bit in ciphertext, nonce, or AAD causes authentication failure.
2. **Offline Brute-Force Attacks**: Mitigated by Argon2id's 64 MiB memory hardness, increasing the cost of specialized FPGA/ASIC hardware attacks.
3. **Nonce Reuse**: Mitigated by XChaCha20's 192-bit random nonce space.
4. **Information Leakage**: Diagnostic messages and errors intentionally omit plaintext, secret keys, and raw ciphertext.
