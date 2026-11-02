# Security Architecture & Cryptographic Primitives

This document outlines the cryptographic standards, memory security designs, parameters, vault binary format, atomic persistence model, and threat model considerations implemented in the Secure Password Manager (Batches 1–5).

---

## 1. Cryptographic Algorithms and Standards

The cryptographic layer exclusively utilizes [libsodium](https://doc.libsodium.org/) (v1.0.22) primitives. Custom or non-standard cryptographic implementations are strictly avoided.

| Component | Standard / Algorithm | Primitive / API | Size / Details |
|---|---|---|---|
| **Key Derivation** | Argon2id v1.3 | `crypto_pwhash` (`crypto_pwhash_ALG_ARGON2ID13`) | 256-bit key output |
| **KDF Salt** | CSPRNG Random Salt | `randombytes_buf` | 16 bytes (128 bits) |
| **Authenticated Encryption** | XChaCha20-Poly1305-IETF | `crypto_aead_xchacha20poly1305_ietf_encrypt` | Stream cipher + MAC |
| **Nonce** | Extended Random Nonce | `randombytes_buf` | 24 bytes (192 bits) |
| **Authentication Tag** | Poly1305 MAC | Integrated within AEAD construction | 16 bytes (128 bits) |
| **Associated Data (AAD)** | Binary Header Configuration | Included in Poly1305 computation | 48 bytes (Offsets 0..47) |
| **Memory Zeroization** | Constant-time Memory Scrubbing | `sodium_memzero` & `sodium_free` | Dynamic |
| **Guarded Buffers** | Page-protected Memory | `sodium_malloc` (guard pages + canaries) | Page-aligned |

---

## 2. Key Derivation (Argon2id v1.3)

### Parameters & Default Profile
Key derivation transforms the user's master password into a 256-bit encryption key (`SecureKey`) using the Argon2id v1.3 algorithm:

- **Algorithm**: `crypto_pwhash_ALG_ARGON2ID13` (ID = `2`)
- **Salt Length**: 16 bytes (`crypto_pwhash_SALTBYTES`), generated randomly for each vault via `randombytes_buf`. Salts are never hardcoded or reused across vaults.
- **Operations Limit (`ops_limit`)**: `crypto_pwhash_OPSLIMIT_INTERACTIVE` (2 iterations).
- **Memory Limit (`mem_limit`)**: `crypto_pwhash_MEMLIMIT_INTERACTIVE` (67,108,864 bytes / 64 MiB).
- **Output Key Length**: 32 bytes (`crypto_aead_xchacha20poly1305_ietf_KEYBYTES`).

### Strict Pre-Derivation Validation Bounds
To defend against Denial-of-Service (DoS) and resource exhaustion attacks (e.g. an attacker modifying vault header limits to 1,000,000 iterations or 128 GB of RAM), all KDF parameters are strictly validated *before* invoking `crypto_pwhash`:
- `ops_limit`: Must be between `1` (`crypto_pwhash_OPSLIMIT_MIN`) and `10` (`MAX_KDF_OPS_LIMIT`).
- `memory_limit`: Must be between `8192` bytes (8 KiB) and `536,870,912` bytes (512 MiB).
- `algorithm`: Must match `crypto_pwhash_ALG_ARGON2ID13` (2).
Any file containing out-of-bounds parameters is rejected immediately with `VaultErrorCode::ResourceLimitExceeded` without performing any key derivation.

---

## 3. Versioned Binary Vault File Format (`SPMV`)

The vault storage format is an explicit, endian-independent binary specification. All multi-byte integers are serialized in Little-Endian byte order without compiler padding.

### Header Byte Layout (80 Bytes Fixed Size)

```text
+-----------------------+---------+--------------------+---------------------------------------------+
| Offset (Bytes)        | Size    | Field Name         | Data Type / Value                           |
+-----------------------+---------+--------------------+---------------------------------------------+
| 00 - 03 (4 bytes)     | 4 B     | Magic Identifier   | ASCII "SPMV" (0x53, 0x50, 0x4D, 0x56)       |
| 04 - 07 (4 bytes)     | 4 B     | Format Version     | uint32_t LE (1)                             |
| 08 - 11 (4 bytes)     | 4 B     | Cipher Algorithm   | uint32_t LE (1 = XChaCha20-Poly1305-IETF)   |
| 12 - 15 (4 bytes)     | 4 B     | KDF Algorithm      | uint32_t LE (2 = Argon2id v1.3)             |
| 16 - 23 (8 bytes)     | 8 B     | KDF Ops Limit      | uint64_t LE (e.g. 2 for interactive)        |
| 24 - 31 (8 bytes)     | 8 B     | KDF Memory Limit   | uint64_t LE (e.g. 67108864 for 64 MiB)      |
| 32 - 47 (16 bytes)    | 16 B    | KDF Random Salt    | uint8_t[16] (libsodium CSPRNG salt)         |
+-----------------------+---------+--------------------+---------------------------------------------+  <-- End of AAD (48 B)
| 48 - 71 (24 bytes)    | 24 B    | AEAD Nonce         | uint8_t[24] (XChaCha20 random 192-bit nonce)|
| 72 - 79 (8 bytes)     | 8 B     | Ciphertext Length  | uint64_t LE (Length of ciphertext + tag)    |
+-----------------------+---------+--------------------+---------------------------------------------+  <-- End of Header (80 B)
| 80 - EOF              | N bytes | Encrypted Payload  | Encrypted JSON credentials + 16B Poly1305   |
+-----------------------+---------+--------------------+---------------------------------------------+
```

### Additional Authenticated Data (AAD) Binding
The cryptographic configuration header spanning **bytes 0 through 47** (48 bytes total: magic, format version, cipher algorithm ID, KDF algorithm ID, KDF ops limit, KDF memory limit, and KDF salt) serves as Additional Authenticated Data (AAD) for the XChaCha20-Poly1305 AEAD construction.

- **Integrity Enforcement**: Any bit flipped within the 48-byte header causes the Poly1305 authentication tag verification to fail during decryption.
- **Algorithm Downgrade Protection**: An attacker cannot modify the algorithm ID or downgrade format version without detection.
- **Nonce Authentication**: The 192-bit nonce directly parameterizes the Poly1305 one-time key; any tampering with the nonce similarly fails authentication.

---

## 4. Credential Serialization and In-Memory Security

Credentials are serialized into structured JSON using `nlohmann/json` before encryption:
- **Full Field Preservation**: All credential fields (`id`, `service`, `username`, `password`, `url`, `category`, `notes`, `created_at`, `updated_at`) are preserved exactly.
- **Sensitive Memory Isolation**: The JSON serialization string is immediately transferred into a guard-page protected `SecureBuffer`, and the intermediate string memory is scrubbed using `sodium_memzero`.
- **Validation on Deserialization**: Deserialized records undergo duplicate ID checks, range checks, and field validation via `CredentialValidator`. Corrupt, malformed, or duplicate entries cause immediate rejection with `VaultErrorCode::DeserializationError`.

---

## 5. Atomic and Safe File Persistence Architecture

Vault saving on Windows is designed to prevent data loss from system crashes, process termination, or concurrent reading:

1. **Unpredictable Temporary File**: A temporary file is created in the **same directory** as the target vault using 16 random hexadecimal characters (`<vault_name>.spm_<random_hex>.tmp`). This guarantees that both the temporary file and the target file reside on the same filesystem volume.
2. **Synchronous Disk Flush**: The complete encrypted vault (80-byte header + ciphertext) is written and flushed (`out.flush()`). On Windows, `FlushFileBuffers()` is executed on the file handle to guarantee physical write-through to disk media before replacement.
3. **Atomic Replacement**:
   - If the target vault already exists, `ReplaceFileW()` with `REPLACEFILE_WRITE_THROUGH` is called to atomically replace the existing file while preserving file metadata and preventing intermediate missing-file states.
   - If the target vault does not exist yet (initial vault creation) or if `ReplaceFileW` requests fallback, `MoveFileExW()` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` is executed.
4. **Failure Preservation**: If any step fails during serialization, encryption, disk writing, or atomic replacement, the temporary file is deleted, and the original existing vault file remains untouched on disk.
5. **Symbolic Link Policy**: Vault persistence strictly forbids writing to or following symbolic links / reparse points to mitigate directory traversal and link redirection vulnerabilities.

---

## 6. Resource Bounds and Protection Against Malicious Files

To ensure stability against hostile or corrupt vault files:
- **Maximum Vault File Size**: `16 MiB` (`MAX_VAULT_FILE_SIZE`). Files exceeding 16 MiB are rejected before reading into memory.
- **Maximum Payload Size**: `16 MiB` (`CryptoConstants::MAX_PAYLOAD_BYTES`).
- **Maximum Credential Count**: `100,000` entries.
- **Minimum Header Size**: `80 bytes`. Files smaller than 80 bytes are rejected immediately as `CorruptedVault`.
- **Exact Size Validation**: The file size on disk must equal `80 + ciphertext_length`. Truncated files or files with trailing unexpected data are rejected with `CorruptedVault`.
- **Ciphertext Tag Bound**: Ciphertext length must be at least 16 bytes (Poly1305 tag size).

---

## 7. Threat Model Considerations

1. **Tampering & Bit-Flipping**: Protected by Poly1305 MAC across ciphertext and the 48-byte AAD header. Modifying even 1 bit in ciphertext, nonce, salt, or parameters results in `VaultErrorCode::AuthenticationFailed`.
2. **Offline Brute-Force Attacks**: Mitigated by Argon2id's 64 MiB memory hardness, increasing the cost of specialized FPGA/ASIC hardware attacks.
3. **Nonce Reuse**: Mitigated by XChaCha20's 192-bit random nonce space, freshly generated via CSPRNG on every single save.
4. **Information Leakage**: Decryption and authentication failures return generic error messages (`VaultErrorCode::AuthenticationFailed`) so an adversary cannot differentiate between an incorrect master password and payload tampering. Diagnostic logs never output passwords, decrypted plaintext, or keys.
5. **Dangling Plaintext**: Unlocked vaults store decrypted credentials in memory only for the lifetime of the application process.

---

## 8. Remaining Limitations

- **Process Memory Snooping**: While sensitive payloads use `SecureBuffer` (guarded by guard pages and `sodium_memzero`), credentials held in `models::Credential` utilize standard `std::string` fields. An attacker with full administrative privileges or kernel-level debugging tools on the local machine could inspect process memory. Future batches will evaluate custom secure string wrappers for domain models.
- **Crash Durability of Filesystem Metadata**: While `FlushFileBuffers` and `REPLACEFILE_WRITE_THROUGH` force file contents and entries to disk, filesystem journal commits depend on host OS filesystem drivers (e.g. NTFS).
