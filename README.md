# Secure Password Manager

A modern, security-conscious C++20 local password manager vault application designed for robust offline credential management.

---

## 1. Project Description

Secure Password Manager provides secure, authenticated, and encrypted local storage for credentials, secrets, and sensitive notes. All cryptographic operations run locally on the client machine using industry-standard primitives (libsodium), without third-party cloud dependencies or unencrypted persistence.

---

## 2. Current Implementation Status

> **Batch 1: Project Foundation Complete**
> - Build system and directory architecture established with modern CMake 3.20+ and MSVC multi-config presets.
> - Dependency manifest management via `vcpkg` (`libsodium`, `nlohmann-json`, `gtest`).
> - Automated test infrastructure configured with GoogleTest and CTest.
> - Minimal CLI startup banner and build configuration reporting.
>
> **Batch 2: Credential Model & Core Vault Complete**
> - In-memory `Credential` model with immutable IDs and creation timestamps.
> - Monotonically increasing unique ID generation (never reused; integer overflow protected).
> - Dedicated `CredentialValidator` with strict field limits and URL syntax verification.
> - Core `Vault` operations: Add, Retrieve, Update (atomic), Delete, List (deterministic ID order).
> - Substring case-insensitive multi-field search (passwords are strictly excluded).
> - Case-insensitive duplicate detection warning system (supports multiple accounts per service).
> - Testable UTC ISO 8601 timestamp generator (`Timestamp` with pluggable `IClock`).
>
> **Batch 3: Cryptographically Secure Password Generator Complete**
> - Standalone `PasswordGenerator` powered by libsodium (`randombytes_uniform`).
> - Unbiased bounded random selection (no modulo reduction, no pseudo-random engines).
> - Fisher-Yates unbiased shuffle algorithm using libsodium randomness.
> - Guaranteed category representation (at least one character from each enabled category).
> - Configurable character categories (Uppercase, Lowercase, Digits, Symbols).
> - Optional ambiguous characters exclusion (`I`, `O`, `l`, `0`, `1`).
> - Validation rules enforcing lengths between 8 and 256 characters.
> - Secure temporary memory clearing via `sodium_memzero`.
>
> **Batch 4: Cryptographic Security Layer Complete**
> - Centralized, thread-safe libsodium initialization via `SodiumInitializer`.
> - 256-bit key derivation from master password using Argon2id v1.3 (`crypto_pwhash_ALG_ARGON2ID13`).
> - 16-byte cryptographically secure random salt generation (`randombytes_buf`).
> - Authenticated encryption and decryption using XChaCha20-Poly1305-IETF.
> - Fresh 24-byte random nonce generation per encryption operation.
> - Additional Authenticated Data (AAD) integrity binding.
> - Move-only RAII `SecureKey` with zeroization upon destruction (`sodium_memzero`).
> - Move-only guard-page protected `SecureBuffer` with `sodium_malloc` and `sodium_free`.
>
> **Batch 5: Versioned Encrypted Vault Format & Atomic Persistence Complete**
> - Versioned binary vault format (`SPMV`) with explicit little-endian multi-byte integers.
> - 80-byte binary header with 48-byte Additional Authenticated Data (AAD) binding.
> - Pre-derivation KDF resource validation guarding against memory and CPU DoS attacks.
> - Sensitive JSON serialization and deserialization within `SecureBuffer`.
> - Robust atomic file persistence on Windows (`ReplaceFileW`, `MoveFileExW`, `FlushFileBuffers`).
> - Tamper resistance and corruption detection (truncated files, bit-flips, trailing bytes rejected).
> - Comprehensive test suite (108 total tests passing in Debug and Release).

---

## 3. Technology Stack

| Component | Technology | Version / Specification |
|---|---|---|
| Language | C++ | C++20 (`/std:c++20`, extensions disabled) |
| Primary Compiler | Microsoft Visual C++ (MSVC) | VS 2022 (MSVC v143+ / 19.44+) |
| Build System | CMake | 3.20+ |
| Dependency Manager | vcpkg | Manifest Mode (`vcpkg.json`) |
| Cryptography | libsodium | 1.0.22 (Argon2id, XChaCha20-Poly1305, CSPRNG, guarded memory) |
| Serialization | nlohmann/json | 3.12.0 (Structured serialization inside `SecureBuffer`) |
| Testing Framework | GoogleTest | 1.18.0 (discovered via CTest) |
| Formatting | clang-format | LLVM / Google Style |

---

## 4. Credential Model & In-Memory Vault

### Credential Fields
| Field | Type | Description | Constraints |
|---|---|---|---|
| `id` | `uint64_t` | Vault-local identifier | Assigned monotonically starting at 1; immutable |
| `service` | `string` | Service or application | Required; trimmed; max 256 chars |
| `username` | `string` | Username or email | Optional; trimmed; max 256 chars |
| `password` | `string` | Credential secret | Required; never trimmed or altered; max 4096 chars |
| `url` | `string` | Optional service URL | Optional; validated for valid scheme/host syntax; max 2048 chars |
| `category` | `string` | Organizing folder/tag | Optional; trimmed; max 128 chars |
| `notes` | `string` | Additional remarks | Optional; max 65536 chars (64 KB) |
| `created_at` | `string` | Creation timestamp | UTC ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`); immutable |
| `updated_at` | `string` | Last modified timestamp | UTC ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`); updated on edit |

---

## 5. Binary Vault Format (`SPMV`) & Storage Architecture

Vault persistence is managed by `VaultStorage`, `VaultSerializer`, and `VaultFileFormat`:

```text
+-----------------------+---------+--------------------+---------------------------------------------+
| Offset (Bytes)        | Size    | Field Name         | Data Type / Value                           |
+-----------------------+---------+--------------------+---------------------------------------------+
| 00 - 03 (4 bytes)     | 4 B     | Magic Identifier   | ASCII "SPMV" (0x53, 0x50, 0x4D, 0x56)       |
| 04 - 07 (4 bytes)     | 4 B     | Format Version     | uint32_t LE (1)                             |
| 08 - 11 (4 bytes)     | 4 B     | Cipher Algorithm   | uint32_t LE (1 = XChaCha20-Poly1305-IETF)   |
| 12 - 15 (4 bytes)     | 4 B     | KDF Algorithm      | uint32_t LE (2 = Argon2id v1.3)             |
| 16 - 23 (8 bytes)     | 8 B     | KDF Ops Limit      | uint64_t LE (2 for interactive default)     |
| 24 - 31 (8 bytes)     | 8 B     | KDF Memory Limit   | uint64_t LE (67108864 for 64 MiB default)   |
| 32 - 47 (16 bytes)    | 16 B    | KDF Random Salt    | uint8_t[16] (libsodium CSPRNG salt)         |
+-----------------------+---------+--------------------+---------------------------------------------+  <-- AAD (48 B)
| 48 - 71 (24 bytes)    | 24 B    | AEAD Nonce         | uint8_t[24] (XChaCha20 random 192-bit nonce)|
| 72 - 79 (8 bytes)     | 8 B     | Ciphertext Length  | uint64_t LE (Length of ciphertext + tag)    |
+-----------------------+---------+--------------------+---------------------------------------------+  <-- Header (80 B)
| 80 - EOF              | N bytes | Encrypted Payload  | Encrypted JSON credentials + 16B Poly1305   |
+-----------------------+---------+--------------------+---------------------------------------------+
```

### Key Storage Features
1. **Authenticated Metadata**: The 48-byte cryptographic configuration header is mathematically authenticated as Additional Authenticated Data (AAD) in the XChaCha20-Poly1305 AEAD tag. Modifying any header parameter immediately breaks decryption.
2. **Resource Boundaries & Pre-validation**:
   - Vault files capped at 16 MiB.
   - Argon2id ops limit bounded between 1 and 10 iterations.
   - Argon2id memory limit bounded between 8 KiB and 512 MiB.
   - All parameters checked *before* executing expensive key derivation.
3. **Atomic File Persistence**:
   - Saves write to an unpredictable temporary file (`<target>.spm_<random_hex>.tmp`) in the same directory.
   - Explicit disk sync via `FlushFileBuffers()`.
   - Atomic swap using `ReplaceFileW()` with `REPLACEFILE_WRITE_THROUGH` (or `MoveFileExW()`).
   - If writing fails at any point, the temporary file is deleted, and the previous valid vault is preserved intact.

---

## 6. Build and Test Instructions

### Prerequisites
- Visual Studio 2022 (MSVC v143+ with C++20 and CMake tools installed)
- CMake 3.20+
- Git

### Presets
Configuration, compilation, and testing utilize standardized CMake presets:

```powershell
# Configure
cmake --preset debug
cmake --preset release

# Build
cmake --build --preset debug
cmake --build --preset release

# Test (GoogleTest via CTest)
ctest --preset debug-test
ctest --preset release-test
```

---

## 7. Project Directory Structure

```text
Password Manager/
│
├── CMakeLists.txt              # Root build configuration
├── CMakePresets.json           # Standardized configure/build/test presets
├── vcpkg.json                  # Dependency manifest (libsodium, json, gtest)
├── .gitignore                  # Git exclusion rules for artifacts and vault data
├── .clang-format               # C++ code formatting specification
├── README.md                   # Project documentation and developer guide
├── LICENSE                     # MIT License
│
├── docs/                       # Architectural & design documentation
│   └── SECURITY.md             # Cryptographic architecture, format spec & threat model
│
├── include/                    # Public headers
│   ├── models/                 # Domain and data models
│   │   └── Credential.hpp      # Credential model & CredentialInput structure
│   ├── core/                   # Core business logic and engine
│   │   ├── AppInfo.hpp         # Version and build configuration metadata
│   │   ├── CredentialValidator.hpp # Input normalization & validation rules
│   │   ├── CryptoParameters.hpp    # Cryptographic constants & KDF parameter structures
│   │   ├── CryptoService.hpp       # Argon2id KDF and XChaCha20-Poly1305 service
│   │   ├── EncryptedMessage.hpp    # Encrypted payload structure (nonce + ciphertext)
│   │   ├── PasswordGenerator.hpp   # Cryptographically secure password generator
│   │   ├── PasswordGeneratorConfig.hpp # Generator policy configuration
│   │   ├── Result.hpp          # Value-or-error functional return type
│   │   ├── SecureBuffer.hpp    # Guard-page protected plaintext memory buffer
│   │   ├── SecureKey.hpp       # Move-only zeroized 256-bit encryption key
│   │   ├── SodiumInitializer.hpp   # Centralized, thread-safe libsodium initialization
│   │   ├── Timestamp.hpp       # Testable UTC ISO 8601 timestamp generator
│   │   ├── Vault.hpp           # In-memory Vault management class
│   │   ├── VaultError.hpp      # Strongly typed vault error representations
│   │   ├── VaultFileFormat.hpp # Binary vault header layout, AAD, and endianness
│   │   ├── VaultSerializer.hpp # Sensitive JSON payload serialization
│   │   └── VaultStorage.hpp    # Atomic vault save, load, and inspection API
│   └── ui/                     # Presentation layer headers
│       └── Banner.hpp          # Startup banner interface
│
├── src/                        # Implementation files
│   ├── main.cpp                # CLI entry point
│   ├── models/                 # Model implementations
│   │   └── Credential.cpp      # Credential constructor & update logic
│   ├── core/                   # Core engine implementations
│   │   ├── CredentialValidator.cpp # Syntax & boundary validators
│   │   ├── CryptoService.cpp       # Argon2id derivation & authenticated encryption
│   │   ├── PasswordGenerator.cpp   # libsodium random generator & Fisher-Yates
│   │   ├── SecureBuffer.cpp        # sodium_malloc / sodium_free buffer implementation
│   │   ├── SecureKey.cpp           # Key zeroization and move semantics
│   │   ├── SodiumInitializer.cpp   # Thread-safe sodium_init wrapper
│   │   ├── Timestamp.cpp           # UTC ISO 8601 formatting implementation
│   │   ├── Vault.cpp               # Vault in-memory CRUD, search, duplicate detection
│   │   ├── VaultSerializer.cpp     # JSON credential serialization in SecureBuffer
│   │   └── VaultStorage.cpp        # Atomic persistence & Win32 ReplaceFile implementation
│   └── ui/                     # UI implementations
│       └── Banner.cpp              # Banner stream rendering
│
├── tests/                      # Automated test suite (GoogleTest)
│   ├── CMakeLists.txt          # Test build configuration & CTest discovery
│   ├── AppInfoTest.cpp         # Metadata & build configuration tests
│   ├── BannerTest.cpp          # UI banner output verification test
│   ├── CredentialTests.cpp     # Credential model & update tests
│   ├── CredentialValidatorTests.cpp # Validation & boundary tests
│   ├── CryptoServiceTests.cpp  # KDF, encryption, decryption, and AAD tests
│   ├── PasswordGeneratorTests.cpp  # Password generator category & security tests
│   ├── SecureBufferTests.cpp   # Guarded memory allocation & move tests
│   ├── SecureKeyTests.cpp      # Key move-only semantics & zeroization tests
│   ├── SmokeTest.cpp           # Basic framework sanity test
│   ├── TimestampTests.cpp      # ISO 8601 UTC format & clock tests
│   ├── VaultStorageTests.cpp   # Binary format, serialization, and atomic persistence tests
│   └── VaultTests.cpp          # Full Vault operations, search, duplicate tests
│
└── assets/                     # Application assets and resources
```

---

## 8. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
