# Secure Password Manager

A modern, security-conscious C++20 local password manager vault application designed for robust offline credential management.

---

## 1. Project Description

Secure Password Manager is designed to provide secure, authenticated, and encrypted local storage for credentials, secrets, and sensitive notes. All cryptographic operations run locally on the client machine using industry-standard primitives (libsodium), without third-party cloud dependencies or unencrypted persistence.

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
> - Comprehensive automated security testing (80 total tests across Debug and Release).
>
> **Note on Current Limitations:** This batch establishes the cryptographic engine. Complete encrypted file-based vault persistence and interactive CLI workflows are scheduled for subsequent batches.

---

## 3. Technology Stack

| Component | Technology | Version / Specification |
|---|---|---|
| Language | C++ | C++20 (`/std:c++20`, extensions disabled) |
| Primary Compiler | Microsoft Visual C++ (MSVC) | VS 2022 (MSVC v143+ / 19.44+) |
| Build System | CMake | 3.20+ |
| Dependency Manager | vcpkg | Manifest Mode (`vcpkg.json`) |
| Cryptography | libsodium | 1.0.22 (Argon2id, XChaCha20-Poly1305, CSPRNG, guarded memory) |
| Serialization | nlohmann/json | 3.12.0 (staged in manifest) |
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

### Vault Operations
- **Add**: Validates input, assigns next monotonic ID, sets timestamps, stores record.
- **Retrieve**: Retrieves credential by ID; returns `NotFound` if non-existent.
- **Update**: Atomically validates and updates record fields; preserves ID and creation timestamp.
- **Delete**: Removes credential by ID; ID is never reused for future entries.
- **List**: Returns all credentials sorted deterministically by ID.
- **Search**: Case-insensitive substring search across service, username, URL, category, and notes. Password fields are strictly excluded from search queries. Empty query returns an empty collection.
- **Duplicate Detection**: Non-blocking warning detection comparing service and username case-insensitively.

---

## 5. Cryptographically Secure Password Generator

The `PasswordGenerator` component creates strong random passwords according to configurable policies:

### Character Categories
- **Uppercase**: `ABCDEFGHIJKLMNOPQRSTUVWXYZ` (26 characters)
- **Lowercase**: `abcdefghijklmnopqrstuvwxyz` (26 characters)
- **Digits**: `0123456789` (10 characters)
- **Symbols**: `!@#$%^&*()-_=+[]{};:,.?/` (24 characters)
- **Ambiguous Characters (Optional Exclusion)**: `I`, `O`, `l`, `0`, `1`

### Configuration Options (`PasswordGeneratorConfig`)
- `length`: Password length between 8 and 256 characters (default: 16).
- `include_uppercase`: Enable/disable uppercase characters (default: `true`).
- `include_lowercase`: Enable/disable lowercase characters (default: `true`).
- `include_digits`: Enable/disable numeric characters (default: `true`).
- `include_symbols`: Enable/disable punctuation/symbol characters (default: `true`).
- `exclude_ambiguous`: Filter out easily confused characters (default: `false`).

---

## 6. Cryptographic Security Layer

Detailed architecture and threat model are documented in [docs/SECURITY.md](docs/SECURITY.md).

### Cryptographic Standards
- **Key Derivation**: Argon2id v1.3 (`crypto_pwhash_ALG_ARGON2ID13`) with 16-byte random salt, deriving 256-bit encryption keys. Default interactive baseline: `ops_limit = 2`, `mem_limit = 64 MiB`.
- **Authenticated Encryption**: XChaCha20-Poly1305-IETF (`crypto_aead_xchacha20poly1305_ietf_*`) with fresh 24-byte (192-bit) random nonces generated per encryption.
- **Integrity Verification**: Poly1305 16-byte authentication tag verified prior to releasing any decrypted data.
- **Additional Authenticated Data (AAD)**: Plaintext metadata (version, salt, parameters) is authenticated alongside ciphertext.
- **Memory Protection**:
  - `SecureKey`: Move-only key container zeroed via `sodium_memzero` on destruction.
  - `SecureBuffer`: Move-only buffer allocated via `sodium_malloc` (with guard pages and canaries) and wiped via `sodium_free`.

---

## 7. Prerequisites

To build and run this project on Windows:

1. **Windows 10 / 11** (x64) with **Windows SDK** (10.0.26100.0 or compatible).
2. **Visual Studio 2022** or **Visual Studio Build Tools 2022** with the **Desktop development with C++** workload.
3. **CMake** 3.20 or newer (tested with CMake 4.4.4).
4. **Git** (tested with Git 2.54+).
5. **vcpkg** package manager. Ensure `VCPKG_ROOT` environment variable points to your vcpkg installation (e.g., `C:\vcpkg`).

---

## 8. Build Instructions (PowerShell)

### Method A: Using CMake Presets (Recommended)

#### Debug Build:
```powershell
# Configure Debug
cmake --preset windows-msvc-debug

# Build Debug
cmake --build --preset debug

# Run CLI
.\build\debug\Debug\password_manager.exe
```

#### Release Build:
```powershell
# Configure Release
cmake --preset windows-msvc-release

# Build Release
cmake --build --preset release

# Run CLI
.\build\release\Release\password_manager.exe
```

---

## 9. Running Tests

### Method A: Using CTest Presets

```powershell
# Run Debug tests (80 unit tests)
ctest --preset debug-test

# Run Release tests (80 unit tests)
ctest --preset release-test
```

### Method B: Direct Test Executable Invocation

```powershell
.\build\debug\tests\Debug\password_manager_tests.exe
.\build\release\tests\Release\password_manager_tests.exe
```

---

## 10. Project Directory Structure

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
│   └── SECURITY.md             # Cryptographic architecture and threat model
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
│   │   └── VaultError.hpp      # Strongly typed vault error representations
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
│   │   └── Vault.cpp               # Vault in-memory CRUD, search, duplicate detection
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
│   └── VaultTests.cpp          # Full Vault operations, search, duplicate tests
│
└── assets/                     # Application assets and resources
```

---

## 11. Security Considerations & In-Memory Limitations

- **No Encryption Yet:** This batch implements cryptographic primitives and in-memory vault logic. Complete encrypted file-based vault persistence will be introduced in Batch 5.
- **Memory Zeroization:** Sensitive keys (`SecureKey`) and decrypted payloads (`SecureBuffer`) use libsodium memory protection (`sodium_memzero`, `sodium_malloc`, `sodium_free`). Plaintext credentials inside the domain model (`std::string`) will be wrapped in protected storage in the vault persistence batch.
- **No Password Exposure:** Stored and generated passwords, master passwords, and secret keys are never logged, never printed automatically, and never searched.
- **Randomness Integrity:** Random generation exclusively relies on libsodium OS-level cryptographic entropy. Weak or predictable PRNGs (`rand()`, `mt19937`) are never used.

---

## 12. Planned Functionality (Upcoming Batches)

- **Batch 5: Vault Storage & Serialization**: Encrypted JSON persistence, atomic file writing, safe backups, authenticated vault file format.
- **Batch 6: CLI & Interactive User Workflows**: Master password setup, unlock, record search, add, edit, and clipboard integration.

---

## 13. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
