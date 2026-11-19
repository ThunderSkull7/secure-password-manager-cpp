# Secure Password Manager

[![CI](https://github.com/ThunderSkull7/secure-password-manager-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/ThunderSkull7/secure-password-manager-cpp/actions/workflows/ci.yml)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg?logo=c%2B%2B)
![CMake](https://img.shields.io/badge/CMake-3.20%2B-064F8C.svg?logo=cmake)
![Platform](https://img.shields.io/badge/Platform-Windows%20MSVC-0078D6.svg?logo=windows)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Tests](https://img.shields.io/badge/Tests-124%20passing-brightgreen.svg)

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
>
> **Batch 6: Interactive CLI Application Integration Complete**
> - First-time vault creation wizard with master password confirmation and strength guidance.
> - Terminal echo suppression (`ConsoleEchoGuard` RAII) for masked master password entry on Windows.
> - Interactive main menu with intuitive 10-option workflow navigation.
> - Full credential lifecycle management: Add, View All, Search, View Details, Edit, Delete.
> - Explicit password reveal protection with screen clearing.
> - Integrated password generator with configurable length and character categories.
> - In-session unsaved changes tracking, atomic save, and graceful session locking.
> - Complete test coverage (120 tests passing in Debug and Release).
>
> **Batch 7: Final Security Hardening, Testing, and Documentation Complete**
> - Comprehensive full source-level security audit across all layers.
> - Sensitive-data lifetime hardening with `ScopedStringScrubber` and `secure_zero_string` wiping temporary master passwords and generated credentials.
> - Defensive session guards on all CLI action handlers preventing operations in locked or uninitialized states.
> - Vault header state zeroing (`vault_header_`) on session lock and application exit.
> - Directory path rejection guarding against invalid vault file destinations.
> - Direct streaming for credential password reveals, eliminating temporary heap allocations.
> - 124 automated tests passing across 16 test suites in both Debug and Release.
> - Complete professional documentation: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and `docs/TESTING.md`.

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

## 4. User Guide: Interactive CLI Workflows

### 4.1 Running the Application
```powershell
# Run with default vault location ("vault.dat" in working directory)
.\build\release\Release\password_manager.exe

# Run with a custom vault file path
.\build\release\Release\password_manager.exe "D:\MySecureFiles\personal.vault"
```

### 4.2 First-Time Setup & Vault Creation
If no vault exists at the specified path, the application automatically launches the vault initialization wizard:
1. Enter your desired master password. Console echo is suppressed for security.
2. Re-enter the password to confirm.
3. The application derives a 256-bit encryption key using Argon2id and atomically creates an encrypted, authenticated binary vault file.

### 4.3 Unlocking an Existing Vault
When opening an existing vault:
1. The application inspects and validates the binary header and KDF resource limits.
2. Enter your master password.
3. Upon successful key derivation and Poly1305 authentication verification, you are greeted with the main menu.
4. Up to 5 attempts are permitted before termination, with short throttling intervals to discourage brute-force attempts.

### 4.4 Main Menu Options
```text
----------------------------------------
        SECURE PASSWORD MANAGER         
Vault: personal.vault
----------------------------------------
 1. Add a credential
 2. View all credentials
 3. Search credentials
 4. View credential details
 5. Edit a credential
 6. Delete a credential
 7. Generate a password
 8. Save vault
 9. Lock vault
10. Exit
----------------------------------------
```

- **Option 1: Add a Credential**: Collects service, username, password, URL, category, and notes. Offers an instant option `[G]` to generate a strong random password. Performs non-blocking duplicate checks.
- **Option 2: View All Credentials**: Prints a clean summary table (ID, Service, Username, Category). Passwords are strictly omitted from this view.
- **Option 3: Search Credentials**: Case-insensitive partial search across service, username, URL, category, and notes. Passwords are never searched or displayed.
- **Option 4: View Credential Details**: Shows full details with the password masked as `••••••••••••`. Pressing `[R]` reveals the password, followed by an immediate prompt to clear the console.
- **Option 5: Edit a Credential**: Allows updating individual fields. Pressing Enter keeps the existing value.
- **Option 6: Delete a Credential**: Requires explicit `[y/N]` confirmation before removing a record.
- **Option 7: Generate a Password**: Standalone generator with configurable length (8–256) and character sets (uppercase, lowercase, digits, symbols, ambiguous character exclusion).
- **Option 8: Save Vault**: Persists all changes atomically to the encrypted file without re-running Argon2id.
- **Option 9: Lock Vault**: Checks for unsaved changes, wipes the derived session key from memory, and returns to the vault unlock screen.
- **Option 10: Exit**: Prompts to save any unsaved changes before terminating the application.

### 4.5 Vault Storage & Backup Advice
- Vault files are encrypted using XChaCha20-Poly1305 and protected by Argon2id key derivation.
- To back up your vault, simply copy your `.vault` or `vault.dat` file to your backup storage (e.g., an external drive).
- Never share your master password. Without the master password, an encrypted vault cannot be recovered.

### 4.6 Example Terminal Session (Illustrative Demo)

> [!NOTE]
> The following session demonstrates typical CLI interaction using synthetic dummy credentials.

```text
========================================
        NEW VAULT INITIALIZATION
========================================
No vault found at: vault.dat
Create a strong master password to secure your local vault.

Enter new master password: [hidden]
Confirm master password: [hidden]
[✓] Encrypted vault created and unlocked successfully.

----------------------------------------
        SECURE PASSWORD MANAGER
Vault: vault.dat
----------------------------------------
 1. Add a credential
 2. View all credentials
 3. Search credentials
 4. View credential details
 5. Edit a credential
 6. Delete a credential
 7. Generate a password
 8. Save vault
 9. Lock vault
10. Exit
----------------------------------------
Enter choice (1-10): 1

--- Add New Credential ---
Service / Website (required): GitHub
Username / Email (optional): alice@example.com
Credential Password:
[G] Generate strong password  |  [T] Type password manually: G
Generated Password: 7k#P9$mQ2!vL8@wZ
Use this password? [Y/n]: y
Website URL (optional): https://github.com
Category (optional): Developer
Notes (optional): Example work token
[✓] Credential added successfully (ID: 1).

----------------------------------------
        SECURE PASSWORD MANAGER
Vault: vault.dat  [UNSAVED CHANGES]
----------------------------------------
Enter choice (1-10): 2

--- All Vault Credentials ---
+------+------------------------+------------------------+------------------------+
| ID   | Service                | Username               | Category               |
+------+------------------------+------------------------+------------------------+
| 1    | GitHub                 | alice@example.com      | Developer              |
+------+------------------------+------------------------+------------------------+
Total: 1 credential(s).
```

---

## 5. Build and Test Instructions

### Prerequisites
- Visual Studio 2022 (MSVC v143+ with C++20 and CMake tools installed)
- CMake 3.20+
- Git

### Build & Test Commands
```powershell
# Configure presets (MSVC C++20 via vcpkg manifest)
cmake --preset windows-msvc-debug
cmake --preset windows-msvc-release

# Build executable and libraries
cmake --build --preset debug
cmake --build --preset release

# Run automated test suites (124 tests across 16 GoogleTest suites)
ctest --preset debug-test --output-on-failure
ctest --preset release-test --output-on-failure
```

---

## 6. Project Directory Structure

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
│   ├── ARCHITECTURE.md         # Layered design & sequence diagrams
│   ├── SECURITY.md             # Cryptographic architecture, format spec & threat model
│   ├── BACKUP_AND_RECOVERY.md  # Manual encrypted vault backup and restore guidance
│   └── TESTING.md              # Test execution & suite breakdown
│
├── include/                    # Public headers
│   ├── cli/                    # Presentation and application orchestration
│   │   ├── Console.hpp         # Console I/O, echo suppression guard (Win32 RAII)
│   │   └── PasswordManagerApp.hpp # Interactive CLI workflow controller
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
│   ├── cli/                    # CLI implementations
│   │   ├── Console.cpp         # Terminal masking and input reader
│   │   └── PasswordManagerApp.cpp # Menu navigation and workflow execution
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
│   ├── CliAppTests.cpp         # End-to-end CLI workflows & interactive simulation tests
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

## 7. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
