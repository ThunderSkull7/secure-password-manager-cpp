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
> **Note on Current Limitations:** Credentials currently reside strictly in memory. Disk persistence, authenticated vault encryption, and master-password authentication are scheduled for subsequent batches.

---

## 3. Technology Stack

| Component | Technology | Version / Specification |
|---|---|---|
| Language | C++ | C++20 (`/std:c++20`, extensions disabled) |
| Primary Compiler | Microsoft Visual C++ (MSVC) | VS 2022 (MSVC v143+ / 19.44+) |
| Build System | CMake | 3.20+ |
| Dependency Manager | vcpkg | Manifest Mode (`vcpkg.json`) |
| Cryptography | libsodium | 1.0.22 (used for randombytes and zeroization) |
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

### Generation Algorithm & Guarantees
1. **Entropy Source**: libsodium (`randombytes_uniform`) provides unbiased, bounded cryptographically secure random integers. Modulo reduction is strictly avoided.
2. **Category Representation Guarantee**: Exactly 1 character is randomly drawn from each enabled category pool, ensuring 100% representation.
3. **Pool Filling**: The remaining positions up to `length` are randomly drawn from the combined pool of all enabled categories.
4. **Fisher-Yates Shuffle**: The full character sequence is shuffled in-place using `randombytes_uniform` bounds, destroying any positional bias from the initial category draws.
5. **Memory Zeroing**: Intermediate character arrays are immediately wiped using `sodium_memzero` before returning.

---

## 6. Prerequisites

To build and run this project on Windows:

1. **Windows 10 / 11** (x64) with **Windows SDK** (10.0.26100.0 or compatible).
2. **Visual Studio 2022** or **Visual Studio Build Tools 2022** with the **Desktop development with C++** workload.
3. **CMake** 3.20 or newer (tested with CMake 4.4.4).
4. **Git** (tested with Git 2.54+).
5. **vcpkg** package manager. Ensure `VCPKG_ROOT` environment variable points to your vcpkg installation (e.g., `C:\vcpkg`).

---

## 7. Build Instructions (PowerShell)

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

## 8. Running Tests

### Method A: Using CTest Presets

```powershell
# Run Debug tests (47 unit tests)
ctest --preset debug-test

# Run Release tests (47 unit tests)
ctest --preset release-test
```

### Method B: Direct Test Executable Invocation

```powershell
.\build\debug\tests\Debug\password_manager_tests.exe
.\build\release\tests\Release\password_manager_tests.exe
```

---

## 9. Project Directory Structure

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
├── include/                    # Public headers
│   ├── models/                 # Domain and data models
│   │   └── Credential.hpp      # Credential model & CredentialInput structure
│   ├── core/                   # Core business logic and engine
│   │   ├── AppInfo.hpp         # Version and build configuration metadata
│   │   ├── CredentialValidator.hpp # Input normalization & validation rules
│   │   ├── PasswordGenerator.hpp   # Cryptographically secure password generator
│   │   ├── PasswordGeneratorConfig.hpp # Generator policy configuration
│   │   ├── Result.hpp          # Value-or-error functional return type
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
│   │   ├── PasswordGenerator.cpp   # libsodium random generator & Fisher-Yates
│   │   ├── Timestamp.cpp       # UTC ISO 8601 formatting implementation
│   │   └── Vault.cpp           # Vault in-memory CRUD, search, duplicate detection
│   └── ui/                     # UI implementations
│       └── Banner.cpp          # Banner stream rendering
│
├── tests/                      # Automated test suite (GoogleTest)
│   ├── CMakeLists.txt          # Test build configuration & CTest discovery
│   ├── AppInfoTest.cpp         # Metadata & build configuration tests
│   ├── BannerTest.cpp          # UI banner output verification test
│   ├── CredentialTests.cpp     # Credential model & update tests
│   ├── CredentialValidatorTests.cpp # Validation & boundary tests
│   ├── PasswordGeneratorTests.cpp  # Password generator category & security tests
│   ├── SmokeTest.cpp           # Basic framework sanity test
│   ├── TimestampTests.cpp      # ISO 8601 UTC format & clock tests
│   └── VaultTests.cpp          # Full Vault operations, search, duplicate tests
│
├── docs/                       # Architectural & design documentation
│
└── assets/                     # Application assets and resources
```

---

## 10. Security Considerations & In-Memory Limitations

- **No Encryption Yet:** This batch implements in-memory vault logic and the standalone password generator. Data is not yet encrypted or persisted to disk.
- **Memory Zeroization:** Intermediate buffers inside `PasswordGenerator` are cleared via `sodium_memzero`. However, returned `std::string` objects do not guarantee secure zeroing on destruction. Secure string wrappers will be introduced during subsequent security hardening batches.
- **No Password Exposure:** Stored and generated passwords are never logged, never printed automatically, and never searched.
- **Randomness Integrity:** Random generation exclusively relies on libsodium OS-level cryptographic entropy. Weak or predictable PRNGs (`rand()`, `mt19937`) are never used.

---

## 11. Planned Functionality (Upcoming Batches)

- **Batch 4: Cryptographic Engine**: Key derivation via Argon2id (`crypto_pwhash`), symmetric authenticated encryption via XChaCha20-Poly1305.
- **Batch 5: Vault Storage & Serialization**: Encrypted JSON persistence, atomic file writing, safe backups.
- **Batch 6: CLI & Interactive User Workflows**: Master password setup, unlock, record search, add, edit, and clipboard integration.

---

## 12. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
