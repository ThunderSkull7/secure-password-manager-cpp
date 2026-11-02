# Secure Password Manager

A modern, security-conscious C++20 local password manager vault application designed for robust offline credential management.

---

## 1. Project Description

Secure Password Manager is designed to provide secure, authenticated, and encrypted local storage for credentials, secrets, and sensitive notes. All cryptographic operations will run locally on the client machine using industry-standard primitives (libsodium), without third-party cloud dependencies or unencrypted persistence.

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
> - **Note on Current Limitations:** Credentials currently reside strictly in memory. Disk persistence, encryption, password generation, and master-password authentication are scheduled for subsequent batches.

---

## 3. Technology Stack

| Component | Technology | Version / Specification |
|---|---|---|
| Language | C++ | C++20 (`/std:c++20`, extensions disabled) |
| Primary Compiler | Microsoft Visual C++ (MSVC) | VS 2022 (MSVC v143+ / 19.44+) |
| Build System | CMake | 3.20+ |
| Dependency Manager | vcpkg | Manifest Mode (`vcpkg.json`) |
| Cryptography | libsodium | 1.0.22 (staged in manifest) |
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

## 5. Prerequisites

To build and run this project on Windows:

1. **Windows 10 / 11** (x64) with **Windows SDK** (10.0.26100.0 or compatible).
2. **Visual Studio 2022** or **Visual Studio Build Tools 2022** with the **Desktop development with C++** workload.
3. **CMake** 3.20 or newer (tested with CMake 4.4.4).
4. **Git** (tested with Git 2.54+).
5. **vcpkg** package manager. Ensure `VCPKG_ROOT` environment variable points to your vcpkg installation (e.g., `C:\vcpkg`).

---

## 6. Build Instructions (PowerShell)

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

## 7. Running Tests

### Method A: Using CTest Presets

```powershell
# Run Debug tests (33 unit tests)
ctest --preset debug-test

# Run Release tests (33 unit tests)
ctest --preset release-test
```

### Method B: Direct Test Executable Invocation

```powershell
.\build\debug\tests\Debug\password_manager_tests.exe
.\build\release\tests\Release\password_manager_tests.exe
```

---

## 8. Project Directory Structure

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
│   ├── SmokeTest.cpp           # Basic framework sanity test
│   ├── TimestampTests.cpp      # ISO 8601 UTC format & clock tests
│   └── VaultTests.cpp          # Full Vault operations, search, duplicate tests
│
├── docs/                       # Architectural & design documentation
│
└── assets/                     # Application assets and resources
```

---

## 9. Security Considerations & In-Memory Limitations

- **No Encryption Yet:** This batch establishes the in-memory domain model. Data is stored in memory as plaintext strings.
- **Memory Zeroization:** Standard `std::string` does not guarantee secure zeroing on destruction. Secure memory wiping primitives (`sodium_memzero`) and guarded memory allocations will be implemented in future security hardening batches.
- **No Password Exposure:** Stored passwords are never searched by `search_credentials`, never logged, and never formatted in diagnostic messages.
- **Atomic Operations:** Validation failures leave stored credentials completely untouched.

---

## 10. Planned Functionality (Upcoming Batches)

- **Batch 3: Cryptographic Engine**: Key derivation via Argon2id (`crypto_pwhash`), symmetric authenticated encryption via XChaCha20-Poly1305.
- **Batch 4: Vault Storage & Serialization**: Encrypted JSON persistence, atomic file writing, safe backups.
- **Batch 5: CLI & Interactive User Workflows**: Master password setup, unlock, record search, add, edit, and clipboard integration.

---

## 11. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
