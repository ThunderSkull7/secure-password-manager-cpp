# Secure Password Manager

A modern, security-conscious C++20 local password manager vault application designed for robust offline credential management.

---

## 1. Project Description

Secure Password Manager is designed to provide secure, authenticated, and encrypted local storage for credentials, secrets, and sensitive notes. All cryptographic operations will run locally on the client machine using industry-standard primitives (libsodium), without third-party cloud dependencies or unencrypted persistence.

---

## 2. Current Implementation Status

> **Batch 1: Project Foundation Complete**
> - Build system and directory architecture established.
> - Modern CMake 3.20+ with MSVC multi-config presets and C++20 standard enforcement.
> - Dependency manifest management via `vcpkg`.
> - Automated test infrastructure configured with GoogleTest and CTest.
> - Minimal CLI startup banner and build configuration reporting implemented.
> - **Note:** Vault storage, encryption, and credential management are intentionally not yet implemented in this foundation batch.

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

## 4. Prerequisites

To build and run this project on Windows:

1. **Windows 10 / 11** (x64) with **Windows SDK** (10.0.26100.0 or compatible).
2. **Visual Studio 2022** or **Visual Studio Build Tools 2022** with the **Desktop development with C++** workload.
3. **CMake** 3.20 or newer (tested with CMake 4.4.4).
4. **Git** (tested with Git 2.54+).
5. **vcpkg** package manager. Ensure `VCPKG_ROOT` environment variable points to your vcpkg installation (e.g., `C:\vcpkg`).

---

## 5. Dependency Installation & Resolution

Dependencies are declared in `vcpkg.json` (Manifest Mode):

- `libsodium`: Authenticated cryptography.
- `nlohmann-json`: JSON serialization for safe structured storage.
- `gtest` (feature: `tests`): GoogleTest framework for unit and integration testing.

CMake automatically integrates with vcpkg via `CMAKE_TOOLCHAIN_FILE`. When CMake configures the project, vcpkg resolves, builds, and links all required libraries without manual copying or vendoring.

To verify or set the `VCPKG_ROOT` environment variable in PowerShell:

```powershell
[System.Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\vcpkg", "User")
$env:VCPKG_ROOT = "C:\vcpkg"
```

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

### Method B: Direct CMake Commands

#### Debug:
```powershell
cmake -B build -S . -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Debug
.\build\Debug\password_manager.exe
```

#### Release:
```powershell
cmake -B build -S . -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release
.\build\Release\password_manager.exe
```

---

## 7. Running Tests

### Method A: Using CTest Presets

```powershell
# Run Debug tests
ctest --preset debug-test

# Run Release tests
ctest --preset release-test
```

### Method B: Direct CTest Invocation

```powershell
ctest --test-dir build\debug -C Debug --output-on-failure
ctest --test-dir build\release -C Release --output-on-failure
```

### Method C: Running the Test Executable Directly

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
│   ├── models/                 # Domain and data models (future batches)
│   ├── core/                   # Core business logic and metadata
│   │   └── AppInfo.hpp
│   └── ui/                     # Presentation layer headers
│       └── Banner.hpp
│
├── src/                        # Implementation files
│   ├── main.cpp                # CLI entry point
│   ├── models/                 # Model implementations (future batches)
│   ├── core/                   # Core engine implementations (future batches)
│   └── ui/                     # UI implementations
│       └── Banner.cpp
│
├── tests/                      # Automated test suite
│   ├── CMakeLists.txt          # Test build configuration
│   ├── SmokeTest.cpp           # Basic framework sanity test
│   ├── AppInfoTest.cpp         # Metadata & build configuration tests
│   └── BannerTest.cpp          # UI banner output verification test
│
├── docs/                       # Architectural & design documentation
│
└── assets/                     # Application assets and resources
```

---

## 9. Planned Functionality (Upcoming Batches)

- **Batch 2: Domain Modeling & Memory Security**: Secure string primitives, zeroing on destruction (`sodium_memzero`), credential models.
- **Batch 3: Cryptographic Engine**: Key derivation via Argon2id (`crypto_pwhash`), symmetric authenticated encryption via XChaCha20-Poly1305.
- **Batch 4: Vault Storage & Serialization**: Encrypted JSON persistence, atomic file writing, safe backups.
- **Batch 5: CLI & Interactive User Workflows**: Master password setup, unlock, record search, add, edit, and clipboard integration.

---

## 10. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
