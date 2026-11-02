# Testing and Verification Guide

## 1. Testing Framework and Architecture

The Secure Password Manager test suite utilizes **GoogleTest** (v1.15.2) and **CMake CTest** to provide comprehensive unit, cryptographic, boundary, and end-to-end integration testing.

All test suites compile and execute identically in both **Debug** and **Release** configurations on MSVC C++20.

---

## 2. Test Suites Summary

The test suite contains **124 automated tests** across 12 distinct test suites:

| Suite Name | Source File | Test Count | Focus Area |
|---|---|---|---|
| **`SmokeTest`** | `SmokeTests.cpp` | 2 | Test harness initialization and basic assertions |
| **`AppInfoTest`** | `AppInfoTests.cpp` | 2 | Version metadata, application name, and build configuration constants |
| **`BannerTest`** | `BannerTests.cpp` | 1 | Welcome banner formatting and version output |
| **`CredentialModelTest`** | `CredentialTests.cpp` | 3 | Credential immutability, optional fields, and update mechanics |
| **`CredentialValidatorTest`**| `CredentialValidatorTests.cpp` | 6 | Field length bounds, empty field rejection, URL format validation |
| **`TimestampTest`** | `TimestampTests.cpp` | 3 | ISO-8601 UTC timestamp generation and formatting consistency |
| **`VaultTest`** | `VaultTests.cpp` | 15 | In-memory CRUD, ID sequencing, duplicate detection, and search filters |
| **`PasswordGeneratorTest`** | `PasswordGeneratorTests.cpp` | 14 | Entropy verification, character category guarantees, unbiased shuffle, and configuration validation |
| **`CryptoServiceTest`** | `CryptoTests.cpp` | 33 | Argon2id KDF, XChaCha20-Poly1305 AEAD, AAD authentication, memory zeroization, parameter DoS guards |
| **`VaultFileFormatTest`** | `VaultStorageTests.cpp` | 14 | 80-byte header format, magic number, version checks, endian safety, and corrupted file rejection |
| **`VaultStorageTest`** | `VaultStorageTests.cpp` | 17 | Atomic replacement, power-loss rollback, temporary file cleanup, directory rejection, and size bounds |
| **`ConsoleTest`** | `CliAppTests.cpp` | 2 | Windows console masking, carriage return normalization, confirmation handling |
| **`CliAppTest`** | `CliAppTests.cpp` | 12 | End-to-end interactive workflows: vault creation, unlock, retries, CRUD, generator, lock/re-unlock, scrubber zeroization, and EOF resilience |
| **Total** | | **124** | **100% Passing in Debug and Release** |

---

## 3. How to Build and Run Tests

### 3.1 Debug Configuration

```powershell
# Configure and build Debug preset
cmake --preset debug
cmake --build --preset debug

# Run all 124 tests via CTest
ctest --preset debug-test --output-on-failure
```

### 3.2 Release Configuration

```powershell
# Configure and build Release preset
cmake --preset release
cmake --build --preset release

# Run all 124 tests via CTest
ctest --preset release-test --output-on-failure
```

### 3.3 Running Specific Test Suites or Individual Tests

To run specific tests directly with detailed GoogleTest output, execute the test binary directly with a filter:

```powershell
# Run only Cryptographic tests
.\build\debug\tests\Debug\password_manager_tests.exe --gtest_filter=CryptoServiceTest.*

# Run only Vault Storage and File Format tests
.\build\debug\tests\Debug\password_manager_tests.exe --gtest_filter=VaultStorageTest.*:VaultFileFormatTest.*

# Run only CLI End-to-End Integration tests
.\build\debug\tests\Debug\password_manager_tests.exe --gtest_filter=CliAppTest.*

# Run a single individual test
.\build\debug\tests\Debug\password_manager_tests.exe --gtest_filter=CliAppTest.ScopedStringScrubberWipesMemory
```

---

## 4. Key Verification Scenarios

### 4.1 Cryptographic Integrity and Tamper Rejection
- **Bit-Flip Rejection**: Tests flip individual bits in ciphertext, nonce, salt, and AAD header bytes; all must be rejected with `VaultErrorCode::AuthenticationFailed`.
- **KDF DoS Limits**: Tests supply excessive memory limits (1 GB) and iteration counts (100) in vault headers; all are safely rejected before Argon2id allocation.
- **Nonce Freshness**: Tests assert that consecutive saves of identical vaults produce distinct 24-byte nonces and completely distinct ciphertexts.

### 4.2 Persistence and Crash Safety
- **Atomic Replacement**: Tests simulate existing vault overwrite using Win32 `ReplaceFileW`, verifying that an interrupted write leaves the original file unmodified.
- **Directory Path Defense**: Attempting to initialize or save a vault pointing to a directory path is rejected gracefully.
- **Resource Cleanup**: Tests verify that temporary `.spm_*.tmp` files are cleaned up following every save operation or failure.

### 4.3 Memory Security and Scrubber Verification
- **RAII Scrubber**: The test `ScopedStringScrubberWipesMemory` verifies that sensitive strings are overwritten with zero bytes (`sodium_memzero`) upon scope exit.
- **Guard Pages**: Tests verify `SecureBuffer` and `SecureKey` allocate protected memory pages via `sodium_malloc` and zero them upon disposal.
