#pragma once

#include <string>

namespace password_manager::core {

enum class VaultErrorCode {
    NotFound,
    ValidationError,
    IdExhaustion,
    InitializationError,
    InvalidConfiguration,
    InvalidKey,
    InvalidSalt,
    InvalidKdfParameters,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    AuthenticationFailed,
    InvalidNonce,
    InvalidCiphertext,
    PayloadTooLarge,
    AllocationFailed
};

struct VaultError {
    VaultErrorCode code;
    std::string message;

    [[nodiscard]] bool operator==(const VaultError& other) const noexcept {
        return code == other.code && message == other.message;
    }
};

}  // namespace password_manager::core
