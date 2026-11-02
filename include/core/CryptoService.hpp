#pragma once

#include <array>
#include <span>
#include <string_view>

#include "core/CryptoParameters.hpp"
#include "core/EncryptedMessage.hpp"
#include "core/Result.hpp"
#include "core/SecureBuffer.hpp"
#include "core/SecureKey.hpp"

namespace password_manager::core {

class CryptoService {
  public:
    CryptoService() = default;

    /**
     * @brief Generates a cryptographically secure random salt for key derivation.
     * @return 16-byte random salt.
     */
    [[nodiscard]] Result<std::array<unsigned char, CryptoConstants::SALT_BYTES>> generate_salt()
        const;

    /**
     * @brief Derives a 256-bit encryption key using Argon2id v1.3.
     * @param master_password The user master password.
     * @param salt A 16-byte cryptographically random salt.
     * @param params Argon2id KDF parameters (ops limit, memory limit, algorithm).
     * @return Derived SecureKey or error on invalid parameters / failure.
     */
    [[nodiscard]] Result<SecureKey> derive_key(
        std::string_view master_password, std::span<const unsigned char> salt,
        const KdfParameters& params = KdfParameters::interactive_default()) const;

    /**
     * @brief Encrypts plaintext using XChaCha20-Poly1305 with authenticated Additional Data (AAD).
     * Generates a fresh 24-byte random nonce for every operation.
     * @param key 256-bit SecureKey.
     * @param plaintext Input binary data up to 16 MiB.
     * @param additional_data Optional unencrypted authenticated data.
     * @return EncryptedMessage containing nonce and ciphertext (with authentication tag).
     */
    [[nodiscard]] Result<EncryptedMessage> encrypt(
        const SecureKey& key, std::span<const unsigned char> plaintext,
        std::span<const unsigned char> additional_data = {}) const;

    /**
     * @brief Authenticates and decrypts ciphertext using XChaCha20-Poly1305.
     * Verifies the Poly1305 authentication tag before returning any decrypted data.
     * @param key 256-bit SecureKey.
     * @param encrypted The EncryptedMessage containing nonce and ciphertext.
     * @param additional_data Additional Authenticated Data matching encryption.
     * @return Decrypted SecureBuffer, or AuthenticationFailed error if tampered.
     */
    [[nodiscard]] Result<SecureBuffer> decrypt(
        const SecureKey& key, const EncryptedMessage& encrypted,
        std::span<const unsigned char> additional_data = {}) const;

    // Validation helpers
    [[nodiscard]] static Result<void> validate_master_password(std::string_view master_password);
    [[nodiscard]] static Result<void> validate_salt(std::span<const unsigned char> salt);
    [[nodiscard]] static Result<void> validate_kdf_parameters(const KdfParameters& params);
};

}  // namespace password_manager::core
