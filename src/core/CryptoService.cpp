#include "core/CryptoService.hpp"

#include <sodium.h>

#include <utility>

#include "core/SodiumInitializer.hpp"

namespace password_manager::core {

Result<std::array<unsigned char, CryptoConstants::SALT_BYTES>> CryptoService::generate_salt()
    const {
    const auto init_res = SodiumInitializer::initialize();
    if (!init_res.has_value()) {
        return Result<std::array<unsigned char, CryptoConstants::SALT_BYTES>>::failure(
            init_res.error().code, init_res.error().message);
    }

    std::array<unsigned char, CryptoConstants::SALT_BYTES> salt{};
    randombytes_buf(salt.data(), salt.size());
    return Result<std::array<unsigned char, CryptoConstants::SALT_BYTES>>(salt);
}

Result<void> CryptoService::validate_master_password(std::string_view master_password) {
    if (master_password.empty()) {
        return Result<void>::failure(VaultErrorCode::ValidationError,
                                     "Master password cannot be empty.");
    }
    return Result<void>::success();
}

Result<void> CryptoService::validate_salt(std::span<const unsigned char> salt) {
    if (salt.size() != CryptoConstants::SALT_BYTES) {
        return Result<void>::failure(VaultErrorCode::InvalidSalt,
                                     "Salt length must be exactly " +
                                         std::to_string(CryptoConstants::SALT_BYTES) + " bytes.");
    }
    return Result<void>::success();
}

Result<void> CryptoService::validate_kdf_parameters(const KdfParameters& params) {
    if (params.algorithm != crypto_pwhash_ALG_ARGON2ID13) {
        return Result<void>::failure(VaultErrorCode::InvalidKdfParameters,
                                     "Unsupported KDF algorithm. Argon2id v1.3 is required.");
    }

    if (params.ops_limit < crypto_pwhash_OPSLIMIT_MIN ||
        params.ops_limit > crypto_pwhash_OPSLIMIT_MAX) {
        return Result<void>::failure(VaultErrorCode::InvalidKdfParameters,
                                     "Argon2id ops limit is out of supported bounds.");
    }

    if (params.memory_limit < crypto_pwhash_MEMLIMIT_MIN ||
        params.memory_limit > crypto_pwhash_MEMLIMIT_MAX) {
        return Result<void>::failure(VaultErrorCode::InvalidKdfParameters,
                                     "Argon2id memory limit is out of supported bounds.");
    }

    return Result<void>::success();
}

Result<SecureKey> CryptoService::derive_key(std::string_view master_password,
                                            std::span<const unsigned char> salt,
                                            const KdfParameters& params) const {
    const auto init_res = SodiumInitializer::initialize();
    if (!init_res.has_value()) {
        return Result<SecureKey>::failure(init_res.error().code, init_res.error().message);
    }

    const auto pwd_val = validate_master_password(master_password);
    if (!pwd_val.has_value()) {
        return Result<SecureKey>::failure(pwd_val.error().code, pwd_val.error().message);
    }

    const auto salt_val = validate_salt(salt);
    if (!salt_val.has_value()) {
        return Result<SecureKey>::failure(salt_val.error().code, salt_val.error().message);
    }

    const auto kdf_val = validate_kdf_parameters(params);
    if (!kdf_val.has_value()) {
        return Result<SecureKey>::failure(kdf_val.error().code, kdf_val.error().message);
    }

    std::array<unsigned char, CryptoConstants::KEY_BYTES> raw_key{};
    const int ret = crypto_pwhash(raw_key.data(), raw_key.size(), master_password.data(),
                                  master_password.size(), salt.data(), params.ops_limit,
                                  params.memory_limit, params.algorithm);

    if (ret != 0) {
        sodium_memzero(raw_key.data(), raw_key.size());
        return Result<SecureKey>::failure(
            VaultErrorCode::KeyDerivationFailed,
            "Argon2id key derivation failed (insufficient resources or system error).");
    }

    SecureKey key(raw_key);
    sodium_memzero(raw_key.data(), raw_key.size());

    return Result<SecureKey>(std::move(key));
}

Result<EncryptedMessage> CryptoService::encrypt(
    const SecureKey& key, std::span<const unsigned char> plaintext,
    std::span<const unsigned char> additional_data) const {
    const auto init_res = SodiumInitializer::initialize();
    if (!init_res.has_value()) {
        return Result<EncryptedMessage>::failure(init_res.error().code, init_res.error().message);
    }

    if (!key.is_valid()) {
        return Result<EncryptedMessage>::failure(VaultErrorCode::InvalidKey,
                                                 "Encryption key is invalid or uninitialized.");
    }

    if (plaintext.size() > CryptoConstants::MAX_PAYLOAD_BYTES) {
        return Result<EncryptedMessage>::failure(
            VaultErrorCode::PayloadTooLarge,
            "Plaintext payload exceeds maximum permitted size of 16 MiB.");
    }

    std::array<unsigned char, CryptoConstants::NONCE_BYTES> nonce{};
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> ciphertext(plaintext.size() + CryptoConstants::TAG_BYTES);
    unsigned long long out_len = 0;

    const int ret = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &out_len, plaintext.data(), plaintext.size(), additional_data.data(),
        additional_data.size(), nullptr, nonce.data(), key.data());

    if (ret != 0) {
        sodium_memzero(ciphertext.data(), ciphertext.size());
        return Result<EncryptedMessage>::failure(VaultErrorCode::EncryptionFailed,
                                                 "XChaCha20-Poly1305 encryption failed.");
    }

    ciphertext.resize(static_cast<std::size_t>(out_len));
    return Result<EncryptedMessage>(EncryptedMessage{nonce, std::move(ciphertext)});
}

Result<SecureBuffer> CryptoService::decrypt(const SecureKey& key, const EncryptedMessage& encrypted,
                                            std::span<const unsigned char> additional_data) const {
    const auto init_res = SodiumInitializer::initialize();
    if (!init_res.has_value()) {
        return Result<SecureBuffer>::failure(init_res.error().code, init_res.error().message);
    }

    if (!key.is_valid()) {
        return Result<SecureBuffer>::failure(VaultErrorCode::InvalidKey,
                                             "Decryption key is invalid or uninitialized.");
    }

    if (encrypted.ciphertext.size() < CryptoConstants::TAG_BYTES) {
        return Result<SecureBuffer>::failure(
            VaultErrorCode::InvalidCiphertext,
            "Ciphertext is too short to contain Poly1305 authentication tag.");
    }

    const std::size_t plaintext_len = encrypted.ciphertext.size() - CryptoConstants::TAG_BYTES;
    if (plaintext_len > CryptoConstants::MAX_PAYLOAD_BYTES) {
        return Result<SecureBuffer>::failure(VaultErrorCode::PayloadTooLarge,
                                             "Decrypted payload exceeds maximum permitted size.");
    }

    auto alloc_res = SecureBuffer::allocate(plaintext_len);
    if (!alloc_res.has_value()) {
        return alloc_res;
    }

    auto buffer = std::move(alloc_res.value());
    unsigned long long decrypted_len = 0;

    const int ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
        buffer.data(), &decrypted_len, nullptr, encrypted.ciphertext.data(),
        encrypted.ciphertext.size(), additional_data.data(), additional_data.size(),
        encrypted.nonce.data(), key.data());

    if (ret != 0) {
        return Result<SecureBuffer>::failure(
            VaultErrorCode::AuthenticationFailed,
            "Decryption failed: authentication tag mismatch or corrupted ciphertext/AAD.");
    }

    return Result<SecureBuffer>(std::move(buffer));
}

}  // namespace password_manager::core
