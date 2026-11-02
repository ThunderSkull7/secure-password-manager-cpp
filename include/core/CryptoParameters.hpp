#pragma once

#include <sodium.h>

#include <cstddef>
#include <cstdint>

namespace password_manager::core {

struct CryptoConstants {
    static constexpr std::size_t KEY_BYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
    static constexpr std::size_t NONCE_BYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    static constexpr std::size_t TAG_BYTES = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    static constexpr std::size_t SALT_BYTES = crypto_pwhash_SALTBYTES;
    static constexpr std::size_t MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;  // 16 MiB
};

struct KdfParameters {
    std::uint64_t ops_limit{crypto_pwhash_OPSLIMIT_INTERACTIVE};
    std::size_t memory_limit{crypto_pwhash_MEMLIMIT_INTERACTIVE};
    int algorithm{crypto_pwhash_ALG_ARGON2ID13};

    static KdfParameters interactive_default() noexcept {
        return {crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_ARGON2ID13};
    }

    [[nodiscard]] bool operator==(const KdfParameters& other) const noexcept {
        return ops_limit == other.ops_limit && memory_limit == other.memory_limit &&
               algorithm == other.algorithm;
    }
};

}  // namespace password_manager::core
