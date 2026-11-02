#pragma once

#include <array>
#include <vector>

#include "core/CryptoParameters.hpp"

namespace password_manager::core {

struct EncryptedMessage {
    std::array<unsigned char, CryptoConstants::NONCE_BYTES> nonce{};
    std::vector<unsigned char> ciphertext;
};

}  // namespace password_manager::core
