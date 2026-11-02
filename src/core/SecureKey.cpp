#include "core/SecureKey.hpp"

#include <sodium.h>

#include <algorithm>

namespace password_manager::core {

SecureKey::SecureKey() noexcept : is_valid_(false) {
    key_.fill(0);
}

SecureKey::SecureKey(std::span<const unsigned char> key_bytes) : is_valid_(false) {
    if (key_bytes.size() == CryptoConstants::KEY_BYTES) {
        std::copy(key_bytes.begin(), key_bytes.end(), key_.begin());
        is_valid_ = true;
    } else {
        key_.fill(0);
    }
}

SecureKey::~SecureKey() {
    sodium_memzero(key_.data(), key_.size());
    is_valid_ = false;
}

SecureKey::SecureKey(SecureKey&& other) noexcept : key_(other.key_), is_valid_(other.is_valid_) {
    sodium_memzero(other.key_.data(), other.key_.size());
    other.is_valid_ = false;
}

SecureKey& SecureKey::operator=(SecureKey&& other) noexcept {
    if (this != &other) {
        sodium_memzero(key_.data(), key_.size());
        key_ = other.key_;
        is_valid_ = other.is_valid_;

        sodium_memzero(other.key_.data(), other.key_.size());
        other.is_valid_ = false;
    }
    return *this;
}

}  // namespace password_manager::core
