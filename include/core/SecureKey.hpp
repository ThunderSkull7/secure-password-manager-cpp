#pragma once

#include <array>
#include <cstddef>
#include <span>

#include "core/CryptoParameters.hpp"

namespace password_manager::core {

class SecureKey {
  public:
    SecureKey() noexcept;
    explicit SecureKey(std::span<const unsigned char> key_bytes);

    ~SecureKey();

    SecureKey(const SecureKey&) = delete;
    SecureKey& operator=(const SecureKey&) = delete;

    SecureKey(SecureKey&& other) noexcept;
    SecureKey& operator=(SecureKey&& other) noexcept;

    [[nodiscard]] const unsigned char* data() const noexcept { return key_.data(); }
    [[nodiscard]] unsigned char* data() noexcept { return key_.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return CryptoConstants::KEY_BYTES; }
    [[nodiscard]] std::span<const unsigned char> as_span() const noexcept {
        return {key_.data(), CryptoConstants::KEY_BYTES};
    }
    [[nodiscard]] bool is_valid() const noexcept { return is_valid_; }

  private:
    std::array<unsigned char, CryptoConstants::KEY_BYTES> key_{};
    bool is_valid_{false};
};

}  // namespace password_manager::core
