#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

#include "core/Result.hpp"

namespace password_manager::core {

class SecureBuffer {
  public:
    SecureBuffer() noexcept = default;
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    [[nodiscard]] const unsigned char* data() const noexcept { return data_; }
    [[nodiscard]] unsigned char* data() noexcept { return data_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

    [[nodiscard]] std::span<const unsigned char> as_span() const noexcept { return {data_, size_}; }

    [[nodiscard]] std::span<unsigned char> as_writable_span() noexcept { return {data_, size_}; }

    [[nodiscard]] std::string to_string() const;

    static Result<SecureBuffer> allocate(std::size_t size);
    static Result<SecureBuffer> from_span(std::span<const unsigned char> bytes);
    static Result<SecureBuffer> from_string(std::string_view str);

  private:
    explicit SecureBuffer(unsigned char* data, std::size_t size) noexcept;

    unsigned char* data_{nullptr};
    std::size_t size_{0};
};

}  // namespace password_manager::core
