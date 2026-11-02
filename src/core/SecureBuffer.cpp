#include "core/SecureBuffer.hpp"

#include <sodium.h>

#include <algorithm>
#include <utility>

namespace password_manager::core {

SecureBuffer::SecureBuffer(unsigned char* data, std::size_t size) noexcept
    : data_(data), size_(size) {}

SecureBuffer::~SecureBuffer() {
    if (data_ != nullptr) {
        sodium_free(data_);
        data_ = nullptr;
    }
    size_ = 0;
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (data_ != nullptr) {
            sodium_free(data_);
        }
        data_ = other.data_;
        size_ = other.size_;

        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

std::string SecureBuffer::to_string() const {
    if (empty()) {
        return "";
    }
    return std::string(reinterpret_cast<const char*>(data_), size_);
}

Result<SecureBuffer> SecureBuffer::allocate(std::size_t size) {
    if (size == 0) {
        return Result<SecureBuffer>(SecureBuffer(nullptr, 0));
    }

    auto* ptr = static_cast<unsigned char*>(sodium_malloc(size));
    if (ptr == nullptr) {
        return Result<SecureBuffer>::failure(
            VaultErrorCode::AllocationFailed,
            "Failed to allocate secure memory buffer via sodium_malloc.");
    }

    sodium_memzero(ptr, size);
    return Result<SecureBuffer>(SecureBuffer(ptr, size));
}

Result<SecureBuffer> SecureBuffer::from_span(std::span<const unsigned char> bytes) {
    auto alloc_res = allocate(bytes.size());
    if (!alloc_res.has_value()) {
        return alloc_res;
    }

    if (!bytes.empty()) {
        std::copy(bytes.begin(), bytes.end(), alloc_res.value().data());
    }

    return alloc_res;
}

Result<SecureBuffer> SecureBuffer::from_string(std::string_view str) {
    const auto* ustr = reinterpret_cast<const unsigned char*>(str.data());
    return from_span(std::span<const unsigned char>(ustr, str.size()));
}

}  // namespace password_manager::core
