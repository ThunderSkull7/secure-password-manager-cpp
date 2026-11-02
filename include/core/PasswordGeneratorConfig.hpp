#pragma once

#include <cstddef>

namespace password_manager::core {

struct PasswordGeneratorConfig {
    static constexpr std::size_t MIN_LENGTH = 8;
    static constexpr std::size_t MAX_LENGTH = 256;
    static constexpr std::size_t DEFAULT_LENGTH = 16;

    std::size_t length = DEFAULT_LENGTH;

    bool include_uppercase = true;
    bool include_lowercase = true;
    bool include_digits = true;
    bool include_symbols = true;

    bool exclude_ambiguous = false;
};

}  // namespace password_manager::core
