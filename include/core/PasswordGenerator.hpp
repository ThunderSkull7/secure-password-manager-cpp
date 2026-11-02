#pragma once

#include <string>
#include <string_view>

#include "core/PasswordGeneratorConfig.hpp"
#include "core/Result.hpp"

namespace password_manager::core {

class PasswordGenerator {
  public:
    static constexpr std::string_view UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static constexpr std::string_view LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    static constexpr std::string_view DIGIT_CHARS = "0123456789";
    static constexpr std::string_view SYMBOL_CHARS = "!@#$%^&*()-_=+[]{};:,.?/";
    static constexpr std::string_view AMBIGUOUS_CHARS = "IOl01";

    PasswordGenerator() = default;

    /**
     * @brief Generates a cryptographically secure random password based on the supplied policy.
     * Uses libsodium's randombytes_uniform for unbiased bounded selection and Fisher-Yates shuffle.
     * @param config Generation options (length, categories, ambiguous character exclusions).
     * @return Result containing generated password string, or VaultError on invalid configuration /
     * failure.
     */
    [[nodiscard]] Result<std::string> generate(
        const PasswordGeneratorConfig& config = PasswordGeneratorConfig{}) const;

    /**
     * @brief Validates a password generation configuration without generating a password.
     * @param config The configuration to validate.
     * @return Result<void>::success() if valid, or a descriptive VaultError.
     */
    [[nodiscard]] static Result<void> validate_config(const PasswordGeneratorConfig& config);
};

}  // namespace password_manager::core
