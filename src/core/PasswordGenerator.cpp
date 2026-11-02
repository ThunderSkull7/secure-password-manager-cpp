#include "core/PasswordGenerator.hpp"

#include <sodium.h>

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "core/SodiumInitializer.hpp"

namespace password_manager::core {

namespace {

bool is_ambiguous(char ch) noexcept {
    return PasswordGenerator::AMBIGUOUS_CHARS.find(ch) != std::string_view::npos;
}

std::string filter_category(std::string_view source, bool exclude_ambiguous) {
    std::string filtered;
    filtered.reserve(source.size());
    for (const char ch : source) {
        if (!exclude_ambiguous || !is_ambiguous(ch)) {
            filtered.push_back(ch);
        }
    }
    return filtered;
}

}  // namespace

Result<void> PasswordGenerator::validate_config(const PasswordGeneratorConfig& config) {
    if (config.length < PasswordGeneratorConfig::MIN_LENGTH) {
        return Result<void>::failure(VaultErrorCode::InvalidConfiguration,
                                     "Password length cannot be less than " +
                                         std::to_string(PasswordGeneratorConfig::MIN_LENGTH) +
                                         " characters.");
    }

    if (config.length > PasswordGeneratorConfig::MAX_LENGTH) {
        return Result<void>::failure(VaultErrorCode::InvalidConfiguration,
                                     "Password length cannot exceed " +
                                         std::to_string(PasswordGeneratorConfig::MAX_LENGTH) +
                                         " characters.");
    }

    const std::size_t enabled_count =
        (config.include_uppercase ? 1 : 0) + (config.include_lowercase ? 1 : 0) +
        (config.include_digits ? 1 : 0) + (config.include_symbols ? 1 : 0);

    if (enabled_count == 0) {
        return Result<void>::failure(VaultErrorCode::InvalidConfiguration,
                                     "At least one character category must be enabled.");
    }

    if (config.length < enabled_count) {
        return Result<void>::failure(
            VaultErrorCode::InvalidConfiguration,
            "Password length is insufficient to guarantee character representation for all "
            "enabled categories.");
    }

    return Result<void>::success();
}

Result<std::string> PasswordGenerator::generate(const PasswordGeneratorConfig& config) const {
    const auto init_res = SodiumInitializer::initialize();
    if (!init_res.has_value()) {
        return Result<std::string>::failure(init_res.error().code, init_res.error().message);
    }

    const auto validation = validate_config(config);
    if (!validation.has_value()) {
        return Result<std::string>::failure(validation.error().code, validation.error().message);
    }

    std::vector<std::string> active_categories;
    std::string combined_pool;

    auto add_category = [&](std::string_view base_set) -> bool {
        std::string pool = filter_category(base_set, config.exclude_ambiguous);
        if (pool.empty()) {
            return false;
        }
        combined_pool.append(pool);
        active_categories.push_back(std::move(pool));
        return true;
    };

    if (config.include_uppercase && !add_category(UPPERCASE_CHARS)) {
        return Result<std::string>::failure(
            VaultErrorCode::InvalidConfiguration,
            "Uppercase category has no available characters after exclusions.");
    }
    if (config.include_lowercase && !add_category(LOWERCASE_CHARS)) {
        return Result<std::string>::failure(
            VaultErrorCode::InvalidConfiguration,
            "Lowercase category has no available characters after exclusions.");
    }
    if (config.include_digits && !add_category(DIGIT_CHARS)) {
        return Result<std::string>::failure(
            VaultErrorCode::InvalidConfiguration,
            "Digits category has no available characters after exclusions.");
    }
    if (config.include_symbols && !add_category(SYMBOL_CHARS)) {
        return Result<std::string>::failure(
            VaultErrorCode::InvalidConfiguration,
            "Symbols category has no available characters after exclusions.");
    }

    // Temporary storage for generated characters
    std::vector<char> password_chars;
    password_chars.reserve(config.length);

    // 1. Guaranteed representation: Select exactly 1 random character from each enabled category
    for (const auto& category_pool : active_categories) {
        const auto bound = static_cast<uint32_t>(category_pool.size());
        const uint32_t random_index = randombytes_uniform(bound);
        password_chars.push_back(category_pool[random_index]);
    }

    // 2. Fill remaining positions from combined pool
    const auto combined_bound = static_cast<uint32_t>(combined_pool.size());
    while (password_chars.size() < config.length) {
        const uint32_t random_index = randombytes_uniform(combined_bound);
        password_chars.push_back(combined_pool[random_index]);
    }

    // 3. Fisher-Yates unbiased shuffle
    for (std::size_t i = password_chars.size() - 1; i > 0; --i) {
        const auto bound = static_cast<uint32_t>(i + 1);
        const uint32_t j = randombytes_uniform(bound);
        std::swap(password_chars[i], password_chars[j]);
    }

    // 4. Copy to return string and securely wipe sensitive intermediate buffer
    std::string result(password_chars.data(), password_chars.size());
    sodium_memzero(password_chars.data(), password_chars.size() * sizeof(char));

    return Result<std::string>(std::move(result));
}

}  // namespace password_manager::core
