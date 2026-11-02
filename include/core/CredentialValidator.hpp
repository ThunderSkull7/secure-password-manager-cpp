#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include "models/Credential.hpp"

namespace password_manager::core {

struct ValidationResult {
    bool is_valid{false};
    std::string error_message;
    models::CredentialInput normalized_input;
};

class CredentialValidator {
  public:
    static constexpr std::size_t MAX_SERVICE_LENGTH = 256;
    static constexpr std::size_t MAX_USERNAME_LENGTH = 256;
    static constexpr std::size_t MAX_PASSWORD_LENGTH = 4096;
    static constexpr std::size_t MAX_URL_LENGTH = 2048;
    static constexpr std::size_t MAX_CATEGORY_LENGTH = 128;
    static constexpr std::size_t MAX_NOTES_LENGTH = 65536;

    [[nodiscard]] static ValidationResult validate(const models::CredentialInput& input);
    [[nodiscard]] static bool is_valid_url(std::string_view url);
    [[nodiscard]] static std::string trim(std::string_view str);
};

}  // namespace password_manager::core
