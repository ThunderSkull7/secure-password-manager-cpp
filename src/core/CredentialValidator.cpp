#include "core/CredentialValidator.hpp"

#include <cctype>
#include <string_view>

namespace password_manager::core {

std::string CredentialValidator::trim(std::string_view str) {
    const auto first = str.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return "";
    }
    const auto last = str.find_last_not_of(" \t\r\n");
    return std::string(str.substr(first, (last - first + 1)));
}

bool CredentialValidator::is_valid_url(std::string_view url) {
    if (url.empty() || url.size() > MAX_URL_LENGTH) {
        return false;
    }

    // Must not contain whitespace
    for (const char ch : url) {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            return false;
        }
    }

    // Must contain scheme separator "://"
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos || scheme_end == 0) {
        return false;
    }

    // Scheme must start with a letter and contain only alphanumeric, '+', '-', or '.'
    if (!std::isalpha(static_cast<unsigned char>(url[0]))) {
        return false;
    }
    for (std::size_t i = 1; i < scheme_end; ++i) {
        const char ch = url[i];
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '+' && ch != '-' && ch != '.') {
            return false;
        }
    }

    // Host portion must be non-empty
    const auto host_start = scheme_end + 3;
    if (host_start >= url.size()) {
        return false;
    }

    const auto host_end = url.find_first_of("/?#", host_start);
    const auto host_length =
        (host_end == std::string_view::npos) ? (url.size() - host_start) : (host_end - host_start);

    return host_length > 0;
}

ValidationResult CredentialValidator::validate(const models::CredentialInput& input) {
    ValidationResult result;
    result.normalized_input = input;

    // 1. Service validation
    const std::string trimmed_service = trim(input.service);
    if (trimmed_service.empty()) {
        result.is_valid = false;
        result.error_message = "Service name cannot be empty or whitespace-only.";
        return result;
    }
    if (trimmed_service.size() > MAX_SERVICE_LENGTH) {
        result.is_valid = false;
        result.error_message = "Service name exceeds maximum permitted length (" +
                               std::to_string(MAX_SERVICE_LENGTH) + " characters).";
        return result;
    }
    result.normalized_input.service = trimmed_service;

    // 2. Password validation (NEVER trimmed or altered)
    if (input.password.empty()) {
        result.is_valid = false;
        result.error_message = "Password cannot be empty.";
        return result;
    }
    if (input.password.size() > MAX_PASSWORD_LENGTH) {
        result.is_valid = false;
        result.error_message = "Password exceeds maximum permitted length (" +
                               std::to_string(MAX_PASSWORD_LENGTH) + " characters).";
        return result;
    }

    // 3. Username validation (optional, but trimmed if present)
    const std::string trimmed_username = trim(input.username);
    if (trimmed_username.size() > MAX_USERNAME_LENGTH) {
        result.is_valid = false;
        result.error_message = "Username exceeds maximum permitted length (" +
                               std::to_string(MAX_USERNAME_LENGTH) + " characters).";
        return result;
    }
    result.normalized_input.username = trimmed_username;

    // 4. URL validation (optional, validated if supplied)
    const std::string trimmed_url = trim(input.url);
    if (!trimmed_url.empty()) {
        if (trimmed_url.size() > MAX_URL_LENGTH) {
            result.is_valid = false;
            result.error_message = "URL exceeds maximum permitted length (" +
                                   std::to_string(MAX_URL_LENGTH) + " characters).";
            return result;
        }
        if (!is_valid_url(trimmed_url)) {
            result.is_valid = false;
            result.error_message = "URL format is invalid. Expected format: http(s)://domain/...";
            return result;
        }
    }
    result.normalized_input.url = trimmed_url;

    // 5. Category validation (optional, trimmed)
    const std::string trimmed_category = trim(input.category);
    if (trimmed_category.size() > MAX_CATEGORY_LENGTH) {
        result.is_valid = false;
        result.error_message = "Category exceeds maximum permitted length (" +
                               std::to_string(MAX_CATEGORY_LENGTH) + " characters).";
        return result;
    }
    result.normalized_input.category = trimmed_category;

    // 6. Notes validation (optional, length limit)
    if (input.notes.size() > MAX_NOTES_LENGTH) {
        result.is_valid = false;
        result.error_message = "Notes exceed maximum permitted length (" +
                               std::to_string(MAX_NOTES_LENGTH) + " characters).";
        return result;
    }

    result.is_valid = true;
    return result;
}

}  // namespace password_manager::core
