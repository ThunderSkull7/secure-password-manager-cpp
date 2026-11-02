#include "core/Vault.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <utility>

#include "core/CredentialValidator.hpp"

namespace password_manager::core {

namespace {

std::string to_lower_ascii(std::string_view sv) {
    std::string result;
    result.reserve(sv.size());
    for (const char ch : sv) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return result;
}

std::string normalize_field_for_comparison(std::string_view sv) {
    return to_lower_ascii(CredentialValidator::trim(sv));
}

bool contains_ignore_case(std::string_view haystack, std::string_view needle_lower) {
    if (needle_lower.empty()) {
        return false;
    }
    const std::string hay_lower = to_lower_ascii(haystack);
    return hay_lower.find(needle_lower) != std::string::npos;
}

}  // namespace

Vault::Vault(std::shared_ptr<IClock> clock)
    : clock_(clock ? std::move(clock) : std::make_shared<SystemClock>()) {}

Result<models::CredentialId> Vault::add_credential(const models::CredentialInput& input) {
    const auto validation = CredentialValidator::validate(input);
    if (!validation.is_valid) {
        return Result<models::CredentialId>::failure(VaultErrorCode::ValidationError,
                                                     validation.error_message);
    }

    if (next_id_ == std::numeric_limits<models::CredentialId>::max()) {
        return Result<models::CredentialId>::failure(VaultErrorCode::IdExhaustion,
                                                     "Vault identifier counter has exhausted.");
    }

    const models::CredentialId assigned_id = next_id_++;
    const std::string now_ts = Timestamp::now_utc(*clock_);

    models::Credential cred(
        assigned_id, validation.normalized_input.service, validation.normalized_input.username,
        validation.normalized_input.password, validation.normalized_input.url,
        validation.normalized_input.category, validation.normalized_input.notes, now_ts, now_ts);

    credentials_.emplace(assigned_id, std::move(cred));
    return Result<models::CredentialId>(assigned_id);
}

Result<models::Credential> Vault::get_credential(models::CredentialId id) const {
    const auto it = credentials_.find(id);
    if (it == credentials_.end()) {
        return Result<models::Credential>::failure(
            VaultErrorCode::NotFound,
            "Credential with ID " + std::to_string(id) + " does not exist.");
    }
    return Result<models::Credential>(it->second);
}

Result<void> Vault::update_credential(models::CredentialId id,
                                      const models::CredentialInput& input) {
    const auto it = credentials_.find(id);
    if (it == credentials_.end()) {
        return Result<void>::failure(
            VaultErrorCode::NotFound,
            "Credential with ID " + std::to_string(id) + " does not exist.");
    }

    const auto validation = CredentialValidator::validate(input);
    if (!validation.is_valid) {
        return Result<void>::failure(VaultErrorCode::ValidationError, validation.error_message);
    }

    const std::string now_ts = Timestamp::now_utc(*clock_);
    it->second.update(validation.normalized_input, now_ts);

    return Result<void>::success();
}

Result<void> Vault::delete_credential(models::CredentialId id) {
    const auto it = credentials_.find(id);
    if (it == credentials_.end()) {
        return Result<void>::failure(
            VaultErrorCode::NotFound,
            "Credential with ID " + std::to_string(id) + " does not exist.");
    }

    credentials_.erase(it);
    return Result<void>::success();
}

std::vector<models::Credential> Vault::list_credentials() const {
    std::vector<models::Credential> result;
    result.reserve(credentials_.size());
    for (const auto& [id, cred] : credentials_) {
        result.push_back(cred);
    }
    return result;
}

std::vector<models::Credential> Vault::search_credentials(const std::string& query) const {
    const std::string trimmed_query = CredentialValidator::trim(query);
    if (trimmed_query.empty()) {
        return {};
    }

    const std::string query_lower = to_lower_ascii(trimmed_query);
    std::vector<models::Credential> matches;

    for (const auto& [id, cred] : credentials_) {
        // Search across service, username, url, category, notes. NEVER search password!
        if (contains_ignore_case(cred.service(), query_lower) ||
            contains_ignore_case(cred.username(), query_lower) ||
            contains_ignore_case(cred.url(), query_lower) ||
            contains_ignore_case(cred.category(), query_lower) ||
            contains_ignore_case(cred.notes(), query_lower)) {
            matches.push_back(cred);
        }
    }

    return matches;
}

std::size_t Vault::size() const noexcept {
    return credentials_.size();
}

bool Vault::empty() const noexcept {
    return credentials_.empty();
}

bool Vault::has_duplicate(const std::string& service, const std::string& username) const {
    const std::string target_service = normalize_field_for_comparison(service);
    const std::string target_username = normalize_field_for_comparison(username);

    for (const auto& [id, cred] : credentials_) {
        if (normalize_field_for_comparison(cred.service()) == target_service &&
            normalize_field_for_comparison(cred.username()) == target_username) {
            return true;
        }
    }
    return false;
}

std::vector<models::CredentialId> Vault::find_duplicates(
    const models::CredentialInput& input) const {
    return find_duplicates(input, 0);
}

std::vector<models::CredentialId> Vault::find_duplicates(const models::CredentialInput& input,
                                                         models::CredentialId exclude_id) const {
    std::vector<models::CredentialId> duplicates;
    const std::string target_service = normalize_field_for_comparison(input.service);
    const std::string target_username = normalize_field_for_comparison(input.username);

    for (const auto& [id, cred] : credentials_) {
        if (id == exclude_id) {
            continue;
        }
        if (normalize_field_for_comparison(cred.service()) == target_service &&
            normalize_field_for_comparison(cred.username()) == target_username) {
            duplicates.push_back(id);
        }
    }
    return duplicates;
}

models::CredentialId Vault::next_id() const noexcept {
    return next_id_;
}

}  // namespace password_manager::core
