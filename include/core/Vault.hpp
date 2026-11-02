#pragma once

#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/Result.hpp"
#include "core/Timestamp.hpp"
#include "models/Credential.hpp"

namespace password_manager::core {

class Vault {
  public:
    static constexpr models::CredentialId INITIAL_CREDENTIAL_ID = 1;

    explicit Vault(std::shared_ptr<IClock> clock = std::make_shared<SystemClock>());

    /**
     * @brief Constructs a Vault from an existing set of validated credentials.
     * Validates that credential IDs are unique and positive, and sets next_id_ accordingly.
     * @param credentials Vector of credentials to populate the vault with.
     * @param clock Clock implementation to use for future modifications.
     * @return Initialized Vault or failure if IDs are duplicated or invalid.
     */
    static Result<Vault> from_credentials(
        std::vector<models::Credential> credentials,
        std::shared_ptr<IClock> clock = std::make_shared<SystemClock>());

    // Core Vault Operations
    Result<models::CredentialId> add_credential(const models::CredentialInput& input);

    Result<models::Credential> get_credential(models::CredentialId id) const;

    Result<void> update_credential(models::CredentialId id, const models::CredentialInput& input);

    Result<void> delete_credential(models::CredentialId id);

    [[nodiscard]] std::vector<models::Credential> list_credentials() const;

    /**
     * @brief Performs a case-insensitive partial substring search.
     * Searches service, username, url, category, and notes. Passwords are NEVER searched.
     * @param query Search query string.
     * @return Matching credentials ordered by ID. An empty or whitespace query returns an empty
     * collection.
     */
    [[nodiscard]] std::vector<models::Credential> search_credentials(
        const std::string& query) const;

    [[nodiscard]] std::size_t size() const noexcept;

    [[nodiscard]] bool empty() const noexcept;

    // Duplicate Detection (Warning Mechanism)
    [[nodiscard]] bool has_duplicate(const std::string& service, const std::string& username) const;
    [[nodiscard]] std::vector<models::CredentialId> find_duplicates(
        const models::CredentialInput& input) const;
    [[nodiscard]] std::vector<models::CredentialId> find_duplicates(
        const models::CredentialInput& input, models::CredentialId exclude_id) const;

    // ID state inspection
    [[nodiscard]] models::CredentialId next_id() const noexcept;

  private:
    std::shared_ptr<IClock> clock_;
    models::CredentialId next_id_{INITIAL_CREDENTIAL_ID};
    std::map<models::CredentialId, models::Credential> credentials_;
};

}  // namespace password_manager::core
