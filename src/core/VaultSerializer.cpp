#include "core/VaultSerializer.hpp"

#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include "core/CredentialValidator.hpp"
#include "core/VaultError.hpp"
#include "core/VaultFileFormat.hpp"

namespace password_manager::core {

Result<SecureBuffer> VaultSerializer::serialize(const Vault& vault) {
    return serialize(vault.list_credentials());
}

Result<SecureBuffer> VaultSerializer::serialize(
    const std::vector<models::Credential>& credentials) {
    nlohmann::json root;
    root["format_version"] = 1;
    root["credentials"] = nlohmann::json::array();

    for (const auto& cred : credentials) {
        nlohmann::json item;
        item["id"] = cred.id();
        item["service"] = cred.service();
        item["username"] = cred.username();
        item["password"] = cred.password();
        item["url"] = cred.url();
        item["category"] = cred.category();
        item["notes"] = cred.notes();
        item["created_at"] = cred.created_at();
        item["updated_at"] = cred.updated_at();
        root["credentials"].push_back(std::move(item));
    }

    std::string serialized = root.dump();
    auto buffer_res = SecureBuffer::from_string(serialized);

    // Safely zero out serialized temporary string
    sodium_memzero(serialized.data(), serialized.size());

    if (!buffer_res.has_value()) {
        return Result<SecureBuffer>::failure(
            VaultErrorCode::SerializationError,
            "Failed to allocate secure buffer for serialized data: " + buffer_res.error().message);
    }

    return buffer_res;
}

Result<std::vector<models::Credential>> VaultSerializer::deserialize(
    const SecureBuffer& plaintext) {
    if (plaintext.empty() || plaintext.data() == nullptr) {
        return Result<std::vector<models::Credential>>::failure(
            VaultErrorCode::DeserializationError, "Decrypted payload buffer is empty.");
    }

    const std::string_view json_view(reinterpret_cast<const char*>(plaintext.data()),
                                     plaintext.size());

    nlohmann::json root;
    try {
        root = nlohmann::json::parse(json_view);
    } catch (const nlohmann::json::exception& e) {
        return Result<std::vector<models::Credential>>::failure(
            VaultErrorCode::DeserializationError,
            "Malformed JSON payload in decrypted vault: " + std::string(e.what()));
    }

    if (!root.is_object()) {
        return Result<std::vector<models::Credential>>::failure(
            VaultErrorCode::DeserializationError, "Vault payload root is not a valid JSON object.");
    }

    if (!root.contains("credentials") || !root["credentials"].is_array()) {
        return Result<std::vector<models::Credential>>::failure(
            VaultErrorCode::DeserializationError, "Vault payload missing 'credentials' array.");
    }

    const auto& creds_array = root["credentials"];
    if (creds_array.size() > VaultFileFormat::MAX_CREDENTIAL_COUNT) {
        return Result<std::vector<models::Credential>>::failure(
            VaultErrorCode::ResourceLimitExceeded,
            "Credential count exceeds maximum permitted limit (" +
                std::to_string(VaultFileFormat::MAX_CREDENTIAL_COUNT) + ").");
    }

    std::vector<models::Credential> credentials;
    credentials.reserve(creds_array.size());
    std::set<models::CredentialId> seen_ids;

    const std::array<const char*, 9> required_fields = {"id",       "service",    "username",
                                                        "password", "url",        "category",
                                                        "notes",    "created_at", "updated_at"};

    for (const auto& item : creds_array) {
        if (!item.is_object()) {
            return Result<std::vector<models::Credential>>::failure(
                VaultErrorCode::DeserializationError, "Credential entry is not a JSON object.");
        }

        for (const char* field : required_fields) {
            if (!item.contains(field)) {
                return Result<std::vector<models::Credential>>::failure(
                    VaultErrorCode::DeserializationError,
                    std::string("Credential entry missing required field: ") + field);
            }
        }

        if (!item["id"].is_number_unsigned()) {
            return Result<std::vector<models::Credential>>::failure(
                VaultErrorCode::DeserializationError, "Credential ID must be an unsigned integer.");
        }

        if (!item["service"].is_string() || !item["username"].is_string() ||
            !item["password"].is_string() || !item["url"].is_string() ||
            !item["category"].is_string() || !item["notes"].is_string() ||
            !item["created_at"].is_string() || !item["updated_at"].is_string()) {
            return Result<std::vector<models::Credential>>::failure(
                VaultErrorCode::DeserializationError, "Credential fields must be strings.");
        }

        const auto id = item["id"].get<models::CredentialId>();
        if (id == 0) {
            return Result<std::vector<models::Credential>>::failure(
                VaultErrorCode::DeserializationError, "Credential ID must be greater than zero.");
        }

        if (!seen_ids.insert(id).second) {
            return Result<std::vector<models::Credential>>::failure(
                VaultErrorCode::DeserializationError,
                "Duplicate credential ID detected in vault payload: " + std::to_string(id));
        }

        std::string service = item["service"].get<std::string>();
        std::string username = item["username"].get<std::string>();
        std::string password = item["password"].get<std::string>();
        std::string url = item["url"].get<std::string>();
        std::string category = item["category"].get<std::string>();
        std::string notes = item["notes"].get<std::string>();
        std::string created_at = item["created_at"].get<std::string>();
        std::string updated_at = item["updated_at"].get<std::string>();

        if (created_at.empty() || updated_at.empty()) {
            return Result<std::vector<models::Credential>>::failure(
                VaultErrorCode::DeserializationError, "Credential timestamps cannot be empty.");
        }

        models::CredentialInput input{service, username, password, url, category, notes};
        const auto validation = CredentialValidator::validate(input);
        if (!validation.is_valid) {
            return Result<std::vector<models::Credential>>::failure(
                VaultErrorCode::DeserializationError,
                "Credential validation error: " + validation.error_message);
        }

        credentials.emplace_back(id, std::move(service), std::move(username), std::move(password),
                                 std::move(url), std::move(category), std::move(notes),
                                 std::move(created_at), std::move(updated_at));
    }

    return Result<std::vector<models::Credential>>(std::move(credentials));
}

}  // namespace password_manager::core
