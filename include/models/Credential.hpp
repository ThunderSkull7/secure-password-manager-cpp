#pragma once

#include <cstdint>
#include <string>

namespace password_manager::models {

using CredentialId = std::uint64_t;

struct CredentialInput {
    std::string service;
    std::string username;
    std::string password;
    std::string url;
    std::string category;
    std::string notes;
};

class Credential {
  public:
    Credential() = default;

    Credential(CredentialId id, std::string service, std::string username, std::string password,
               std::string url, std::string category, std::string notes, std::string created_at,
               std::string updated_at);

    [[nodiscard]] CredentialId id() const noexcept { return id_; }
    [[nodiscard]] const std::string& service() const noexcept { return service_; }
    [[nodiscard]] const std::string& username() const noexcept { return username_; }
    [[nodiscard]] const std::string& password() const noexcept { return password_; }
    [[nodiscard]] const std::string& url() const noexcept { return url_; }
    [[nodiscard]] const std::string& category() const noexcept { return category_; }
    [[nodiscard]] const std::string& notes() const noexcept { return notes_; }
    [[nodiscard]] const std::string& created_at() const noexcept { return created_at_; }
    [[nodiscard]] const std::string& updated_at() const noexcept { return updated_at_; }

    void update(const CredentialInput& input, std::string updated_at);

  private:
    CredentialId id_{0};
    std::string service_;
    std::string username_;
    std::string password_;
    std::string url_;
    std::string category_;
    std::string notes_;
    std::string created_at_;
    std::string updated_at_;
};

}  // namespace password_manager::models
