#include "models/Credential.hpp"

#include <utility>

namespace password_manager::models {

Credential::Credential(CredentialId id, std::string service, std::string username,
                       std::string password, std::string url, std::string category,
                       std::string notes, std::string created_at, std::string updated_at)
    : id_(id),
      service_(std::move(service)),
      username_(std::move(username)),
      password_(std::move(password)),
      url_(std::move(url)),
      category_(std::move(category)),
      notes_(std::move(notes)),
      created_at_(std::move(created_at)),
      updated_at_(std::move(updated_at)) {}

void Credential::update(const CredentialInput& input, std::string updated_at) {
    service_ = input.service;
    username_ = input.username;
    password_ = input.password;
    url_ = input.url;
    category_ = input.category;
    notes_ = input.notes;
    updated_at_ = std::move(updated_at);
}

}  // namespace password_manager::models
