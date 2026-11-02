#pragma once

#include <vector>

#include "core/Result.hpp"
#include "core/SecureBuffer.hpp"
#include "core/Vault.hpp"
#include "models/Credential.hpp"

namespace password_manager::core {

class VaultSerializer {
  public:
    [[nodiscard]] static Result<SecureBuffer> serialize(const Vault& vault);
    [[nodiscard]] static Result<SecureBuffer> serialize(
        const std::vector<models::Credential>& credentials);

    [[nodiscard]] static Result<std::vector<models::Credential>> deserialize(
        const SecureBuffer& plaintext);
};

}  // namespace password_manager::core
