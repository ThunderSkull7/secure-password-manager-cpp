#pragma once

#include <filesystem>
#include <span>
#include <string_view>

#include "core/CryptoParameters.hpp"
#include "core/CryptoService.hpp"
#include "core/Result.hpp"
#include "core/SecureKey.hpp"
#include "core/Vault.hpp"
#include "core/VaultFileFormat.hpp"

namespace password_manager::core {

class VaultStorage {
  public:
    VaultStorage() = default;

    /**
     * @brief Saves a vault to disk encrypted with a derived key from master password.
     * Generates a fresh random salt and nonce, authenticates the metadata header,
     * and performs atomic file replacement.
     */
    [[nodiscard]] static Result<void> save_vault(
        const std::filesystem::path& path, const Vault& vault, std::string_view master_password,
        const KdfParameters& kdf_params = KdfParameters::interactive_default());

    /**
     * @brief Saves a vault using an existing derived SecureKey and header template.
     * Generates a fresh nonce for every save operation and writes atomically.
     */
    [[nodiscard]] static Result<void> save_vault(const std::filesystem::path& path,
                                                 const Vault& vault, const SecureKey& key,
                                                 const VaultHeader& header_template);

    /**
     * @brief Loads and decrypts a vault file using the master password.
     * Validates file size, header fields, KDF resource limits, AEAD authentication tag,
     * and deserializes the credentials.
     */
    [[nodiscard]] static Result<Vault> load_vault(const std::filesystem::path& path,
                                                  std::string_view master_password);

    /**
     * @brief Loads and decrypts a vault file using an already-derived SecureKey.
     */
    [[nodiscard]] static Result<Vault> load_vault(const std::filesystem::path& path,
                                                  const SecureKey& key);

    /**
     * @brief Inspects and validates the binary header of a vault file without decrypting it.
     */
    [[nodiscard]] static Result<VaultHeader> inspect_header(const std::filesystem::path& path);

    /**
     * @brief Writes data to an unpredictable temporary file in the target directory
     * and atomically replaces the target file.
     */
    [[nodiscard]] static Result<void> write_atomic_file(const std::filesystem::path& target_path,
                                                        std::span<const unsigned char> data);
};

}  // namespace password_manager::core
