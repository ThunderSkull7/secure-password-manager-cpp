#include "core/VaultStorage.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <fstream>
#include <utility>
#include <vector>

#include "core/SodiumInitializer.hpp"
#include "core/VaultError.hpp"
#include "core/VaultSerializer.hpp"

namespace password_manager::core {

Result<VaultHeader> VaultStorage::inspect_header(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return Result<VaultHeader>::failure(VaultErrorCode::NotFound,
                                            "Vault file does not exist: " + path.string());
    }

    if (std::filesystem::is_symlink(path, ec)) {
        return Result<VaultHeader>::failure(VaultErrorCode::InvalidVaultFormat,
                                            "Symbolic links are not supported for vault storage.");
    }

    if (std::filesystem::is_directory(path, ec)) {
        return Result<VaultHeader>::failure(
            VaultErrorCode::InvalidVaultFormat,
            "Target path is a directory, not a vault file: " + path.string());
    }

    const auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return Result<VaultHeader>::failure(VaultErrorCode::FileReadError,
                                            "Failed to query vault file size: " + ec.message());
    }

    if (file_size < VaultFileFormat::HEADER_SIZE) {
        return Result<VaultHeader>::failure(
            VaultErrorCode::CorruptedVault,
            "Vault file is smaller than minimum required header size (" +
                std::to_string(VaultFileFormat::HEADER_SIZE) + " bytes).");
    }

    if (file_size > VaultFileFormat::MAX_VAULT_FILE_SIZE) {
        return Result<VaultHeader>::failure(
            VaultErrorCode::ResourceLimitExceeded,
            "Vault file exceeds maximum permitted file size (" +
                std::to_string(VaultFileFormat::MAX_VAULT_FILE_SIZE) + " bytes).");
    }

    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return Result<VaultHeader>::failure(
            VaultErrorCode::FileReadError,
            "Failed to open vault file for reading: " + path.string());
    }

    std::array<unsigned char, VaultFileFormat::HEADER_SIZE> header_bytes{};
    in.read(reinterpret_cast<char*>(header_bytes.data()),
            static_cast<std::streamsize>(header_bytes.size()));
    if (!in.good()) {
        return Result<VaultHeader>::failure(VaultErrorCode::FileReadError,
                                            "Failed to read vault header bytes.");
    }

    auto header_res = VaultHeader::deserialize(header_bytes);
    if (!header_res.has_value()) {
        return header_res;
    }

    const auto& header = header_res.value();
    const std::uint64_t expected_total_size =
        static_cast<std::uint64_t>(VaultFileFormat::HEADER_SIZE) + header.ciphertext_length;

    if (file_size < expected_total_size) {
        return Result<VaultHeader>::failure(
            VaultErrorCode::CorruptedVault,
            "Vault file is truncated (expected " + std::to_string(expected_total_size) +
                " bytes, got " + std::to_string(file_size) + " bytes).");
    }

    if (file_size > expected_total_size) {
        return Result<VaultHeader>::failure(
            VaultErrorCode::CorruptedVault,
            "Vault file contains unexpected trailing data (expected " +
                std::to_string(expected_total_size) + " bytes, got " + std::to_string(file_size) +
                " bytes).");
    }

    return header_res;
}

Result<void> VaultStorage::write_atomic_file(const std::filesystem::path& target_path,
                                             std::span<const unsigned char> data) {
    if (target_path.empty()) {
        return Result<void>::failure(VaultErrorCode::FileWriteError,
                                     "Target path cannot be empty.");
    }

    std::error_code ec;
    if (std::filesystem::is_symlink(target_path, ec)) {
        return Result<void>::failure(VaultErrorCode::FileWriteError,
                                     "Symbolic links are not supported for vault storage.");
    }

    if (std::filesystem::is_directory(target_path, ec)) {
        return Result<void>::failure(
            VaultErrorCode::FileWriteError,
            "Target path is an existing directory, not a file: " + target_path.string());
    }

    const std::filesystem::path parent = target_path.parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent, ec)) {
        return Result<void>::failure(VaultErrorCode::FileWriteError,
                                     "Target directory does not exist: " + parent.string());
    }

    const auto init_res = SodiumInitializer::initialize();
    if (!init_res.has_value()) {
        return Result<void>::failure(init_res.error().code, init_res.error().message);
    }

    // Generate random 8 bytes (16 hex characters) for temporary file suffix
    std::array<unsigned char, 8> rand_bytes{};
    randombytes_buf(rand_bytes.data(), rand_bytes.size());
    std::array<char, 17> hex_buf{};
    sodium_bin2hex(hex_buf.data(), hex_buf.size(), rand_bytes.data(), rand_bytes.size());

    const std::string filename =
        target_path.filename().string() + ".spm_" + hex_buf.data() + ".tmp";
    const std::filesystem::path temp_path =
        parent.empty() ? std::filesystem::path(filename) : (parent / filename);

    // Write contents to temporary file
    {
        std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            return Result<void>::failure(
                VaultErrorCode::FileWriteError,
                "Failed to open temporary file for writing: " + temp_path.string());
        }

        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        }
        out.flush();

        if (!out.good()) {
            out.close();
            std::filesystem::remove(temp_path, ec);
            return Result<void>::failure(VaultErrorCode::FileWriteError,
                                         "Failed writing vault payload to temporary file.");
        }
    }

#ifdef _WIN32
    // Flush file buffers to physical disk storage
    HANDLE hFile = CreateFileW(temp_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
    }

    const bool target_exists = std::filesystem::exists(target_path, ec);
    bool replace_success = false;

    if (target_exists) {
        if (ReplaceFileW(target_path.c_str(), temp_path.c_str(), nullptr, REPLACEFILE_WRITE_THROUGH,
                         nullptr, nullptr)) {
            replace_success = true;
        } else {
            if (MoveFileExW(temp_path.c_str(), target_path.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                replace_success = true;
            }
        }
    } else {
        if (MoveFileExW(temp_path.c_str(), target_path.c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            replace_success = true;
        }
    }

    if (!replace_success) {
        std::filesystem::remove(temp_path, ec);
        return Result<void>::failure(VaultErrorCode::AtomicReplacementError,
                                     "Failed to atomically replace target vault file.");
    }
#else
    std::filesystem::rename(temp_path, target_path, ec);
    if (ec) {
        std::filesystem::remove(temp_path, ec);
        return Result<void>::failure(VaultErrorCode::AtomicReplacementError,
                                     "Failed to atomically move temporary file: " + ec.message());
    }
#endif

    return Result<void>::success();
}

Result<Vault> VaultStorage::load_vault(const std::filesystem::path& path,
                                       std::string_view master_password) {
    auto pwd_val = CryptoService::validate_master_password(master_password);
    if (!pwd_val.has_value()) {
        return Result<Vault>::failure(pwd_val.error().code, pwd_val.error().message);
    }

    auto header_res = inspect_header(path);
    if (!header_res.has_value()) {
        return Result<Vault>::failure(header_res.error().code, header_res.error().message);
    }
    const auto& header = header_res.value();

    KdfParameters params{header.kdf_ops_limit, static_cast<std::size_t>(header.kdf_mem_limit),
                         static_cast<int>(header.kdf_algorithm)};

    CryptoService crypto_service;
    auto key_res = crypto_service.derive_key(master_password, header.salt, params);
    if (!key_res.has_value()) {
        return Result<Vault>::failure(key_res.error().code, key_res.error().message);
    }

    return load_vault(path, key_res.value());
}

Result<Vault> VaultStorage::load_vault(const std::filesystem::path& path, const SecureKey& key) {
    if (!key.is_valid()) {
        return Result<Vault>::failure(VaultErrorCode::InvalidKey,
                                      "Decryption key is uninitialized or invalid.");
    }

    auto header_res = inspect_header(path);
    if (!header_res.has_value()) {
        return Result<Vault>::failure(header_res.error().code, header_res.error().message);
    }
    const auto& header = header_res.value();

    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return Result<Vault>::failure(VaultErrorCode::FileReadError,
                                      "Failed to open vault file for reading: " + path.string());
    }

    in.seekg(static_cast<std::streamoff>(VaultFileFormat::HEADER_SIZE), std::ios::beg);
    std::vector<unsigned char> ciphertext(static_cast<std::size_t>(header.ciphertext_length));
    in.read(reinterpret_cast<char*>(ciphertext.data()),
            static_cast<std::streamsize>(header.ciphertext_length));
    if (!in.good()) {
        return Result<Vault>::failure(VaultErrorCode::FileReadError,
                                      "Failed to read encrypted ciphertext from vault file.");
    }

    const auto aad = header.serialize_aad();
    CryptoService crypto_service;
    EncryptedMessage msg{header.nonce, std::move(ciphertext)};
    auto decrypt_res = crypto_service.decrypt(key, msg, aad);
    if (!decrypt_res.has_value()) {
        return Result<Vault>::failure(
            VaultErrorCode::AuthenticationFailed,
            "Failed to unlock vault: invalid master password or corrupted/tampered vault file.");
    }

    auto creds_res = VaultSerializer::deserialize(decrypt_res.value());
    if (!creds_res.has_value()) {
        return Result<Vault>::failure(creds_res.error().code, creds_res.error().message);
    }

    return Vault::from_credentials(std::move(creds_res.value()));
}

Result<void> VaultStorage::save_vault(const std::filesystem::path& path, const Vault& vault,
                                      std::string_view master_password,
                                      const KdfParameters& kdf_params) {
    auto pwd_val = CryptoService::validate_master_password(master_password);
    if (!pwd_val.has_value()) {
        return Result<void>::failure(pwd_val.error().code, pwd_val.error().message);
    }

    auto kdf_val = CryptoService::validate_kdf_parameters(kdf_params);
    if (!kdf_val.has_value()) {
        return Result<void>::failure(kdf_val.error().code, kdf_val.error().message);
    }

    CryptoService crypto_service;
    auto salt_res = crypto_service.generate_salt();
    if (!salt_res.has_value()) {
        return Result<void>::failure(salt_res.error().code, salt_res.error().message);
    }
    const auto salt = salt_res.value();

    auto key_res = crypto_service.derive_key(master_password, salt, kdf_params);
    if (!key_res.has_value()) {
        return Result<void>::failure(key_res.error().code, key_res.error().message);
    }

    VaultHeader header;
    header.version = VaultFileFormat::CURRENT_VERSION;
    header.cipher_algorithm = VaultFileFormat::CIPHER_ALGO_XCHACHA20_POLY1305;
    header.kdf_algorithm = static_cast<std::uint32_t>(kdf_params.algorithm);
    header.kdf_ops_limit = kdf_params.ops_limit;
    header.kdf_mem_limit = static_cast<std::uint64_t>(kdf_params.memory_limit);
    header.salt = salt;

    return save_vault(path, vault, key_res.value(), header);
}

Result<void> VaultStorage::save_vault(const std::filesystem::path& path, const Vault& vault,
                                      const SecureKey& key, const VaultHeader& header_template) {
    if (!key.is_valid()) {
        return Result<void>::failure(VaultErrorCode::InvalidKey,
                                     "Encryption key is invalid or uninitialized.");
    }

    VaultHeader header = header_template;
    header.version = VaultFileFormat::CURRENT_VERSION;
    header.cipher_algorithm = VaultFileFormat::CIPHER_ALGO_XCHACHA20_POLY1305;

    auto serialize_res = VaultSerializer::serialize(vault);
    if (!serialize_res.has_value()) {
        return Result<void>::failure(serialize_res.error().code, serialize_res.error().message);
    }
    const auto& plaintext = serialize_res.value();

    const auto aad = header.serialize_aad();

    CryptoService crypto_service;
    auto encrypt_res = crypto_service.encrypt(key, plaintext.as_span(), aad);
    if (!encrypt_res.has_value()) {
        return Result<void>::failure(encrypt_res.error().code, encrypt_res.error().message);
    }
    auto encrypted = std::move(encrypt_res.value());

    header.nonce = encrypted.nonce;
    header.ciphertext_length = encrypted.ciphertext.size();

    const auto serialized_hdr = header.serialize_header();

    std::vector<unsigned char> full_file;
    full_file.reserve(serialized_hdr.size() + encrypted.ciphertext.size());
    full_file.insert(full_file.end(), serialized_hdr.begin(), serialized_hdr.end());
    full_file.insert(full_file.end(), encrypted.ciphertext.begin(), encrypted.ciphertext.end());

    auto write_res = write_atomic_file(path, full_file);
    sodium_memzero(full_file.data(), full_file.size());

    return write_res;
}

}  // namespace password_manager::core
