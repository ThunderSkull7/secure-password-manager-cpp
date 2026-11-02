#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "core/CryptoParameters.hpp"
#include "core/CryptoService.hpp"
#include "core/Result.hpp"
#include "core/SecureBuffer.hpp"
#include "core/Vault.hpp"
#include "core/VaultError.hpp"
#include "core/VaultFileFormat.hpp"
#include "core/VaultSerializer.hpp"
#include "core/VaultStorage.hpp"
#include "models/Credential.hpp"

namespace password_manager::core::test {

namespace {

class TempDirectoryGuard {
  public:
    TempDirectoryGuard() {
        std::error_code ec;
        path_ = std::filesystem::temp_directory_path() /
                ("spm_test_" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(path_, ec);
    }

    ~TempDirectoryGuard() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

  private:
    std::filesystem::path path_;
};

models::CredentialInput create_sample_input(std::string service = "GitHub",
                                            std::string username = "alice",
                                            std::string password = "SecretPassword123!",
                                            std::string url = "https://github.com",
                                            std::string category = "Development",
                                            std::string notes = "Primary developer account") {
    return {std::move(service), std::move(username), std::move(password),
            std::move(url),     std::move(category), std::move(notes)};
}

}  // namespace

// ============================================================================
// 1. Format and Serialization Tests
// ============================================================================

TEST(VaultSerializerTest, EmptyVaultRoundTrip) {
    Vault vault;
    auto serialize_res = VaultSerializer::serialize(vault);
    ASSERT_TRUE(serialize_res.has_value());

    auto deserialize_res = VaultSerializer::deserialize(serialize_res.value());
    ASSERT_TRUE(deserialize_res.has_value());
    EXPECT_TRUE(deserialize_res.value().empty());

    auto vault_res = Vault::from_credentials(std::move(deserialize_res.value()));
    ASSERT_TRUE(vault_res.has_value());
    EXPECT_EQ(vault_res.value().size(), 0u);
}

TEST(VaultSerializerTest, SingleCredentialRoundTrip) {
    Vault vault;
    auto add_res = vault.add_credential(create_sample_input());
    ASSERT_TRUE(add_res.has_value());
    const auto original_id = add_res.value();

    auto serialize_res = VaultSerializer::serialize(vault);
    ASSERT_TRUE(serialize_res.has_value());

    auto deserialize_res = VaultSerializer::deserialize(serialize_res.value());
    ASSERT_TRUE(deserialize_res.has_value());
    const auto& creds = deserialize_res.value();
    ASSERT_EQ(creds.size(), 1u);

    EXPECT_EQ(creds[0].id(), original_id);
    EXPECT_EQ(creds[0].service(), "GitHub");
    EXPECT_EQ(creds[0].username(), "alice");
    EXPECT_EQ(creds[0].password(), "SecretPassword123!");
    EXPECT_EQ(creds[0].url(), "https://github.com");
    EXPECT_EQ(creds[0].category(), "Development");
    EXPECT_EQ(creds[0].notes(), "Primary developer account");
    EXPECT_FALSE(creds[0].created_at().empty());
    EXPECT_FALSE(creds[0].updated_at().empty());
}

TEST(VaultSerializerTest, MultipleCredentialRoundTrip) {
    Vault vault;
    auto id1 = vault.add_credential(create_sample_input("Google", "alice@gmail.com", "P@ss1"));
    auto id2 = vault.add_credential(create_sample_input("AWS", "alice@work.com", "P@ss2"));
    auto id3 = vault.add_credential(create_sample_input("Slack", "alice", "P@ss3"));

    ASSERT_TRUE(id1.has_value() && id2.has_value() && id3.has_value());

    auto serialize_res = VaultSerializer::serialize(vault);
    ASSERT_TRUE(serialize_res.has_value());

    auto deserialize_res = VaultSerializer::deserialize(serialize_res.value());
    ASSERT_TRUE(deserialize_res.has_value());
    const auto& creds = deserialize_res.value();
    ASSERT_EQ(creds.size(), 3u);

    EXPECT_EQ(creds[0].id(), id1.value());
    EXPECT_EQ(creds[1].id(), id2.value());
    EXPECT_EQ(creds[2].id(), id3.value());

    auto restored_vault_res = Vault::from_credentials(std::move(deserialize_res.value()));
    ASSERT_TRUE(restored_vault_res.has_value());
    EXPECT_EQ(restored_vault_res.value().size(), 3u);
    EXPECT_GT(restored_vault_res.value().next_id(), id3.value());
}

TEST(VaultSerializerTest, UnicodeAndSpecialCharacters) {
    Vault vault;
    const std::string unicode_service = "银行服务 (Bank 🏦)";
    const std::string unicode_username = "ユーザー@ドメイン.jp";
    const std::string unicode_password = "P@$$wørd!_🔒_#%^&*()";
    const std::string unicode_category = "Finance 💰";
    const std::string unicode_notes = "Special notes: \n Line 2 \t Tabbed \"Quoted\" & <bracketed>";

    auto add_res =
        vault.add_credential({unicode_service, unicode_username, unicode_password,
                              "https://bank.example.jp", unicode_category, unicode_notes});
    ASSERT_TRUE(add_res.has_value());

    auto serialize_res = VaultSerializer::serialize(vault);
    ASSERT_TRUE(serialize_res.has_value());

    auto deserialize_res = VaultSerializer::deserialize(serialize_res.value());
    ASSERT_TRUE(deserialize_res.has_value());
    const auto& creds = deserialize_res.value();
    ASSERT_EQ(creds.size(), 1u);

    EXPECT_EQ(creds[0].service(), unicode_service);
    EXPECT_EQ(creds[0].username(), unicode_username);
    EXPECT_EQ(creds[0].password(), unicode_password);
    EXPECT_EQ(creds[0].category(), unicode_category);
    EXPECT_EQ(creds[0].notes(), unicode_notes);
}

TEST(VaultSerializerTest, LongNotesAndOptionalFields) {
    Vault vault;
    std::string long_notes(60000, 'N');
    auto add_res = vault.add_credential({"ServiceA", "userA", "passA", "", "", long_notes});
    ASSERT_TRUE(add_res.has_value());

    auto serialize_res = VaultSerializer::serialize(vault);
    ASSERT_TRUE(serialize_res.has_value());

    auto deserialize_res = VaultSerializer::deserialize(serialize_res.value());
    ASSERT_TRUE(deserialize_res.has_value());
    const auto& creds = deserialize_res.value();
    ASSERT_EQ(creds.size(), 1u);

    EXPECT_TRUE(creds[0].url().empty());
    EXPECT_TRUE(creds[0].category().empty());
    EXPECT_EQ(creds[0].notes().size(), 60000u);
}

TEST(VaultSerializerTest, RejectsDuplicateIds) {
    std::string duplicate_json = R"({
        "format_version": 1,
        "credentials": [
            {
                "id": 1,
                "service": "Service1",
                "username": "user1",
                "password": "pass1",
                "url": "",
                "category": "",
                "notes": "",
                "created_at": "2026-11-02T12:00:00Z",
                "updated_at": "2026-11-02T12:00:00Z"
            },
            {
                "id": 1,
                "service": "Service2",
                "username": "user2",
                "password": "pass2",
                "url": "",
                "category": "",
                "notes": "",
                "created_at": "2026-11-02T12:00:00Z",
                "updated_at": "2026-11-02T12:00:00Z"
            }
        ]
    })";

    auto buf_res = SecureBuffer::from_string(duplicate_json);
    ASSERT_TRUE(buf_res.has_value());

    auto des_res = VaultSerializer::deserialize(buf_res.value());
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::DeserializationError);
}

TEST(VaultSerializerTest, RejectsMalformedPayload) {
    auto buf_res = SecureBuffer::from_string("{ corrupted_json ");
    ASSERT_TRUE(buf_res.has_value());

    auto des_res = VaultSerializer::deserialize(buf_res.value());
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::DeserializationError);
}

TEST(VaultSerializerTest, RejectsMissingRequiredFields) {
    std::string missing_field_json = R"({
        "format_version": 1,
        "credentials": [
            {
                "id": 1,
                "service": "Service1"
            }
        ]
    })";

    auto buf_res = SecureBuffer::from_string(missing_field_json);
    ASSERT_TRUE(buf_res.has_value());

    auto des_res = VaultSerializer::deserialize(buf_res.value());
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::DeserializationError);
}

TEST(VaultFileFormatTest, HeaderSerializationAndDeserializationRoundTrip) {
    VaultHeader header;
    header.version = 1;
    header.cipher_algorithm = 1;
    header.kdf_algorithm = 2;
    header.kdf_ops_limit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    header.kdf_mem_limit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    header.salt.fill(0xAA);
    header.nonce.fill(0xBB);
    header.ciphertext_length = 1024;

    const auto serialized = header.serialize_header();
    EXPECT_EQ(serialized.size(), VaultFileFormat::HEADER_SIZE);

    auto des_res = VaultHeader::deserialize(serialized);
    ASSERT_TRUE(des_res.has_value());
    const auto& deserialized = des_res.value();

    EXPECT_EQ(deserialized.version, header.version);
    EXPECT_EQ(deserialized.cipher_algorithm, header.cipher_algorithm);
    EXPECT_EQ(deserialized.kdf_algorithm, header.kdf_algorithm);
    EXPECT_EQ(deserialized.kdf_ops_limit, header.kdf_ops_limit);
    EXPECT_EQ(deserialized.kdf_mem_limit, header.kdf_mem_limit);
    EXPECT_EQ(deserialized.salt, header.salt);
    EXPECT_EQ(deserialized.nonce, header.nonce);
    EXPECT_EQ(deserialized.ciphertext_length, header.ciphertext_length);
}

TEST(VaultFileFormatTest, RejectsInvalidMagic) {
    VaultHeader header;
    header.ciphertext_length = 64;
    auto serialized = header.serialize_header();
    serialized[0] = 'X';  // Corrupt magic

    auto des_res = VaultHeader::deserialize(serialized);
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::InvalidVaultFormat);
}

TEST(VaultFileFormatTest, RejectsUnsupportedVersion) {
    VaultHeader header;
    header.version = 2;  // Future unsupported version
    header.ciphertext_length = 64;
    const auto serialized = header.serialize_header();

    auto des_res = VaultHeader::deserialize(serialized);
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::UnsupportedVersion);
}

TEST(VaultFileFormatTest, RejectsUnsupportedAlgorithms) {
    VaultHeader header;
    header.ciphertext_length = 64;
    header.cipher_algorithm = 99;  // Unsupported cipher
    auto serialized = header.serialize_header();

    auto des_res = VaultHeader::deserialize(serialized);
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::InvalidVaultFormat);

    header.cipher_algorithm = VaultFileFormat::CIPHER_ALGO_XCHACHA20_POLY1305;
    header.kdf_algorithm = 99;  // Unsupported KDF
    serialized = header.serialize_header();

    des_res = VaultHeader::deserialize(serialized);
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::InvalidKdfParameters);
}

TEST(VaultFileFormatTest, RejectsTruncatedHeader) {
    std::vector<unsigned char> truncated(VaultFileFormat::HEADER_SIZE - 1, 0);
    auto des_res = VaultHeader::deserialize(truncated);
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::CorruptedVault);
}

TEST(VaultFileFormatTest, RejectsExcessiveKdfLimits) {
    VaultHeader header;
    header.ciphertext_length = 64;
    header.kdf_ops_limit = 999;  // Out of bounds ops limit
    auto serialized = header.serialize_header();

    auto des_res = VaultHeader::deserialize(serialized);
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::ResourceLimitExceeded);

    header.kdf_ops_limit = VaultFileFormat::MIN_KDF_OPS_LIMIT;
    header.kdf_mem_limit = 1024ULL * 1024 * 1024;  // 1 GiB > 512 MiB limit
    serialized = header.serialize_header();

    des_res = VaultHeader::deserialize(serialized);
    EXPECT_FALSE(des_res.has_value());
    EXPECT_EQ(des_res.error().code, VaultErrorCode::ResourceLimitExceeded);
}

// ============================================================================
// 2. Cryptographic Integration Tests
// ============================================================================

TEST(VaultStorageTest, SaveAndLoadVaultWithMasterPasswordSucceeds) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "test.vault";

    Vault vault;
    ASSERT_TRUE(
        vault.add_credential(create_sample_input("GitHub", "alice", "SecretPass")).has_value());
    ASSERT_TRUE(
        vault.add_credential(create_sample_input("GitLab", "bob", "SecretPass2")).has_value());

    const std::string master_password = "CorrectMasterPassword123!";
    auto save_res = VaultStorage::save_vault(vault_path, vault, master_password);
    ASSERT_TRUE(save_res.has_value()) << save_res.error().message;

    auto load_res = VaultStorage::load_vault(vault_path, master_password);
    ASSERT_TRUE(load_res.has_value()) << load_res.error().message;

    const auto& loaded_vault = load_res.value();
    EXPECT_EQ(loaded_vault.size(), 2u);

    auto cred1 = loaded_vault.get_credential(1);
    ASSERT_TRUE(cred1.has_value());
    EXPECT_EQ(cred1.value().service(), "GitHub");
    EXPECT_EQ(cred1.value().username(), "alice");
    EXPECT_EQ(cred1.value().password(), "SecretPass");
}

TEST(VaultStorageTest, WrongMasterPasswordFailsWithAuthenticationFailed) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "test.vault";

    Vault vault;
    ASSERT_TRUE(vault.add_credential(create_sample_input()).has_value());

    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault, "CorrectPassword").has_value());

    auto load_res = VaultStorage::load_vault(vault_path, "WrongPassword");
    EXPECT_FALSE(load_res.has_value());
    EXPECT_EQ(load_res.error().code, VaultErrorCode::AuthenticationFailed);
}

TEST(VaultStorageTest, TamperedCiphertextFailsAuthentication) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "test.vault";

    Vault vault;
    ASSERT_TRUE(vault.add_credential(create_sample_input()).has_value());
    const std::string master_pwd = "StrongMasterPassword";
    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault, master_pwd).has_value());

    // Tamper with one byte in the ciphertext portion (after offset 80)
    std::fstream file(vault_path, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open());
    file.seekp(VaultFileFormat::HEADER_SIZE + 5, std::ios::beg);
    char byte_val = 0;
    file.read(&byte_val, 1);
    byte_val ^= 0xFF;
    file.seekp(VaultFileFormat::HEADER_SIZE + 5, std::ios::beg);
    file.write(&byte_val, 1);
    file.close();

    auto load_res = VaultStorage::load_vault(vault_path, master_pwd);
    EXPECT_FALSE(load_res.has_value());
    EXPECT_EQ(load_res.error().code, VaultErrorCode::AuthenticationFailed);
}

TEST(VaultStorageTest, TamperedNonceFailsAuthentication) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "test.vault";

    Vault vault;
    ASSERT_TRUE(vault.add_credential(create_sample_input()).has_value());
    const std::string master_pwd = "StrongMasterPassword";
    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault, master_pwd).has_value());

    // Tamper with nonce (located at offset 48)
    std::fstream file(vault_path, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open());
    file.seekp(48, std::ios::beg);
    char byte_val = 0;
    file.read(&byte_val, 1);
    byte_val ^= 0xFF;
    file.seekp(48, std::ios::beg);
    file.write(&byte_val, 1);
    file.close();

    auto load_res = VaultStorage::load_vault(vault_path, master_pwd);
    EXPECT_FALSE(load_res.has_value());
    EXPECT_EQ(load_res.error().code, VaultErrorCode::AuthenticationFailed);
}

TEST(VaultStorageTest, TamperedSaltFailsAuthentication) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "test.vault";

    Vault vault;
    ASSERT_TRUE(vault.add_credential(create_sample_input()).has_value());
    const std::string master_pwd = "StrongMasterPassword";
    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault, master_pwd).has_value());

    // Tamper with salt (located at offset 32)
    std::fstream file(vault_path, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open());
    file.seekp(32, std::ios::beg);
    char byte_val = 0;
    file.read(&byte_val, 1);
    byte_val ^= 0xFF;
    file.seekp(32, std::ios::beg);
    file.write(&byte_val, 1);
    file.close();

    auto load_res = VaultStorage::load_vault(vault_path, master_pwd);
    EXPECT_FALSE(load_res.has_value());
    EXPECT_EQ(load_res.error().code, VaultErrorCode::AuthenticationFailed);
}

TEST(VaultStorageTest, TwoConsecutiveSavesProduceDifferentNoncesAndCiphertext) {
    TempDirectoryGuard temp_dir;
    const auto path1 = temp_dir.path() / "vault1.vault";
    const auto path2 = temp_dir.path() / "vault2.vault";

    Vault vault;
    ASSERT_TRUE(vault.add_credential(create_sample_input()).has_value());

    ASSERT_TRUE(VaultStorage::save_vault(path1, vault, "MasterPassword").has_value());
    ASSERT_TRUE(VaultStorage::save_vault(path2, vault, "MasterPassword").has_value());

    auto hdr1 = VaultStorage::inspect_header(path1);
    auto hdr2 = VaultStorage::inspect_header(path2);
    ASSERT_TRUE(hdr1.has_value() && hdr2.has_value());

    EXPECT_NE(hdr1.value().nonce, hdr2.value().nonce);
    EXPECT_NE(hdr1.value().salt, hdr2.value().salt);
}

TEST(VaultStorageTest, SaveAndLoadWithDerivedKeyPreservesDataAcrossCycles) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "key_vault.vault";

    Vault vault;
    ASSERT_TRUE(vault.add_credential(create_sample_input("S1", "U1", "P1")).has_value());

    CryptoService crypto;
    auto salt_res = crypto.generate_salt();
    ASSERT_TRUE(salt_res.has_value());

    auto key_res = crypto.derive_key("SecretMasterPassword", salt_res.value());
    ASSERT_TRUE(key_res.has_value());
    const auto& key = key_res.value();

    VaultHeader header_template;
    header_template.salt = salt_res.value();

    // Save cycle 1
    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault, key, header_template).has_value());

    // Load cycle 1
    auto loaded1 = VaultStorage::load_vault(vault_path, key);
    ASSERT_TRUE(loaded1.has_value());
    EXPECT_EQ(loaded1.value().size(), 1u);

    // Modify vault and save cycle 2
    ASSERT_TRUE(loaded1.value().add_credential(create_sample_input("S2", "U2", "P2")).has_value());
    ASSERT_TRUE(
        VaultStorage::save_vault(vault_path, loaded1.value(), key, header_template).has_value());

    // Load cycle 2
    auto loaded2 = VaultStorage::load_vault(vault_path, key);
    ASSERT_TRUE(loaded2.has_value());
    EXPECT_EQ(loaded2.value().size(), 2u);
}

// ============================================================================
// 3. Atomic Persistence Tests
// ============================================================================

TEST(VaultStorageTest, AtomicReplacementOverwritesExistingVaultSafely) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "atomic.vault";

    Vault vault1;
    ASSERT_TRUE(vault1.add_credential(create_sample_input("Original", "u", "p")).has_value());
    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault1, "Password123").has_value());

    Vault vault2;
    ASSERT_TRUE(vault2.add_credential(create_sample_input("Replaced", "u2", "p2")).has_value());
    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault2, "Password123").has_value());

    auto loaded = VaultStorage::load_vault(vault_path, "Password123");
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded.value().size(), 1u);
    EXPECT_EQ(loaded.value().list_credentials()[0].service(), "Replaced");
}

TEST(VaultStorageTest, CleansUpTemporaryFilesAfterSave) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "cleanup_test.vault";

    Vault vault;
    ASSERT_TRUE(vault.add_credential(create_sample_input()).has_value());
    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault, "Pass").has_value());

    for (const auto& entry : std::filesystem::directory_iterator(temp_dir.path())) {
        EXPECT_NE(entry.path().extension(), ".tmp");
    }
}

TEST(VaultStorageTest, SaveToNonExistentDirectoryFailsSafely) {
    const std::filesystem::path invalid_path = "Z:/NonExistentPath_xyz123/vault.dat";
    Vault vault;
    auto save_res = VaultStorage::save_vault(invalid_path, vault, "Password");
    EXPECT_FALSE(save_res.has_value());
    EXPECT_EQ(save_res.error().code, VaultErrorCode::FileWriteError);
}

TEST(VaultStorageTest, TruncatedVaultFileRejected) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "truncated.vault";

    Vault vault;
    ASSERT_TRUE(vault.add_credential(create_sample_input()).has_value());
    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault, "Password").has_value());

    // Truncate file by 10 bytes
    const auto full_size = std::filesystem::file_size(vault_path);
    std::filesystem::resize_file(vault_path, full_size - 10);

    auto load_res = VaultStorage::load_vault(vault_path, "Password");
    EXPECT_FALSE(load_res.has_value());
    EXPECT_EQ(load_res.error().code, VaultErrorCode::CorruptedVault);
}

TEST(VaultStorageTest, TrailingBytesInVaultFileRejected) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "trailing.vault";

    Vault vault;
    ASSERT_TRUE(vault.add_credential(create_sample_input()).has_value());
    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault, "Password").has_value());

    // Append unexpected trailing bytes
    std::ofstream out(vault_path, std::ios::binary | std::ios::app);
    out.write("EXTRADATA", 9);
    out.close();

    auto load_res = VaultStorage::load_vault(vault_path, "Password");
    EXPECT_FALSE(load_res.has_value());
    EXPECT_EQ(load_res.error().code, VaultErrorCode::CorruptedVault);
}

// ============================================================================
// 4. Security Boundaries Tests
// ============================================================================

TEST(VaultStorageTest, RawVaultFileContainsNoPlaintextCredentials) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "confidential.vault";

    const std::string sensitive_service = "SuperTopSecretBank";
    const std::string sensitive_username = "alice_covert_ops";
    const std::string sensitive_password = "UltraClassifiedPassword999!";
    const std::string sensitive_notes = "Highly classified internal notes and access codes.";

    Vault vault;
    ASSERT_TRUE(vault
                    .add_credential({sensitive_service, sensitive_username, sensitive_password,
                                     "https://covert.bank.com", "Classified", sensitive_notes})
                    .has_value());

    ASSERT_TRUE(VaultStorage::save_vault(vault_path, vault, "MasterSecret123!").has_value());

    // Read entire raw file into byte vector
    std::ifstream file(vault_path, std::ios::binary);
    std::string raw_content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    file.close();

    EXPECT_EQ(raw_content.find(sensitive_service), std::string::npos);
    EXPECT_EQ(raw_content.find(sensitive_username), std::string::npos);
    EXPECT_EQ(raw_content.find(sensitive_password), std::string::npos);
    EXPECT_EQ(raw_content.find(sensitive_notes), std::string::npos);
}

TEST(VaultStorageTest, MaliciousLargePayloadLengthRejectedBeforeAllocation) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "gigantic.vault";

    VaultHeader header;
    header.ciphertext_length = 500ULL * 1024 * 1024;  // Claims 500 MiB ciphertext
    const auto serialized = header.serialize_header();

    std::ofstream out(vault_path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(serialized.data()), serialized.size());
    out.close();

    auto inspect_res = VaultStorage::inspect_header(vault_path);
    EXPECT_FALSE(inspect_res.has_value());
    EXPECT_EQ(inspect_res.error().code, VaultErrorCode::ResourceLimitExceeded);
}

}  // namespace password_manager::core::test
