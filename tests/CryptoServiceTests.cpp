#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "core/CryptoService.hpp"

namespace password_manager::testing {

class CryptoServiceTest : public ::testing::Test {
  protected:
    core::CryptoService crypto;
};

// ----------------------------------------------------------------------------
// A. Salt Generation Tests
// ----------------------------------------------------------------------------

TEST_F(CryptoServiceTest, GenerateSaltProducesCorrectSizeAndVaryingBytes) {
    const auto salt1 = crypto.generate_salt();
    const auto salt2 = crypto.generate_salt();

    ASSERT_TRUE(salt1.has_value());
    ASSERT_TRUE(salt2.has_value());

    EXPECT_EQ(salt1.value().size(), core::CryptoConstants::SALT_BYTES);
    EXPECT_EQ(salt2.value().size(), core::CryptoConstants::SALT_BYTES);

    // Two random salts should not be identical
    EXPECT_NE(salt1.value(), salt2.value());
}

// ----------------------------------------------------------------------------
// B. Key Derivation (Argon2id) Tests
// ----------------------------------------------------------------------------

TEST_F(CryptoServiceTest, DeriveKeySucceedsWithValidInputs) {
    const auto salt = crypto.generate_salt();
    ASSERT_TRUE(salt.has_value());

    const auto key_res = crypto.derive_key("CorrectHorseBatteryStaple", salt.value());
    ASSERT_TRUE(key_res.has_value());
    EXPECT_TRUE(key_res.value().is_valid());
    EXPECT_EQ(key_res.value().size(), core::CryptoConstants::KEY_BYTES);
}

TEST_F(CryptoServiceTest, DeriveKeyIsDeterministicForIdenticalInputs) {
    const auto salt = crypto.generate_salt();
    ASSERT_TRUE(salt.has_value());

    const auto key1 = crypto.derive_key("MasterSecret123!", salt.value());
    const auto key2 = crypto.derive_key("MasterSecret123!", salt.value());

    ASSERT_TRUE(key1.has_value());
    ASSERT_TRUE(key2.has_value());

    EXPECT_EQ(key1.value().as_span().size(), key2.value().as_span().size());
    EXPECT_EQ(
        std::memcmp(key1.value().data(), key2.value().data(), core::CryptoConstants::KEY_BYTES), 0);
}

TEST_F(CryptoServiceTest, DifferentPasswordsYieldDifferentKeys) {
    const auto salt = crypto.generate_salt();
    ASSERT_TRUE(salt.has_value());

    const auto key1 = crypto.derive_key("PasswordOne", salt.value());
    const auto key2 = crypto.derive_key("PasswordTwo", salt.value());

    ASSERT_TRUE(key1.has_value());
    ASSERT_TRUE(key2.has_value());

    EXPECT_NE(
        std::memcmp(key1.value().data(), key2.value().data(), core::CryptoConstants::KEY_BYTES), 0);
}

TEST_F(CryptoServiceTest, DifferentSaltsYieldDifferentKeys) {
    const auto salt1 = crypto.generate_salt();
    const auto salt2 = crypto.generate_salt();
    ASSERT_TRUE(salt1.has_value());
    ASSERT_TRUE(salt2.has_value());

    const auto key1 = crypto.derive_key("SamePassword", salt1.value());
    const auto key2 = crypto.derive_key("SamePassword", salt2.value());

    ASSERT_TRUE(key1.has_value());
    ASSERT_TRUE(key2.has_value());

    EXPECT_NE(
        std::memcmp(key1.value().data(), key2.value().data(), core::CryptoConstants::KEY_BYTES), 0);
}

TEST_F(CryptoServiceTest, DeriveKeyRejectsEmptyMasterPassword) {
    const auto salt = crypto.generate_salt();
    ASSERT_TRUE(salt.has_value());

    const auto res = crypto.derive_key("", salt.value());
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, core::VaultErrorCode::ValidationError);
}

TEST_F(CryptoServiceTest, DeriveKeyRejectsInvalidSaltLength) {
    std::array<unsigned char, 8> short_salt{};
    const auto res = crypto.derive_key("Password", short_salt);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, core::VaultErrorCode::InvalidSalt);
}

TEST_F(CryptoServiceTest, DeriveKeyRejectsInvalidKdfParameters) {
    const auto salt = crypto.generate_salt();
    ASSERT_TRUE(salt.has_value());

    // Wrong algorithm
    core::KdfParameters bad_algo = core::KdfParameters::interactive_default();
    bad_algo.algorithm = 9999;
    EXPECT_EQ(crypto.derive_key("pwd", salt.value(), bad_algo).error().code,
              core::VaultErrorCode::InvalidKdfParameters);

    // Ops limit too low
    core::KdfParameters bad_ops = core::KdfParameters::interactive_default();
    bad_ops.ops_limit = crypto_pwhash_OPSLIMIT_MIN - 1;
    EXPECT_EQ(crypto.derive_key("pwd", salt.value(), bad_ops).error().code,
              core::VaultErrorCode::InvalidKdfParameters);

    // Memory limit too low
    core::KdfParameters bad_mem = core::KdfParameters::interactive_default();
    bad_mem.memory_limit = crypto_pwhash_MEMLIMIT_MIN - 1;
    EXPECT_EQ(crypto.derive_key("pwd", salt.value(), bad_mem).error().code,
              core::VaultErrorCode::InvalidKdfParameters);
}

// ----------------------------------------------------------------------------
// C. Encryption Tests
// ----------------------------------------------------------------------------

TEST_F(CryptoServiceTest, EncryptProducesExpectedCiphertextWithFreshNonce) {
    const auto salt = crypto.generate_salt().value();
    const auto key = crypto.derive_key("password", salt).value();

    const std::string plaintext = "Confidential vault record 42";
    const auto p_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());

    const auto enc1 = crypto.encrypt(key, p_span);
    const auto enc2 = crypto.encrypt(key, p_span);

    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());

    // Ciphertext must include the 16-byte Poly1305 authentication tag
    EXPECT_EQ(enc1.value().ciphertext.size(), plaintext.size() + core::CryptoConstants::TAG_BYTES);
    EXPECT_EQ(enc2.value().ciphertext.size(), plaintext.size() + core::CryptoConstants::TAG_BYTES);

    // Nonces must be fresh (random 24 bytes) for every encryption
    EXPECT_NE(enc1.value().nonce, enc2.value().nonce);
    EXPECT_NE(enc1.value().ciphertext, enc2.value().ciphertext);
}

TEST_F(CryptoServiceTest, EncryptEmptyPlaintextYieldsTagOnly) {
    const auto salt = crypto.generate_salt().value();
    const auto key = crypto.derive_key("password", salt).value();

    const auto enc = crypto.encrypt(key, {});
    ASSERT_TRUE(enc.has_value());
    EXPECT_EQ(enc.value().ciphertext.size(), core::CryptoConstants::TAG_BYTES);
}

TEST_F(CryptoServiceTest, EncryptRejectsInvalidKey) {
    core::SecureKey invalid_key;
    const std::string plaintext = "data";
    const auto p_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());

    const auto enc = crypto.encrypt(invalid_key, p_span);
    ASSERT_FALSE(enc.has_value());
    EXPECT_EQ(enc.error().code, core::VaultErrorCode::InvalidKey);
}

// ----------------------------------------------------------------------------
// D. Decryption & Authentication Tests
// ----------------------------------------------------------------------------

TEST_F(CryptoServiceTest, DecryptRestoresOriginalPlaintextWithMatchingAad) {
    const auto salt = crypto.generate_salt().value();
    const auto key = crypto.derive_key("VaultMasterKey#1", salt).value();

    const std::string secret_payload = "Sensitive credential string with unicode: 🔑🔒 €100";
    const std::string aad_header = "VAULT_V1_METADATA_HEADER";

    const auto p_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(secret_payload.data()), secret_payload.size());
    const auto aad_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(aad_header.data()), aad_header.size());

    const auto enc = crypto.encrypt(key, p_span, aad_span);
    ASSERT_TRUE(enc.has_value());

    const auto dec = crypto.decrypt(key, enc.value(), aad_span);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(dec.value().to_string(), secret_payload);
}

TEST_F(CryptoServiceTest, DecryptEmptyPlaintextSucceeds) {
    const auto salt = crypto.generate_salt().value();
    const auto key = crypto.derive_key("password", salt).value();

    const auto enc = crypto.encrypt(key, {});
    ASSERT_TRUE(enc.has_value());

    const auto dec = crypto.decrypt(key, enc.value());
    ASSERT_TRUE(dec.has_value());
    EXPECT_TRUE(dec.value().empty());
}

TEST_F(CryptoServiceTest, DecryptFailsWithWrongKey) {
    const auto salt = crypto.generate_salt().value();
    const auto key_correct = crypto.derive_key("RightPassword", salt).value();
    const auto key_wrong = crypto.derive_key("WrongPassword", salt).value();

    const std::string payload = "Top secret data";
    const auto p_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());

    const auto enc = crypto.encrypt(key_correct, p_span).value();
    const auto dec = crypto.decrypt(key_wrong, enc);

    ASSERT_FALSE(dec.has_value());
    EXPECT_EQ(dec.error().code, core::VaultErrorCode::AuthenticationFailed);
}

TEST_F(CryptoServiceTest, DecryptFailsWhenCiphertextIsTampered) {
    const auto salt = crypto.generate_salt().value();
    const auto key = crypto.derive_key("password", salt).value();

    const std::string payload = "Financial assets and seed phrases";
    const auto p_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());

    auto enc = crypto.encrypt(key, p_span).value();

    // Flip a bit in the ciphertext
    enc.ciphertext[0] ^= 0x01;

    const auto dec = crypto.decrypt(key, enc);
    ASSERT_FALSE(dec.has_value());
    EXPECT_EQ(dec.error().code, core::VaultErrorCode::AuthenticationFailed);
}

TEST_F(CryptoServiceTest, DecryptFailsWhenNonceIsTampered) {
    const auto salt = crypto.generate_salt().value();
    const auto key = crypto.derive_key("password", salt).value();

    const std::string payload = "Important message";
    const auto p_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());

    auto enc = crypto.encrypt(key, p_span).value();

    // Flip a bit in the nonce
    enc.nonce[0] ^= 0x01;

    const auto dec = crypto.decrypt(key, enc);
    ASSERT_FALSE(dec.has_value());
    EXPECT_EQ(dec.error().code, core::VaultErrorCode::AuthenticationFailed);
}

TEST_F(CryptoServiceTest, DecryptFailsWhenAadIsTampered) {
    const auto salt = crypto.generate_salt().value();
    const auto key = crypto.derive_key("password", salt).value();

    const std::string payload = "Vault payload";
    const std::string aad_good = "HeaderV1";
    const std::string aad_tampered = "HeaderV2";

    const auto p_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    const auto aad_good_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(aad_good.data()), aad_good.size());
    const auto aad_bad_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(aad_tampered.data()), aad_tampered.size());

    const auto enc = crypto.encrypt(key, p_span, aad_good_span).value();
    const auto dec = crypto.decrypt(key, enc, aad_bad_span);

    ASSERT_FALSE(dec.has_value());
    EXPECT_EQ(dec.error().code, core::VaultErrorCode::AuthenticationFailed);
}

TEST_F(CryptoServiceTest, DecryptRejectsTruncatedCiphertextBelowTagSize) {
    const auto salt = crypto.generate_salt().value();
    const auto key = crypto.derive_key("password", salt).value();

    core::EncryptedMessage msg;
    msg.ciphertext.resize(core::CryptoConstants::TAG_BYTES - 1);  // Less than 16 bytes

    const auto dec = crypto.decrypt(key, msg);
    ASSERT_FALSE(dec.has_value());
    EXPECT_EQ(dec.error().code, core::VaultErrorCode::InvalidCiphertext);
}

// ----------------------------------------------------------------------------
// E. Large Payload Encryption / Decryption
// ----------------------------------------------------------------------------

TEST_F(CryptoServiceTest, LargePayloadRoundTripSucceeds) {
    const auto salt = crypto.generate_salt().value();
    const auto key = crypto.derive_key("password", salt).value();

    // 256 KiB representative large payload
    std::vector<unsigned char> large_payload(256 * 1024);
    for (std::size_t i = 0; i < large_payload.size(); ++i) {
        large_payload[i] = static_cast<unsigned char>(i & 0xFF);
    }

    const auto enc = crypto.encrypt(key, large_payload);
    ASSERT_TRUE(enc.has_value());

    const auto dec = crypto.decrypt(key, enc.value());
    ASSERT_TRUE(dec.has_value());

    const auto dec_span = dec.value().as_span();
    EXPECT_EQ(dec_span.size(), large_payload.size());
    EXPECT_EQ(std::memcmp(dec_span.data(), large_payload.data(), large_payload.size()), 0);
}

}  // namespace password_manager::testing
