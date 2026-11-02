#include <gtest/gtest.h>

#include "core/CredentialValidator.hpp"

namespace password_manager::testing {

TEST(CredentialValidatorTest, ValidInputSucceedsAndNormalizes) {
    using core::CredentialValidator;
    using models::CredentialInput;

    const CredentialInput input{.service = "   GitHub   ",
                                .username = "  octocat@example.com  ",
                                .password = "  P@ssw0rd with spaces and !@#$%^&*()_+  ",
                                .url = "   https://github.com/login   ",
                                .category = "  Developer  ",
                                .notes = "Primary dev account"};

    const auto result = CredentialValidator::validate(input);
    EXPECT_TRUE(result.is_valid);
    EXPECT_TRUE(result.error_message.empty());

    // Normalized expectations
    EXPECT_EQ(result.normalized_input.service, "GitHub");
    EXPECT_EQ(result.normalized_input.username, "octocat@example.com");
    // CRITICAL: Password must NOT be trimmed!
    EXPECT_EQ(result.normalized_input.password, "  P@ssw0rd with spaces and !@#$%^&*()_+  ");
    EXPECT_EQ(result.normalized_input.url, "https://github.com/login");
    EXPECT_EQ(result.normalized_input.category, "Developer");
    EXPECT_EQ(result.normalized_input.notes, "Primary dev account");
}

TEST(CredentialValidatorTest, RejectsEmptyOrWhitespaceService) {
    using core::CredentialValidator;
    using models::CredentialInput;

    CredentialInput input{.service = "",
                          .username = "user",
                          .password = "valid_password",
                          .url = "",
                          .category = "",
                          .notes = ""};

    EXPECT_FALSE(CredentialValidator::validate(input).is_valid);

    input.service = "    \t \r \n  ";
    EXPECT_FALSE(CredentialValidator::validate(input).is_valid);
}

TEST(CredentialValidatorTest, RejectsEmptyPassword) {
    using core::CredentialValidator;
    using models::CredentialInput;

    const CredentialInput input{.service = "ValidService",
                                .username = "user",
                                .password = "",
                                .url = "",
                                .category = "",
                                .notes = ""};

    EXPECT_FALSE(CredentialValidator::validate(input).is_valid);
}

TEST(CredentialValidatorTest, AcceptsComplexPasswordsWithSymbolsSpacesAndUnicode) {
    using core::CredentialValidator;
    using models::CredentialInput;

    const CredentialInput input{.service = "Service",
                                .username = "user",
                                .password = "🔒 P@ss w0rd with spaces & 🔑 utf8 characters €£¥! 🚀",
                                .url = "",
                                .category = "",
                                .notes = ""};

    const auto result = CredentialValidator::validate(input);
    EXPECT_TRUE(result.is_valid);
    EXPECT_EQ(result.normalized_input.password,
              "🔒 P@ss w0rd with spaces & 🔑 utf8 characters €£¥! 🚀");
}

TEST(CredentialValidatorTest, RejectsExcessivelyLongFields) {
    using core::CredentialValidator;
    using models::CredentialInput;

    // Service > 256 chars
    CredentialInput input{.service = std::string(CredentialValidator::MAX_SERVICE_LENGTH + 1, 'a'),
                          .username = "user",
                          .password = "pass",
                          .url = "",
                          .category = "",
                          .notes = ""};
    EXPECT_FALSE(CredentialValidator::validate(input).is_valid);

    // Password > 4096 chars
    input.service = "Service";
    input.password = std::string(CredentialValidator::MAX_PASSWORD_LENGTH + 1, 'x');
    EXPECT_FALSE(CredentialValidator::validate(input).is_valid);

    // Username > 256 chars
    input.password = "pass";
    input.username = std::string(CredentialValidator::MAX_USERNAME_LENGTH + 1, 'u');
    EXPECT_FALSE(CredentialValidator::validate(input).is_valid);

    // Category > 128 chars
    input.username = "user";
    input.category = std::string(CredentialValidator::MAX_CATEGORY_LENGTH + 1, 'c');
    EXPECT_FALSE(CredentialValidator::validate(input).is_valid);

    // Notes > 65536 chars
    input.category = "cat";
    input.notes = std::string(CredentialValidator::MAX_NOTES_LENGTH + 1, 'n');
    EXPECT_FALSE(CredentialValidator::validate(input).is_valid);
}

TEST(CredentialValidatorTest, ValidatesUrlsCorrectly) {
    using core::CredentialValidator;

    // Valid URLs
    EXPECT_TRUE(CredentialValidator::is_valid_url("http://example.com"));
    EXPECT_TRUE(CredentialValidator::is_valid_url("https://sub.domain.org/path?q=1&v=2#anchor"));
    EXPECT_TRUE(CredentialValidator::is_valid_url("ftp://files.example.com:21/dump"));

    // Invalid URLs
    EXPECT_FALSE(CredentialValidator::is_valid_url(""));
    EXPECT_FALSE(CredentialValidator::is_valid_url("not_a_url"));
    EXPECT_FALSE(CredentialValidator::is_valid_url("http://"));
    EXPECT_FALSE(CredentialValidator::is_valid_url("https://"));
    EXPECT_FALSE(CredentialValidator::is_valid_url("://example.com"));
    EXPECT_FALSE(CredentialValidator::is_valid_url("https:// space.com"));
    EXPECT_FALSE(CredentialValidator::is_valid_url("123://numeric-scheme"));
}

}  // namespace password_manager::testing
