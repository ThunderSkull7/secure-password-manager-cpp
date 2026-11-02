#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>

#include "core/Vault.hpp"

namespace password_manager::testing {

class TestClock final : public core::IClock {
  public:
    explicit TestClock(std::chrono::system_clock::time_point start_time)
        : current_time_(start_time) {}

    [[nodiscard]] std::chrono::system_clock::time_point now() const override {
        return current_time_;
    }

    void advance_seconds(int seconds) { current_time_ += std::chrono::seconds(seconds); }

  private:
    std::chrono::system_clock::time_point current_time_;
};

class VaultTest : public ::testing::Test {
  protected:
    void SetUp() override {
        std::tm start_tm{};
        start_tm.tm_year = 2026 - 1900;
        start_tm.tm_mon = 10;  // November
        start_tm.tm_mday = 2;
        start_tm.tm_hour = 12;
        start_tm.tm_min = 0;
        start_tm.tm_sec = 0;

#if defined(_WIN32) || defined(_WIN64)
        const std::time_t tt = _mkgmtime(&start_tm);
#else
        const std::time_t tt = timegm(&start_tm);
#endif

        clock_ = std::make_shared<TestClock>(std::chrono::system_clock::from_time_t(tt));
        vault_ = std::make_unique<core::Vault>(clock_);
    }

    std::shared_ptr<TestClock> clock_;
    std::unique_ptr<core::Vault> vault_;
};

// ----------------------------------------------------------------------------
// Add Credential Tests
// ----------------------------------------------------------------------------

TEST_F(VaultTest, AddCredentialSuccessfullyAssignsIdAndTimestamps) {
    const models::CredentialInput input{.service = "GitHub",
                                        .username = "user1",
                                        .password = "Secr3t!P@ss",
                                        .url = "https://github.com",
                                        .category = "Dev",
                                        .notes = "Main account"};

    const auto result = vault_->add_credential(input);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 1);
    EXPECT_EQ(vault_->size(), 1u);
    EXPECT_FALSE(vault_->empty());

    const auto get_res = vault_->get_credential(1);
    ASSERT_TRUE(get_res.has_value());
    const auto& cred = get_res.value();
    EXPECT_EQ(cred.id(), 1);
    EXPECT_EQ(cred.service(), "GitHub");
    EXPECT_EQ(cred.username(), "user1");
    EXPECT_EQ(cred.password(), "Secr3t!P@ss");
    EXPECT_EQ(cred.created_at(), "2026-11-02T12:00:00Z");
    EXPECT_EQ(cred.updated_at(), "2026-11-02T12:00:00Z");
}

TEST_F(VaultTest, AddMultipleCredentialsGeneratesMonotonicallyIncreasingUniqueIds) {
    const models::CredentialInput input1{.service = "ServiceA", .username = "u1", .password = "p1"};
    const models::CredentialInput input2{.service = "ServiceB", .username = "u2", .password = "p2"};
    const models::CredentialInput input3{.service = "ServiceC", .username = "u3", .password = "p3"};

    const auto id1 = vault_->add_credential(input1);
    const auto id2 = vault_->add_credential(input2);
    const auto id3 = vault_->add_credential(input3);

    ASSERT_TRUE(id1.has_value());
    ASSERT_TRUE(id2.has_value());
    ASSERT_TRUE(id3.has_value());

    EXPECT_EQ(id1.value(), 1);
    EXPECT_EQ(id2.value(), 2);
    EXPECT_EQ(id3.value(), 3);
    EXPECT_EQ(vault_->size(), 3u);
}

TEST_F(VaultTest, AddMultipleAccountsForSameServiceIsPermitted) {
    const models::CredentialInput personal{
        .service = "Google", .username = "me@gmail.com", .password = "pass1"};
    const models::CredentialInput work{
        .service = "Google", .username = "work@company.com", .password = "pass2"};

    const auto id1 = vault_->add_credential(personal);
    const auto id2 = vault_->add_credential(work);

    EXPECT_TRUE(id1.has_value());
    EXPECT_TRUE(id2.has_value());
    EXPECT_NE(id1.value(), id2.value());
    EXPECT_EQ(vault_->size(), 2u);
}

TEST_F(VaultTest, AddRejectsInvalidInputs) {
    // Empty service
    const models::CredentialInput empty_srv{.service = "", .username = "u", .password = "p"};
    EXPECT_EQ(vault_->add_credential(empty_srv).error().code,
              core::VaultErrorCode::ValidationError);

    // Whitespace-only service
    const models::CredentialInput ws_srv{.service = "   \t\n ", .username = "u", .password = "p"};
    EXPECT_EQ(vault_->add_credential(ws_srv).error().code, core::VaultErrorCode::ValidationError);

    // Empty password
    const models::CredentialInput empty_pwd{.service = "Service", .username = "u", .password = ""};
    EXPECT_EQ(vault_->add_credential(empty_pwd).error().code,
              core::VaultErrorCode::ValidationError);

    EXPECT_EQ(vault_->size(), 0u);
}

TEST_F(VaultTest, DuplicateDetectionWarnsWithoutPreventingAddition) {
    const models::CredentialInput account1{
        .service = "Bitbucket", .username = "DevUser", .password = "pwd1"};
    vault_->add_credential(account1);

    // Exact duplicate
    const models::CredentialInput duplicate_input{
        .service = "bitbucket", .username = "devuser", .password = "pwd2"};

    EXPECT_TRUE(vault_->has_duplicate("Bitbucket", "DevUser"));
    EXPECT_TRUE(vault_->has_duplicate("BITBUCKET", "devuser"));
    EXPECT_FALSE(vault_->has_duplicate("Bitbucket", "OtherUser"));

    const auto dup_ids = vault_->find_duplicates(duplicate_input);
    ASSERT_EQ(dup_ids.size(), 1u);
    EXPECT_EQ(dup_ids[0], 1);

    // Adding duplicate succeeds because users may legitimately have multiple accounts
    const auto res2 = vault_->add_credential(duplicate_input);
    EXPECT_TRUE(res2.has_value());
    EXPECT_EQ(vault_->size(), 2u);
}

// ----------------------------------------------------------------------------
// Retrieve Credential Tests
// ----------------------------------------------------------------------------

TEST_F(VaultTest, RetrieveExistingCredentialSucceedsWithoutModifyingVault) {
    const models::CredentialInput input{.service = "GitLab", .username = "u", .password = "p"};
    const auto add_res = vault_->add_credential(input);
    ASSERT_TRUE(add_res.has_value());

    const auto get_res = vault_->get_credential(add_res.value());
    ASSERT_TRUE(get_res.has_value());
    EXPECT_EQ(get_res.value().service(), "GitLab");
    EXPECT_EQ(vault_->size(), 1u);
}

TEST_F(VaultTest, RetrieveMissingCredentialReturnsNotFoundError) {
    const auto get_res = vault_->get_credential(999);
    ASSERT_FALSE(get_res.has_value());
    EXPECT_EQ(get_res.error().code, core::VaultErrorCode::NotFound);
}

// ----------------------------------------------------------------------------
// Update Credential Tests
// ----------------------------------------------------------------------------

TEST_F(VaultTest, UpdateCredentialPreservesIdAndCreationTimeWhileUpdatingModificationTime) {
    const models::CredentialInput initial{.service = "AWS",
                                          .username = "admin",
                                          .password = "init_pwd",
                                          .url = "https://aws.amazon.com",
                                          .category = "Cloud",
                                          .notes = "Initial notes"};

    const auto add_res = vault_->add_credential(initial);
    ASSERT_TRUE(add_res.has_value());
    const auto id = add_res.value();

    // Advance clock by 30 seconds
    clock_->advance_seconds(30);

    const models::CredentialInput replacement{.service = "AWS Cloud",
                                              .username = "admin_v2",
                                              .password = "updated_pwd!#$",
                                              .url = "https://signin.aws.amazon.com",
                                              .category = "Infrastructure",
                                              .notes = "Updated notes"};

    const auto update_res = vault_->update_credential(id, replacement);
    ASSERT_TRUE(update_res.has_value());

    const auto get_res = vault_->get_credential(id);
    ASSERT_TRUE(get_res.has_value());
    const auto& cred = get_res.value();

    EXPECT_EQ(cred.id(), id);
    EXPECT_EQ(cred.service(), "AWS Cloud");
    EXPECT_EQ(cred.username(), "admin_v2");
    EXPECT_EQ(cred.password(), "updated_pwd!#$");
    EXPECT_EQ(cred.url(), "https://signin.aws.amazon.com");
    EXPECT_EQ(cred.category(), "Infrastructure");
    EXPECT_EQ(cred.notes(), "Updated notes");
    EXPECT_EQ(cred.created_at(), "2026-11-02T12:00:00Z");
    EXPECT_EQ(cred.updated_at(), "2026-11-02T12:00:30Z");
}

TEST_F(VaultTest, UpdateCanClearOptionalFields) {
    const models::CredentialInput initial{.service = "ServiceWithOptionals",
                                          .username = "user",
                                          .password = "pwd",
                                          .url = "https://example.com",
                                          .category = "Cat",
                                          .notes = "Note"};

    const auto id = vault_->add_credential(initial).value();

    const models::CredentialInput cleared{.service = "ServiceWithOptionals",
                                          .username = "",
                                          .password = "pwd",
                                          .url = "",
                                          .category = "",
                                          .notes = ""};

    EXPECT_TRUE(vault_->update_credential(id, cleared).has_value());

    const auto cred = vault_->get_credential(id).value();
    EXPECT_EQ(cred.username(), "");
    EXPECT_EQ(cred.url(), "");
    EXPECT_EQ(cred.category(), "");
    EXPECT_EQ(cred.notes(), "");
}

TEST_F(VaultTest, UpdateRejectsMissingId) {
    const models::CredentialInput replacement{.service = "S", .username = "u", .password = "p"};
    const auto res = vault_->update_credential(404, replacement);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, core::VaultErrorCode::NotFound);
}

TEST_F(VaultTest, UpdateWithInvalidDataIsAtomicAndLeavesOriginalIntact) {
    const models::CredentialInput original{
        .service = "OriginalService", .username = "orig_user", .password = "orig_pass"};

    const auto id = vault_->add_credential(original).value();

    // Invalid replacement: empty password
    const models::CredentialInput invalid_input{
        .service = "NewService", .username = "new_user", .password = ""};

    const auto res = vault_->update_credential(id, invalid_input);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, core::VaultErrorCode::ValidationError);

    // Verify original record is unchanged
    const auto cred = vault_->get_credential(id).value();
    EXPECT_EQ(cred.service(), "OriginalService");
    EXPECT_EQ(cred.username(), "orig_user");
    EXPECT_EQ(cred.password(), "orig_pass");
}

// ----------------------------------------------------------------------------
// Delete Credential Tests
// ----------------------------------------------------------------------------

TEST_F(VaultTest, DeleteExistingCredentialSucceedsAndDoesNotAffectOthers) {
    const auto id1 =
        vault_->add_credential({.service = "S1", .username = "u1", .password = "p1"}).value();
    const auto id2 =
        vault_->add_credential({.service = "S2", .username = "u2", .password = "p2"}).value();

    EXPECT_TRUE(vault_->delete_credential(id1).has_value());
    EXPECT_EQ(vault_->size(), 1u);

    // id1 no longer exists
    EXPECT_EQ(vault_->get_credential(id1).error().code, core::VaultErrorCode::NotFound);

    // id2 still exists and is unaffected
    const auto cred2 = vault_->get_credential(id2);
    ASSERT_TRUE(cred2.has_value());
    EXPECT_EQ(cred2.value().service(), "S2");

    // Repeated deletion returns NotFound
    EXPECT_EQ(vault_->delete_credential(id1).error().code, core::VaultErrorCode::NotFound);
}

TEST_F(VaultTest, DeletionDoesNotCauseIdCollisionForSubsequentAdds) {
    const auto id1 =
        vault_->add_credential({.service = "S1", .username = "u1", .password = "p1"}).value();
    EXPECT_EQ(id1, 1);

    EXPECT_TRUE(vault_->delete_credential(id1).has_value());
    EXPECT_TRUE(vault_->empty());

    // Next added credential must get ID 2, never reuse ID 1
    const auto id2 =
        vault_->add_credential({.service = "S2", .username = "u2", .password = "p2"}).value();
    EXPECT_EQ(id2, 2);
}

// ----------------------------------------------------------------------------
// List Credentials Tests
// ----------------------------------------------------------------------------

TEST_F(VaultTest, ListCredentialsReturnsEmptyVectorWhenVaultIsEmpty) {
    EXPECT_TRUE(vault_->list_credentials().empty());
}

TEST_F(VaultTest, ListCredentialsReturnsAllItemsInDeterministicAscendingIdOrder) {
    vault_->add_credential({.service = "Gamma", .username = "u", .password = "p"});
    vault_->add_credential({.service = "Alpha", .username = "u", .password = "p"});
    vault_->add_credential({.service = "Beta", .username = "u", .password = "p"});

    const auto list = vault_->list_credentials();
    ASSERT_EQ(list.size(), 3u);
    EXPECT_EQ(list[0].id(), 1);
    EXPECT_EQ(list[0].service(), "Gamma");
    EXPECT_EQ(list[1].id(), 2);
    EXPECT_EQ(list[1].service(), "Alpha");
    EXPECT_EQ(list[2].id(), 3);
    EXPECT_EQ(list[2].service(), "Beta");

    // Listing must not modify vault
    EXPECT_EQ(vault_->size(), 3u);
}

// ----------------------------------------------------------------------------
// Search Credentials Tests
// ----------------------------------------------------------------------------

TEST_F(VaultTest, SearchCredentialsFindsAcrossAllNonSecretFields) {
    vault_->add_credential({.service = "ProtonMail",
                            .username = "secops@proton.me",
                            .password = "super_secret_alpha",
                            .url = "https://mail.proton.me",
                            .category = "Communications",
                            .notes = "Encrypted email inbox"});

    vault_->add_credential({.service = "DigitalOcean",
                            .username = "root",
                            .password = "super_secret_beta",
                            .url = "https://cloud.digitalocean.com",
                            .category = "Server",
                            .notes = "Production droplet"});

    // 1. Search by service (case-insensitive partial)
    auto results = vault_->search_credentials("proton");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].service(), "ProtonMail");

    // 2. Search by username
    results = vault_->search_credentials("secops");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].username(), "secops@proton.me");

    // 3. Search by URL
    results = vault_->search_credentials("digitalocean.com");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].service(), "DigitalOcean");

    // 4. Search by Category
    results = vault_->search_credentials("COMMUNICATIONS");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].category(), "Communications");

    // 5. Search by Notes
    results = vault_->search_credentials("droplet");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].notes(), "Production droplet");

    // 6. Non-matching query returns empty vector
    EXPECT_TRUE(vault_->search_credentials("NonExistentTerm").empty());

    // 7. Empty or whitespace query returns empty vector
    EXPECT_TRUE(vault_->search_credentials("").empty());
    EXPECT_TRUE(vault_->search_credentials("   \t  ").empty());

    // 8. CRITICAL: Passwords are NEVER searched!
    EXPECT_TRUE(vault_->search_credentials("super_secret_alpha").empty());
    EXPECT_TRUE(vault_->search_credentials("secret").empty());
}

}  // namespace password_manager::testing
