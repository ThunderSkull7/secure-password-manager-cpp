#include <gtest/gtest.h>

#include "models/Credential.hpp"

namespace password_manager::testing {

TEST(CredentialModelTest, CorrectInitializationWithAllFields) {
    using password_manager::models::Credential;

    const Credential cred(42, "example.com", "user@example.com", "SecretP@ss123",
                          "https://example.com/login", "Work", "Urgent key", "2026-11-02T10:00:00Z",
                          "2026-11-02T10:00:00Z");

    EXPECT_EQ(cred.id(), 42);
    EXPECT_EQ(cred.service(), "example.com");
    EXPECT_EQ(cred.username(), "user@example.com");
    EXPECT_EQ(cred.password(), "SecretP@ss123");
    EXPECT_EQ(cred.url(), "https://example.com/login");
    EXPECT_EQ(cred.category(), "Work");
    EXPECT_EQ(cred.notes(), "Urgent key");
    EXPECT_EQ(cred.created_at(), "2026-11-02T10:00:00Z");
    EXPECT_EQ(cred.updated_at(), "2026-11-02T10:00:00Z");
}

TEST(CredentialModelTest, HandlesEmptyOptionalFields) {
    using password_manager::models::Credential;

    const Credential cred(1, "service-only", "", "somePassword", "", "", "", "2026-11-02T12:00:00Z",
                          "2026-11-02T12:00:00Z");

    EXPECT_EQ(cred.id(), 1);
    EXPECT_EQ(cred.service(), "service-only");
    EXPECT_EQ(cred.username(), "");
    EXPECT_EQ(cred.password(), "somePassword");
    EXPECT_EQ(cred.url(), "");
    EXPECT_EQ(cred.category(), "");
    EXPECT_EQ(cred.notes(), "");
}

TEST(CredentialModelTest, UpdatePreservesIdAndCreatedAtWhileUpdatingFields) {
    using password_manager::models::Credential;
    using password_manager::models::CredentialInput;

    Credential cred(100, "OldService", "old_user", "old_pass", "https://old.org", "Personal",
                    "Old note", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");

    const CredentialInput newInput{.service = "NewService",
                                   .username = "new_user",
                                   .password = "new_pass!@#",
                                   .url = "https://new.org",
                                   .category = "Finance",
                                   .notes = "New note updated"};

    cred.update(newInput, "2026-11-02T14:00:00Z");

    // Invariants: ID and created_at MUST be preserved
    EXPECT_EQ(cred.id(), 100);
    EXPECT_EQ(cred.created_at(), "2026-01-01T00:00:00Z");

    // Mutated fields
    EXPECT_EQ(cred.service(), "NewService");
    EXPECT_EQ(cred.username(), "new_user");
    EXPECT_EQ(cred.password(), "new_pass!@#");
    EXPECT_EQ(cred.url(), "https://new.org");
    EXPECT_EQ(cred.category(), "Finance");
    EXPECT_EQ(cred.notes(), "New note updated");
    EXPECT_EQ(cred.updated_at(), "2026-11-02T14:00:00Z");
}

}  // namespace password_manager::testing
