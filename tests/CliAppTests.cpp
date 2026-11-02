#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <sstream>
#include <string>

#include "cli/Console.hpp"
#include "cli/PasswordManagerApp.hpp"
#include "core/VaultStorage.hpp"

namespace password_manager::cli::test {

namespace {

class TempDirectoryGuard {
  public:
    TempDirectoryGuard() {
        std::error_code ec;
        path_ = std::filesystem::temp_directory_path() /
                ("spm_clitest_" +
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

}  // namespace

TEST(ConsoleTest, ReadLineTrimsCrAndReadsCorrectly) {
    std::stringstream in("hello world\r\nsecond line\n");
    std::stringstream out;
    Console console(in, out);
    console.set_interactive(false);

    EXPECT_EQ(console.read_line(), "hello world");
    EXPECT_EQ(console.read_line(), "second line");
}

TEST(ConsoleTest, ReadConfirmationHandlesDefaultsAndExplicitChoices) {
    std::stringstream in("\ny\nn\n");
    std::stringstream out;
    Console console(in, out);
    console.set_interactive(false);

    EXPECT_TRUE(console.read_confirmation("Prompt 1", true));
    EXPECT_TRUE(console.read_confirmation("Prompt 2", false));
    EXPECT_FALSE(console.read_confirmation("Prompt 3", true));
}

TEST(CliAppTest, FirstTimeVaultCreationWorkflow) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "new_vault.dat";

    // Inputs: master_password, confirm_password, exit choice (10)
    std::stringstream in("MyMasterPassword123!\nMyMasterPassword123!\n10\n");
    std::stringstream out;

    PasswordManagerApp app(vault_path, in, out);
    int code = app.run();
    EXPECT_EQ(code, 0);

    EXPECT_TRUE(std::filesystem::exists(vault_path));
    auto inspect_res = core::VaultStorage::inspect_header(vault_path);
    ASSERT_TRUE(inspect_res.has_value());
    EXPECT_EQ(inspect_res.value().version, 1u);
}

TEST(CliAppTest, CreationHandlesPasswordMismatchGracefully) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "mismatch.dat";

    // Inputs: pwd1, mismatch_pwd, pwd1, pwd1, exit (10)
    std::stringstream in("Pass1234!\nMismatch!\nPass1234!\nPass1234!\n10\n");
    std::stringstream out;

    PasswordManagerApp app(vault_path, in, out);
    int code = app.run();
    EXPECT_EQ(code, 0);

    EXPECT_TRUE(std::filesystem::exists(vault_path));
    std::string output = out.str();
    EXPECT_NE(output.find("Passwords do not match"), std::string::npos);
}

TEST(CliAppTest, ExistingVaultUnlockSucceedsWithCorrectPassword) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "unlock.dat";

    // 1. Create vault
    {
        std::stringstream in("VaultPassword123!\nVaultPassword123!\n10\n");
        std::stringstream out;
        PasswordManagerApp app(vault_path, in, out);
        app.run();
    }

    // 2. Unlock vault with correct password, then exit (10)
    {
        std::stringstream in("VaultPassword123!\n10\n");
        std::stringstream out;
        PasswordManagerApp app(vault_path, in, out);
        int code = app.run();
        EXPECT_EQ(code, 0);

        std::string output = out.str();
        EXPECT_NE(output.find("Vault unlocked successfully"), std::string::npos);
    }
}

TEST(CliAppTest, WrongPasswordRetryWorkflow) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "retry.dat";

    // 1. Create vault
    {
        std::stringstream in("CorrectMasterPassword!\nCorrectMasterPassword!\n10\n");
        std::stringstream out;
        PasswordManagerApp app(vault_path, in, out);
        app.run();
    }

    // 2. Feed wrong password, then correct password, then exit (10)
    {
        std::stringstream in("WrongPassword\nCorrectMasterPassword!\n10\n");
        std::stringstream out;
        PasswordManagerApp app(vault_path, in, out);
        int code = app.run();
        EXPECT_EQ(code, 0);

        std::string output = out.str();
        EXPECT_NE(output.find("Authentication failed"), std::string::npos);
        EXPECT_NE(output.find("Vault unlocked successfully"), std::string::npos);
    }
}

TEST(CliAppTest, AddViewSearchAndRevealCredentialWorkflow) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "ops.dat";

    // Creation: pwd, pwd
    // 1. Add credential:
    //    choice: 1
    //    service: GitHub
    //    username: alice
    //    pwd choice: T (manual)
    //    pwd: SecretPassword!
    //    url: https://github.com
    //    category: Dev
    //    notes: Work account
    // 2. View all: choice 2
    // 3. Search: choice 3, query: Git
    // 4. View details: choice 4, ID: 1, action: R (reveal), pause: \n
    // 5. Save: choice 8
    // 6. Exit: choice 10
    std::stringstream in(
        "MasterPwd123!\nMasterPwd123!\n"
        "1\nGitHub\nalice\nT\nSecretPassword!\nhttps://github.com\nDev\nWork account\n"
        "2\n"
        "3\nGit\n"
        "4\n1\nR\n\n"
        "8\n"
        "10\n");
    std::stringstream out;

    PasswordManagerApp app(vault_path, in, out);
    int code = app.run();
    EXPECT_EQ(code, 0);

    std::string output = out.str();
    EXPECT_NE(output.find("Credential added successfully"), std::string::npos);
    EXPECT_NE(output.find("GitHub"), std::string::npos);
    EXPECT_NE(output.find("alice"), std::string::npos);
    EXPECT_NE(output.find("Password: SecretPassword!"), std::string::npos);
    EXPECT_NE(output.find("Vault saved successfully"), std::string::npos);
}

TEST(CliAppTest, EditCredentialWorkflow) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "edit.dat";

    // Create, Add (ID 1), Edit (ID 1, change username to alice_updated, keep others), Save, Exit
    std::stringstream in(
        "MasterPwd123!\nMasterPwd123!\n"
        "1\nGitLab\nalice\nT\nSecret1!\n\n\n\n"
        "5\n1\n\nalice_updated\nn\n\n\n\n"
        "8\n"
        "10\n");
    std::stringstream out;

    PasswordManagerApp app(vault_path, in, out);
    int code = app.run();
    EXPECT_EQ(code, 0);

    std::string output = out.str();
    EXPECT_NE(output.find("Credential updated successfully"), std::string::npos);

    // Verify persistence
    auto load_res = core::VaultStorage::load_vault(vault_path, "MasterPwd123!");
    ASSERT_TRUE(load_res.has_value());
    auto cred = load_res.value().get_credential(1);
    ASSERT_TRUE(cred.has_value());
    EXPECT_EQ(cred.value().username(), "alice_updated");
}

TEST(CliAppTest, DeleteCredentialWorkflow) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "delete.dat";

    // Create, Add, Delete with confirmation 'y', View all, Save, Exit
    std::stringstream in(
        "MasterPwd123!\nMasterPwd123!\n"
        "1\nAWS\nalice\nT\nSecretAws!\n\n\n\n"
        "6\n1\ny\n"
        "2\n"
        "8\n"
        "10\n");
    std::stringstream out;

    PasswordManagerApp app(vault_path, in, out);
    int code = app.run();
    EXPECT_EQ(code, 0);

    std::string output = out.str();
    EXPECT_NE(output.find("Credential deleted successfully"), std::string::npos);
    EXPECT_NE(output.find("No credentials to display"), std::string::npos);
}

TEST(CliAppTest, StandalonePasswordGeneratorWorkflow) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "gen.dat";

    // Create, choice 7 (generator), len 20, default flags (\n, \n, \n, \n, \n), exit 10
    std::stringstream in(
        "MasterPwd123!\nMasterPwd123!\n"
        "7\n20\n\n\n\n\n\n"
        "10\n");
    std::stringstream out;

    PasswordManagerApp app(vault_path, in, out);
    int code = app.run();
    EXPECT_EQ(code, 0);

    std::string output = out.str();
    EXPECT_NE(output.find("Generated Password:"), std::string::npos);
}

TEST(CliAppTest, UnsavedChangesSavedPromptOnLockAndExit) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "unsaved.dat";

    // 1. Create vault, add credential, select Lock (9), answer 'y' to save, then quit ('q')
    {
        std::stringstream in(
            "MasterPwd123!\nMasterPwd123!\n"
            "1\nDiscord\nbob\nT\nDiscordPass!\n\n\n\n"
            "9\ny\n"
            "q\n");
        std::stringstream out;
        PasswordManagerApp app(vault_path, in, out);
        app.run();
    }

    // 2. Reopen vault in new app and verify Discord credential was saved
    {
        std::stringstream in("MasterPwd123!\n2\n10\n");
        std::stringstream out;
        PasswordManagerApp app(vault_path, in, out);
        app.run();

        std::string output = out.str();
        EXPECT_NE(output.find("Discord"), std::string::npos);
        EXPECT_NE(output.find("bob"), std::string::npos);
    }
}

TEST(CliAppTest, LockAndReunlockCycleWithinSameRun) {
    TempDirectoryGuard temp_dir;
    const auto vault_path = temp_dir.path() / "reunlock.dat";

    // 1. Create vault
    // 2. Add credential
    // 3. Lock vault (9, 'y' to save)
    // 4. In re-prompt for master password: type "MasterPwd123!"
    // 5. View all credentials (2)
    // 6. Exit (10)
    std::stringstream in(
        "MasterPwd123!\nMasterPwd123!\n"
        "1\nTwitter\nuser1\nT\nTweetSecret!\n\n\n\n"
        "9\ny\n"
        "MasterPwd123!\n"
        "2\n"
        "10\n");
    std::stringstream out;

    PasswordManagerApp app(vault_path, in, out);
    int code = app.run();
    EXPECT_EQ(code, 0);

    std::string output = out.str();
    EXPECT_NE(output.find("[🔒] Vault locked"), std::string::npos);
    EXPECT_NE(output.find("[🔓] Vault unlocked successfully"), std::string::npos);
    EXPECT_NE(output.find("Twitter"), std::string::npos);
}

}  // namespace password_manager::cli::test
