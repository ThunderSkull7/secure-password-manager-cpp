#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

#include "cli/Console.hpp"
#include "core/CryptoService.hpp"
#include "core/SecureKey.hpp"
#include "core/Timestamp.hpp"
#include "core/Vault.hpp"
#include "core/VaultFileFormat.hpp"
#include "core/VaultStorage.hpp"

namespace password_manager::cli {

class PasswordManagerApp {
  public:
    explicit PasswordManagerApp(
        std::filesystem::path vault_path = "vault.dat", std::istream& in = std::cin,
        std::ostream& out = std::cout,
        std::shared_ptr<core::IClock> clock = std::make_shared<core::SystemClock>());

    /**
     * @brief Executes the main application lifecycle loop.
     * @return Exit code (0 for normal termination).
     */
    int run();

    [[nodiscard]] bool is_unlocked() const noexcept { return is_unlocked_; }
    [[nodiscard]] bool has_unsaved_changes() const noexcept { return has_unsaved_changes_; }
    [[nodiscard]] const std::filesystem::path& vault_path() const noexcept { return vault_path_; }

  private:
    bool initialize_or_unlock();
    bool create_vault_workflow();
    bool unlock_vault_workflow();

    void run_main_menu();

    // Menu handlers
    void handle_add_credential();
    void handle_view_all_credentials();
    void handle_search_credentials();
    void handle_view_credential_details();
    void handle_edit_credential();
    void handle_delete_credential();
    void handle_generate_password();
    void handle_save_vault();
    void handle_lock_vault();
    void handle_exit();

    // Helper workflows
    bool prompt_unsaved_changes(std::string_view action_name);
    std::string prompt_password_with_generate_option(std::string_view prompt_text,
                                                     bool allow_empty_to_keep = false);

    std::filesystem::path vault_path_;
    Console console_;
    std::shared_ptr<core::IClock> clock_;
    std::unique_ptr<core::Vault> vault_;
    core::SecureKey session_key_;
    core::VaultHeader vault_header_;
    bool is_unlocked_{false};
    bool has_unsaved_changes_{false};
    bool should_exit_{false};
};

}  // namespace password_manager::cli
