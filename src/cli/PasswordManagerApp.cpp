#include "cli/PasswordManagerApp.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

#include "core/CredentialValidator.hpp"
#include "core/PasswordGenerator.hpp"
#include "core/PasswordGeneratorConfig.hpp"
#include "ui/Banner.hpp"

namespace password_manager::cli {

namespace {

std::string truncate_field(std::string_view sv, std::size_t max_len = 22) {
    if (sv.size() <= max_len) {
        return std::string(sv);
    }
    if (max_len <= 3) {
        return std::string(sv.substr(0, max_len));
    }
    return std::string(sv.substr(0, max_len - 3)) + "...";
}

void print_credentials_table(Console& console, const std::vector<models::Credential>& creds) {
    if (creds.empty()) {
        console.println("[i] No credentials to display.");
        return;
    }

    console.println(
        "+------+------------------------+------------------------+------------------------+");
    console.println(
        "| ID   | Service                | Username               | Category               |");
    console.println(
        "+------+------------------------+------------------------+------------------------+");

    for (const auto& c : creds) {
        std::ostringstream oss;
        oss << "| " << std::left << std::setw(4) << c.id() << " | " << std::left << std::setw(22)
            << truncate_field(c.service()) << " | " << std::left << std::setw(22)
            << truncate_field(c.username()) << " | " << std::left << std::setw(22)
            << truncate_field(c.category()) << " |";
        console.println(oss.str());
    }

    console.println(
        "+------+------------------------+------------------------+------------------------+");
    console.println("Total: " + std::to_string(creds.size()) + " credential(s).");
}

}  // namespace

PasswordManagerApp::PasswordManagerApp(std::filesystem::path vault_path, std::istream& in,
                                       std::ostream& out, std::shared_ptr<core::IClock> clock)
    : vault_path_(std::move(vault_path)),
      console_(in, out),
      clock_(clock ? std::move(clock) : std::make_shared<core::SystemClock>()) {}

int PasswordManagerApp::run() {
    ui::display_welcome_banner(console_.out());

    while (!should_exit_) {
        if (!is_unlocked_) {
            if (!initialize_or_unlock()) {
                break;
            }
        }

        if (is_unlocked_) {
            run_main_menu();
        }
    }

    console_.println("[i] Exiting Secure Password Manager. Stay safe!");
    return 0;
}

bool PasswordManagerApp::initialize_or_unlock() {
    std::error_code ec;
    const bool exists = std::filesystem::exists(vault_path_, ec);

    if (!exists) {
        return create_vault_workflow();
    } else {
        return unlock_vault_workflow();
    }
}

bool PasswordManagerApp::create_vault_workflow() {
    console_.println();
    console_.println("========================================");
    console_.println("        NEW VAULT INITIALIZATION        ");
    console_.println("========================================");
    console_.println("No vault found at: " + vault_path_.string());
    console_.println("Create a strong master password to secure your local vault.");
    console_.println();

    while (true) {
        std::string pwd = console_.read_password("Enter new master password: ");
        if (pwd.empty()) {
            console_.println("[!] Master password cannot be empty. Please try again.");
            continue;
        }

        std::string confirm = console_.read_password("Confirm master password: ");
        if (pwd != confirm) {
            console_.println("[!] Passwords do not match. Please try again.");
            continue;
        }

        if (pwd.size() < 8) {
            console_.println(
                "[!] Advisory: Passwords with 12+ characters or passphrases offer superior "
                "security against offline attacks.");
        }

        auto new_vault = std::make_unique<core::Vault>(clock_);
        auto save_res = core::VaultStorage::save_vault(vault_path_, *new_vault, pwd);
        if (!save_res.has_value()) {
            console_.println("[!] Failed to create vault: " + save_res.error().message);
            return false;
        }

        auto hdr_res = core::VaultStorage::inspect_header(vault_path_);
        if (!hdr_res.has_value()) {
            console_.println("[!] Failed to verify created vault: " + hdr_res.error().message);
            return false;
        }

        core::CryptoService crypto;
        core::KdfParameters params{hdr_res.value().kdf_ops_limit,
                                   static_cast<std::size_t>(hdr_res.value().kdf_mem_limit),
                                   static_cast<int>(hdr_res.value().kdf_algorithm)};

        auto key_res = crypto.derive_key(pwd, hdr_res.value().salt, params);
        if (!key_res.has_value()) {
            console_.println("[!] Key derivation failed during creation.");
            return false;
        }

        session_key_ = std::move(key_res.value());
        vault_header_ = hdr_res.value();
        vault_ = std::move(new_vault);
        is_unlocked_ = true;
        has_unsaved_changes_ = false;

        console_.println("[✓] Encrypted vault created and unlocked successfully.");
        return true;
    }
}

bool PasswordManagerApp::unlock_vault_workflow() {
    auto hdr_res = core::VaultStorage::inspect_header(vault_path_);
    if (!hdr_res.has_value()) {
        console_.println("[!] Vault file is invalid or corrupted: " + hdr_res.error().message);
        return false;
    }

    const auto header = hdr_res.value();

    console_.println();
    console_.println("========================================");
    console_.println("              UNLOCK VAULT              ");
    console_.println("========================================");
    console_.println("Vault file: " + vault_path_.string());
    console_.println();

    for (int attempt = 1; attempt <= 5; ++attempt) {
        std::string pwd = console_.read_password("Enter master password (or 'q' to quit): ");
        if (pwd == "q" || pwd == "quit") {
            should_exit_ = true;
            return false;
        }

        if (pwd.empty()) {
            continue;
        }

        auto load_res = core::VaultStorage::load_vault(vault_path_, pwd);
        if (!load_res.has_value()) {
            console_.println(
                "[!] Authentication failed: incorrect master password or corrupted vault.");
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        core::CryptoService crypto;
        core::KdfParameters params{header.kdf_ops_limit,
                                   static_cast<std::size_t>(header.kdf_mem_limit),
                                   static_cast<int>(header.kdf_algorithm)};

        auto key_res = crypto.derive_key(pwd, header.salt, params);
        if (!key_res.has_value()) {
            console_.println("[!] Key derivation error.");
            return false;
        }

        session_key_ = std::move(key_res.value());
        vault_header_ = header;
        vault_ = std::make_unique<core::Vault>(std::move(load_res.value()));
        is_unlocked_ = true;
        has_unsaved_changes_ = false;

        console_.println("[🔓] Vault unlocked successfully.");
        return true;
    }

    console_.println("[!] Maximum unlock attempts reached.");
    should_exit_ = true;
    return false;
}

void PasswordManagerApp::run_main_menu() {
    console_.println();
    console_.println("----------------------------------------");
    console_.println("        SECURE PASSWORD MANAGER         ");
    std::string vault_status = "Vault: " + vault_path_.filename().string();
    if (has_unsaved_changes_) {
        vault_status += "  [UNSAVED CHANGES]";
    }
    console_.println(vault_status);
    console_.println("----------------------------------------");
    console_.println(" 1. Add a credential");
    console_.println(" 2. View all credentials");
    console_.println(" 3. Search credentials");
    console_.println(" 4. View credential details");
    console_.println(" 5. Edit a credential");
    console_.println(" 6. Delete a credential");
    console_.println(" 7. Generate a password");
    console_.println(" 8. Save vault");
    console_.println(" 9. Lock vault");
    console_.println("10. Exit");
    console_.println("----------------------------------------");

    std::string choice = console_.read_line("Enter choice (1-10): ");
    auto first = choice.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return;
    }

    std::string trimmed = choice.substr(first);
    if (trimmed == "1") {
        handle_add_credential();
    } else if (trimmed == "2") {
        handle_view_all_credentials();
    } else if (trimmed == "3") {
        handle_search_credentials();
    } else if (trimmed == "4") {
        handle_view_credential_details();
    } else if (trimmed == "5") {
        handle_edit_credential();
    } else if (trimmed == "6") {
        handle_delete_credential();
    } else if (trimmed == "7") {
        handle_generate_password();
    } else if (trimmed == "8") {
        handle_save_vault();
    } else if (trimmed == "9") {
        handle_lock_vault();
    } else if (trimmed == "10") {
        handle_exit();
    } else {
        console_.println("[!] Invalid choice. Please enter a number between 1 and 10.");
    }
}

std::string PasswordManagerApp::prompt_password_with_generate_option(std::string_view prompt_text,
                                                                     bool allow_empty_to_keep) {
    while (true) {
        console_.println(prompt_text);
        std::string choice =
            console_.read_line("[G] Generate strong password  |  [T] Type password manually: ");
        auto first = choice.find_first_not_of(" \t\r\n");
        char ch = (first == std::string::npos)
                      ? '\0'
                      : static_cast<char>(std::tolower(static_cast<unsigned char>(choice[first])));

        if (ch == 'g') {
            core::PasswordGeneratorConfig config;
            config.length = 16;
            config.include_uppercase = true;
            config.include_lowercase = true;
            config.include_digits = true;
            config.include_symbols = true;

            core::PasswordGenerator generator;
            auto gen_res = generator.generate(config);
            if (!gen_res.has_value()) {
                console_.println("[!] Generator error: " + gen_res.error().message);
                continue;
            }

            std::string generated = gen_res.value();
            console_.println("Generated Password: " + generated);
            if (console_.read_confirmation("Use this password?", true)) {
                return generated;
            }
        } else if (ch == 't') {
            std::string manual = console_.read_line("Enter password: ");
            if (manual.empty() && !allow_empty_to_keep) {
                console_.println("[!] Password cannot be empty.");
                continue;
            }
            return manual;
        } else if (allow_empty_to_keep && first == std::string::npos) {
            return "";
        } else {
            console_.println("[!] Please enter 'G' to generate or 'T' to type.");
        }
    }
}

void PasswordManagerApp::handle_add_credential() {
    console_.println();
    console_.println("--- Add New Credential ---");

    std::string service = console_.read_line("Service / Website (required): ");
    if (core::CredentialValidator::trim(service).empty()) {
        console_.println("[!] Service name cannot be empty.");
        return;
    }

    std::string username = console_.read_line("Username / Email (optional): ");
    std::string password = prompt_password_with_generate_option("Credential Password:");
    if (password.empty()) {
        console_.println("[!] Password cannot be empty.");
        return;
    }

    std::string url = console_.read_line("Website URL (optional): ");
    std::string category = console_.read_line("Category (optional): ");
    std::string notes = console_.read_line("Notes (optional): ");

    if (vault_->has_duplicate(service, username)) {
        console_.println("[!] Note: A credential for '" + service + "' with username '" + username +
                         "' already exists.");
        if (!console_.read_confirmation("Do you still want to add this credential?", false)) {
            console_.println("[i] Add cancelled.");
            return;
        }
    }

    models::CredentialInput input{service, username, password, url, category, notes};
    auto add_res = vault_->add_credential(input);
    if (!add_res.has_value()) {
        console_.println("[!] Failed to add credential: " + add_res.error().message);
        return;
    }

    has_unsaved_changes_ = true;
    console_.println("[✓] Credential added successfully (ID: " + std::to_string(add_res.value()) +
                     ").");
}

void PasswordManagerApp::handle_view_all_credentials() {
    console_.println();
    console_.println("--- All Vault Credentials ---");
    auto creds = vault_->list_credentials();
    print_credentials_table(console_, creds);
}

void PasswordManagerApp::handle_search_credentials() {
    console_.println();
    console_.println("--- Search Credentials ---");
    std::string query = console_.read_line("Enter search query: ");
    if (core::CredentialValidator::trim(query).empty()) {
        console_.println("[i] Search query was empty.");
        return;
    }

    auto matches = vault_->search_credentials(query);
    if (matches.empty()) {
        console_.println("[i] No credentials matched '" + query + "'.");
    } else {
        print_credentials_table(console_, matches);
    }
}

void PasswordManagerApp::handle_view_credential_details() {
    console_.println();
    console_.println("--- View Credential Details ---");
    std::string id_str = console_.read_line("Enter Credential ID: ");
    models::CredentialId id = 0;
    try {
        id = std::stoull(id_str);
    } catch (...) {
        console_.println("[!] Invalid ID format.");
        return;
    }

    auto res = vault_->get_credential(id);
    if (!res.has_value()) {
        console_.println("[!] Credential not found: " + res.error().message);
        return;
    }

    const auto& c = res.value();
    console_.println("========================================");
    console_.println("ID:          " + std::to_string(c.id()));
    console_.println("Service:     " + c.service());
    console_.println("Username:    " + (c.username().empty() ? "(none)" : c.username()));
    console_.println("Password:    ••••••••••••");
    console_.println("URL:         " + (c.url().empty() ? "(none)" : c.url()));
    console_.println("Category:    " + (c.category().empty() ? "(none)" : c.category()));
    console_.println("Notes:       " + (c.notes().empty() ? "(none)" : c.notes()));
    console_.println("Created At:  " + c.created_at());
    console_.println("Updated At:  " + c.updated_at());
    console_.println("========================================");

    std::string action = console_.read_line("[R] Reveal Password  |  [Enter] Return to Menu: ");
    auto first = action.find_first_not_of(" \t\r\n");
    if (first != std::string::npos &&
        std::tolower(static_cast<unsigned char>(action[first])) == 'r') {
        console_.println();
        console_.println("Password: " + c.password());
        console_.pause("Press Enter to hide password and continue...");
        console_.clear_screen();
    }
}

void PasswordManagerApp::handle_edit_credential() {
    console_.println();
    console_.println("--- Edit Credential ---");
    std::string id_str = console_.read_line("Enter Credential ID to edit: ");
    models::CredentialId id = 0;
    try {
        id = std::stoull(id_str);
    } catch (...) {
        console_.println("[!] Invalid ID format.");
        return;
    }

    auto res = vault_->get_credential(id);
    if (!res.has_value()) {
        console_.println("[!] Credential not found.");
        return;
    }

    const auto& current = res.value();
    console_.println("Press Enter to keep existing value in brackets.");

    std::string service_prompt = "Service [" + current.service() + "]: ";
    std::string new_service = console_.read_line(service_prompt);
    if (new_service.empty()) {
        new_service = current.service();
    }

    std::string user_prompt = "Username [" + current.username() + "]: ";
    std::string new_user = console_.read_line(user_prompt);
    if (new_user.empty()) {
        new_user = current.username();
    }

    std::string new_password;
    if (console_.read_confirmation("Do you want to change the password?", false)) {
        new_password = prompt_password_with_generate_option("New Password:");
    }
    if (new_password.empty()) {
        new_password = current.password();
    }

    std::string url_prompt = "URL [" + current.url() + "]: ";
    std::string new_url = console_.read_line(url_prompt);
    if (new_url.empty()) {
        new_url = current.url();
    }

    std::string cat_prompt = "Category [" + current.category() + "]: ";
    std::string new_category = console_.read_line(cat_prompt);
    if (new_category.empty()) {
        new_category = current.category();
    }

    std::string notes_prompt = "Notes [" + current.notes() + "]: ";
    std::string new_notes = console_.read_line(notes_prompt);
    if (new_notes.empty()) {
        new_notes = current.notes();
    }

    models::CredentialInput input{new_service, new_user,     new_password,
                                  new_url,     new_category, new_notes};
    auto dupes = vault_->find_duplicates(input, id);
    if (!dupes.empty()) {
        console_.println("[!] Note: Another credential with this service and username exists.");
    }

    auto update_res = vault_->update_credential(id, input);
    if (!update_res.has_value()) {
        console_.println("[!] Failed to update credential: " + update_res.error().message);
        return;
    }

    has_unsaved_changes_ = true;
    console_.println("[✓] Credential updated successfully.");
}

void PasswordManagerApp::handle_delete_credential() {
    console_.println();
    console_.println("--- Delete Credential ---");
    std::string id_str = console_.read_line("Enter Credential ID to delete: ");
    models::CredentialId id = 0;
    try {
        id = std::stoull(id_str);
    } catch (...) {
        console_.println("[!] Invalid ID format.");
        return;
    }

    auto res = vault_->get_credential(id);
    if (!res.has_value()) {
        console_.println("[!] Credential not found.");
        return;
    }

    const auto& c = res.value();
    console_.println("Selected: ID " + std::to_string(c.id()) + " - " + c.service() + " (" +
                     c.username() + ")");
    if (!console_.read_confirmation("Are you sure you want to permanently delete this credential?",
                                    false)) {
        console_.println("[i] Deletion cancelled.");
        return;
    }

    auto del_res = vault_->delete_credential(id);
    if (!del_res.has_value()) {
        console_.println("[!] Failed to delete: " + del_res.error().message);
        return;
    }

    has_unsaved_changes_ = true;
    console_.println("[✓] Credential deleted successfully.");
}

void PasswordManagerApp::handle_generate_password() {
    console_.println();
    console_.println("--- Standalone Password Generator ---");

    std::string len_str = console_.read_line("Password length [16]: ");
    std::size_t length = 16;
    if (!len_str.empty()) {
        try {
            length = std::stoul(len_str);
        } catch (...) {
            console_.println("[!] Invalid length format, using 16.");
            length = 16;
        }
    }

    bool uppercase = console_.read_confirmation("Include uppercase letters (A-Z)?", true);
    bool lowercase = console_.read_confirmation("Include lowercase letters (a-z)?", true);
    bool digits = console_.read_confirmation("Include numbers (0-9)?", true);
    bool symbols = console_.read_confirmation("Include special symbols (!@#$)?", true);
    bool exclude_ambiguous =
        console_.read_confirmation("Exclude ambiguous characters (I, O, l, 0, 1)?", false);

    core::PasswordGeneratorConfig config{length, uppercase, lowercase,
                                         digits, symbols,   exclude_ambiguous};
    auto val_res = core::PasswordGenerator::validate_config(config);
    if (!val_res.has_value()) {
        console_.println("[!] Configuration error: " + val_res.error().message);
        return;
    }

    core::PasswordGenerator generator;
    auto gen_res = generator.generate(config);
    if (!gen_res.has_value()) {
        console_.println("[!] Generation failed: " + gen_res.error().message);
        return;
    }

    console_.println("========================================");
    console_.println("Generated Password: " + gen_res.value());
    console_.println("========================================");
}

void PasswordManagerApp::handle_save_vault() {
    if (!has_unsaved_changes_) {
        console_.println("[i] No unsaved changes.");
        return;
    }

    auto save_res =
        core::VaultStorage::save_vault(vault_path_, *vault_, session_key_, vault_header_);
    if (!save_res.has_value()) {
        console_.println("[!] Failed to save vault: " + save_res.error().message);
        return;
    }

    has_unsaved_changes_ = false;
    console_.println("[✓] Vault saved successfully to " + vault_path_.string());
}

bool PasswordManagerApp::prompt_unsaved_changes(std::string_view action_name) {
    if (!has_unsaved_changes_) {
        return true;
    }

    console_.println("[!] You have unsaved changes.");
    std::string response =
        console_.read_line(std::string("Save changes before ") + std::string(action_name) +
                           "? [Y]es / [N]o / [C]ancel: ");
    auto first = response.find_first_not_of(" \t\r\n");
    char ch = (first == std::string::npos)
                  ? 'y'
                  : static_cast<char>(std::tolower(static_cast<unsigned char>(response[first])));

    if (ch == 'y') {
        auto save_res =
            core::VaultStorage::save_vault(vault_path_, *vault_, session_key_, vault_header_);
        if (!save_res.has_value()) {
            console_.println("[!] Failed to save vault: " + save_res.error().message);
            return false;
        }
        has_unsaved_changes_ = false;
        console_.println("[✓] Changes saved.");
        return true;
    } else if (ch == 'n') {
        console_.println("[i] Changes discarded.");
        has_unsaved_changes_ = false;
        return true;
    } else {
        console_.println("[i] Action cancelled.");
        return false;
    }
}

void PasswordManagerApp::handle_lock_vault() {
    if (!prompt_unsaved_changes("locking")) {
        return;
    }

    session_key_ = core::SecureKey();
    vault_.reset();
    is_unlocked_ = false;
    has_unsaved_changes_ = false;
    console_.println("[🔒] Vault locked.");
}

void PasswordManagerApp::handle_exit() {
    if (!prompt_unsaved_changes("exiting")) {
        return;
    }

    session_key_ = core::SecureKey();
    vault_.reset();
    is_unlocked_ = false;
    should_exit_ = true;
}

}  // namespace password_manager::cli
