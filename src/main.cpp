#include <filesystem>
#include <iostream>

#include "cli/PasswordManagerApp.hpp"

int main(int argc, char* argv[]) {
    std::filesystem::path vault_path = "vault.dat";
    if (argc > 1) {
        vault_path = argv[1];
    }

    try {
        password_manager::cli::PasswordManagerApp app(vault_path);
        return app.run();
    } catch (const std::exception& e) {
        std::cerr << "Fatal application error: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Fatal unknown application error.\n";
        return 1;
    }
}
