#include "ui/Banner.hpp"

#include <iostream>

#include "core/AppInfo.hpp"

namespace password_manager::ui {

void display_welcome_banner(std::ostream& out) {
    out << "========================================\n"
        << "          " << core::AppInfo::APP_NAME << "\n"
        << "========================================\n\n"
        << "Welcome to your local password vault.\n\n"
        << "Application Status: " << core::AppInfo::STATUS << "\n"
        << "Version: " << core::AppInfo::VERSION << "\n"
        << "Build: " << core::AppInfo::get_build_type() << "\n\n"
        << "The password manager foundation is ready.\n\n"
        << "========================================\n";
}

void display_welcome_banner() {
    display_welcome_banner(std::cout);
}

}  // namespace password_manager::ui
