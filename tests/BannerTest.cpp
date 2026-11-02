#include <gtest/gtest.h>

#include <sstream>
#include <string>

#include "core/AppInfo.hpp"
#include "ui/Banner.hpp"

TEST(BannerTest, OutputsExpectedWelcomeMessage) {
    std::ostringstream buffer;
    password_manager::ui::display_welcome_banner(buffer);

    const std::string output = buffer.str();

    EXPECT_NE(output.find("========================================"), std::string::npos);
    EXPECT_NE(output.find("SECURE PASSWORD MANAGER"), std::string::npos);
    EXPECT_NE(output.find("Welcome to your local password vault."), std::string::npos);
    EXPECT_NE(output.find("Application Status: Initialized"), std::string::npos);
    EXPECT_NE(output.find("Version: 1.0.0"), std::string::npos);

    const std::string expectedBuild =
        std::string("Build: ") + std::string(password_manager::core::AppInfo::get_build_type());
    EXPECT_NE(output.find(expectedBuild), std::string::npos);

    EXPECT_NE(output.find("The password manager foundation is ready."), std::string::npos);
}
