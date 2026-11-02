#include <gtest/gtest.h>

#include "core/AppInfo.hpp"

TEST(AppInfoTest, MetadataValuesAreCorrect) {
    using password_manager::core::AppInfo;

    EXPECT_EQ(AppInfo::APP_NAME, "SECURE PASSWORD MANAGER");
    EXPECT_EQ(AppInfo::VERSION, "1.0.0");
    EXPECT_EQ(AppInfo::STATUS, "Initialized");
}

TEST(AppInfoTest, BuildTypeMatchesActiveConfiguration) {
    using password_manager::core::AppInfo;

#if defined(_DEBUG) || defined(DEBUG)
    EXPECT_EQ(AppInfo::get_build_type(), "Debug");
#else
    EXPECT_EQ(AppInfo::get_build_type(), "Release");
#endif
}
