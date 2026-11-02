#include <gtest/gtest.h>

TEST(SmokeTest, FrameworkInitializesCorrectly) {
    EXPECT_TRUE(true);
}

TEST(SmokeTest, BasicMathAssertion) {
    EXPECT_EQ(2 + 2, 4);
}
