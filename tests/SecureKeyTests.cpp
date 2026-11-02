#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <span>
#include <type_traits>

#include "core/SecureKey.hpp"

namespace password_manager::testing {

TEST(SecureKeyTest, EnforcesMoveOnlySemanticsAtCompileTime) {
    using core::SecureKey;
    static_assert(!std::is_copy_constructible_v<SecureKey>, "SecureKey must not be copyable");
    static_assert(!std::is_copy_assignable_v<SecureKey>, "SecureKey must not be copy-assignable");
    static_assert(std::is_move_constructible_v<SecureKey>, "SecureKey must be movable");
    static_assert(std::is_move_assignable_v<SecureKey>, "SecureKey must be move-assignable");
}

TEST(SecureKeyTest, DefaultConstructedKeyIsInvalid) {
    core::SecureKey key;
    EXPECT_FALSE(key.is_valid());
    EXPECT_EQ(key.size(), core::CryptoConstants::KEY_BYTES);

    const auto span = key.as_span();
    EXPECT_TRUE(std::all_of(span.begin(), span.end(), [](unsigned char b) { return b == 0; }));
}

TEST(SecureKeyTest, InitializedWithCorrectSizeIsValid) {
    std::array<unsigned char, core::CryptoConstants::KEY_BYTES> raw{};
    raw.fill(0xAA);

    core::SecureKey key(raw);
    EXPECT_TRUE(key.is_valid());
    EXPECT_EQ(key.size(), core::CryptoConstants::KEY_BYTES);
    EXPECT_EQ(key.data()[0], 0xAA);
}

TEST(SecureKeyTest, InitializedWithWrongSizeIsInvalid) {
    std::array<unsigned char, 16> short_raw{};
    short_raw.fill(0x55);

    core::SecureKey key(short_raw);
    EXPECT_FALSE(key.is_valid());
}

TEST(SecureKeyTest, MoveConstructionTransfersKeyAndInvalidatesSource) {
    std::array<unsigned char, core::CryptoConstants::KEY_BYTES> raw{};
    raw.fill(0x7F);

    core::SecureKey source(raw);
    ASSERT_TRUE(source.is_valid());

    core::SecureKey destination(std::move(source));
    EXPECT_TRUE(destination.is_valid());
    EXPECT_EQ(destination.data()[0], 0x7F);

    // Source must be invalidated and zeroed
    EXPECT_FALSE(source.is_valid());
    const auto src_span = source.as_span();
    EXPECT_TRUE(
        std::all_of(src_span.begin(), src_span.end(), [](unsigned char b) { return b == 0; }));
}

TEST(SecureKeyTest, MoveAssignmentTransfersKeyAndCleansSource) {
    std::array<unsigned char, core::CryptoConstants::KEY_BYTES> raw1{};
    raw1.fill(0x11);
    std::array<unsigned char, core::CryptoConstants::KEY_BYTES> raw2{};
    raw2.fill(0x22);

    core::SecureKey key1(raw1);
    core::SecureKey key2(raw2);

    key1 = std::move(key2);
    EXPECT_TRUE(key1.is_valid());
    EXPECT_EQ(key1.data()[0], 0x22);

    EXPECT_FALSE(key2.is_valid());
    const auto k2_span = key2.as_span();
    EXPECT_TRUE(
        std::all_of(k2_span.begin(), k2_span.end(), [](unsigned char b) { return b == 0; }));
}

}  // namespace password_manager::testing
