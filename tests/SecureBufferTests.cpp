#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <type_traits>

#include "core/SecureBuffer.hpp"

namespace password_manager::testing {

TEST(SecureBufferTest, EnforcesMoveOnlySemanticsAtCompileTime) {
    using core::SecureBuffer;
    static_assert(!std::is_copy_constructible_v<SecureBuffer>, "SecureBuffer must not be copyable");
    static_assert(!std::is_copy_assignable_v<SecureBuffer>,
                  "SecureBuffer must not be copy-assignable");
    static_assert(std::is_move_constructible_v<SecureBuffer>, "SecureBuffer must be movable");
    static_assert(std::is_move_assignable_v<SecureBuffer>, "SecureBuffer must be move-assignable");
}

TEST(SecureBufferTest, DefaultConstructedBufferIsEmpty) {
    core::SecureBuffer buffer;
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.size(), 0u);
    EXPECT_EQ(buffer.data(), nullptr);
    EXPECT_EQ(buffer.to_string(), "");
}

TEST(SecureBufferTest, AllocateZeroSizeCreatesEmptyBufferSafely) {
    auto res = core::SecureBuffer::allocate(0);
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(res.value().empty());
    EXPECT_EQ(res.value().size(), 0u);
}

TEST(SecureBufferTest, AllocatePositiveSizeZeroInitializes) {
    auto res = core::SecureBuffer::allocate(64);
    ASSERT_TRUE(res.has_value());
    auto& buffer = res.value();

    EXPECT_FALSE(buffer.empty());
    EXPECT_EQ(buffer.size(), 64u);
    ASSERT_NE(buffer.data(), nullptr);

    const auto span = buffer.as_span();
    for (unsigned char b : span) {
        EXPECT_EQ(b, 0);
    }
}

TEST(SecureBufferTest, FromStringAndFromSpanCopyCorrectly) {
    const std::string text = "Secret decrypted vault content 12345!";
    auto res = core::SecureBuffer::from_string(text);
    ASSERT_TRUE(res.has_value());

    auto& buffer = res.value();
    EXPECT_EQ(buffer.size(), text.size());
    EXPECT_EQ(buffer.to_string(), text);

    const auto span = buffer.as_span();
    EXPECT_EQ(std::memcmp(span.data(), text.data(), text.size()), 0);
}

TEST(SecureBufferTest, MoveConstructionTransfersOwnershipAndResetsSource) {
    auto res = core::SecureBuffer::from_string("ConfidentialData");
    ASSERT_TRUE(res.has_value());

    core::SecureBuffer source = std::move(res.value());
    const auto* original_ptr = source.data();
    const auto original_size = source.size();

    core::SecureBuffer destination(std::move(source));

    EXPECT_EQ(destination.data(), original_ptr);
    EXPECT_EQ(destination.size(), original_size);
    EXPECT_EQ(destination.to_string(), "ConfidentialData");

    EXPECT_TRUE(source.empty());
    EXPECT_EQ(source.data(), nullptr);
    EXPECT_EQ(source.size(), 0u);
}

TEST(SecureBufferTest, MoveAssignmentFreesPreviousAndTransfersOwnership) {
    auto res1 = core::SecureBuffer::from_string("BufferOne");
    auto res2 = core::SecureBuffer::from_string("BufferTwo");

    ASSERT_TRUE(res1.has_value());
    ASSERT_TRUE(res2.has_value());

    core::SecureBuffer buf1 = std::move(res1.value());
    core::SecureBuffer buf2 = std::move(res2.value());

    buf1 = std::move(buf2);

    EXPECT_EQ(buf1.to_string(), "BufferTwo");
    EXPECT_TRUE(buf2.empty());
    EXPECT_EQ(buf2.data(), nullptr);
}

TEST(SecureBufferTest, AsWritableSpanAllowsInPlaceModification) {
    auto res = core::SecureBuffer::allocate(4);
    ASSERT_TRUE(res.has_value());

    auto& buffer = res.value();
    auto writable = buffer.as_writable_span();
    writable[0] = 'T';
    writable[1] = 'E';
    writable[2] = 'S';
    writable[3] = 'T';

    EXPECT_EQ(buffer.to_string(), "TEST");
}

}  // namespace password_manager::testing
