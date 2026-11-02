#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <string_view>

#include "core/PasswordGenerator.hpp"

namespace password_manager::testing {

namespace {

bool contains_any(std::string_view str, std::string_view chars) {
    return str.find_first_of(chars) != std::string_view::npos;
}

bool contains_only(std::string_view str, std::string_view allowed_chars) {
    return str.find_first_not_of(allowed_chars) == std::string_view::npos;
}

}  // namespace

class PasswordGeneratorTest : public ::testing::Test {
  protected:
    core::PasswordGenerator generator;
};

// ----------------------------------------------------------------------------
// 1. Basic Generation Tests
// ----------------------------------------------------------------------------

TEST_F(PasswordGeneratorTest, DefaultConfigurationGeneratesValidPassword) {
    const auto result = generator.generate();
    ASSERT_TRUE(result.has_value());

    const std::string& pwd = result.value();
    EXPECT_EQ(pwd.size(), core::PasswordGeneratorConfig::DEFAULT_LENGTH);
    EXPECT_FALSE(pwd.empty());
}

TEST_F(PasswordGeneratorTest, CustomLengthIsRespectedExactly) {
    for (std::size_t len : {8, 12, 20, 32, 64, 128, 256}) {
        core::PasswordGeneratorConfig config;
        config.length = len;

        const auto result = generator.generate(config);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result.value().size(), len);
    }
}

TEST_F(PasswordGeneratorTest, RepeatedGenerationsSucceedAndVary) {
    core::PasswordGeneratorConfig config{.length = 16};
    std::string first;

    const auto res1 = generator.generate(config);
    ASSERT_TRUE(res1.has_value());
    first = res1.value();

    bool has_different = false;
    for (int i = 0; i < 10; ++i) {
        const auto res = generator.generate(config);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(res.value().size(), 16u);
        if (res.value() != first) {
            has_different = true;
        }
    }
    EXPECT_TRUE(has_different);
}

// ----------------------------------------------------------------------------
// 2. Character Categories & Guaranteed Representation Tests
// ----------------------------------------------------------------------------

TEST_F(PasswordGeneratorTest, GuaranteesAllFourCategoriesWhenEnabled) {
    core::PasswordGeneratorConfig config{.length = 16,
                                         .include_uppercase = true,
                                         .include_lowercase = true,
                                         .include_digits = true,
                                         .include_symbols = true,
                                         .exclude_ambiguous = false};

    for (int trial = 0; trial < 50; ++trial) {
        const auto res = generator.generate(config);
        ASSERT_TRUE(res.has_value());
        const std::string& pwd = res.value();

        EXPECT_TRUE(contains_any(pwd, core::PasswordGenerator::UPPERCASE_CHARS));
        EXPECT_TRUE(contains_any(pwd, core::PasswordGenerator::LOWERCASE_CHARS));
        EXPECT_TRUE(contains_any(pwd, core::PasswordGenerator::DIGIT_CHARS));
        EXPECT_TRUE(contains_any(pwd, core::PasswordGenerator::SYMBOL_CHARS));
    }
}

TEST_F(PasswordGeneratorTest, UppercaseOnlyConfiguration) {
    core::PasswordGeneratorConfig config{.length = 16,
                                         .include_uppercase = true,
                                         .include_lowercase = false,
                                         .include_digits = false,
                                         .include_symbols = false};

    for (int trial = 0; trial < 20; ++trial) {
        const auto res = generator.generate(config);
        ASSERT_TRUE(res.has_value());
        const std::string& pwd = res.value();

        EXPECT_TRUE(contains_only(pwd, core::PasswordGenerator::UPPERCASE_CHARS));
        EXPECT_FALSE(contains_any(pwd, core::PasswordGenerator::LOWERCASE_CHARS));
        EXPECT_FALSE(contains_any(pwd, core::PasswordGenerator::DIGIT_CHARS));
        EXPECT_FALSE(contains_any(pwd, core::PasswordGenerator::SYMBOL_CHARS));
    }
}

TEST_F(PasswordGeneratorTest, LowercaseOnlyConfiguration) {
    core::PasswordGeneratorConfig config{.length = 16,
                                         .include_uppercase = false,
                                         .include_lowercase = true,
                                         .include_digits = false,
                                         .include_symbols = false};

    const auto res = generator.generate(config);
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(contains_only(res.value(), core::PasswordGenerator::LOWERCASE_CHARS));
}

TEST_F(PasswordGeneratorTest, DigitsOnlyConfiguration) {
    core::PasswordGeneratorConfig config{.length = 10,
                                         .include_uppercase = false,
                                         .include_lowercase = false,
                                         .include_digits = true,
                                         .include_symbols = false};

    const auto res = generator.generate(config);
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(contains_only(res.value(), core::PasswordGenerator::DIGIT_CHARS));
}

TEST_F(PasswordGeneratorTest, SymbolsOnlyConfiguration) {
    core::PasswordGeneratorConfig config{.length = 12,
                                         .include_uppercase = false,
                                         .include_lowercase = false,
                                         .include_digits = false,
                                         .include_symbols = true};

    const auto res = generator.generate(config);
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(contains_only(res.value(), core::PasswordGenerator::SYMBOL_CHARS));
}

TEST_F(PasswordGeneratorTest, MixedConfigurationWithoutSymbols) {
    core::PasswordGeneratorConfig config{.length = 16,
                                         .include_uppercase = true,
                                         .include_lowercase = true,
                                         .include_digits = true,
                                         .include_symbols = false};

    for (int trial = 0; trial < 20; ++trial) {
        const auto res = generator.generate(config);
        ASSERT_TRUE(res.has_value());
        const std::string& pwd = res.value();

        EXPECT_TRUE(contains_any(pwd, core::PasswordGenerator::UPPERCASE_CHARS));
        EXPECT_TRUE(contains_any(pwd, core::PasswordGenerator::LOWERCASE_CHARS));
        EXPECT_TRUE(contains_any(pwd, core::PasswordGenerator::DIGIT_CHARS));
        EXPECT_FALSE(contains_any(pwd, core::PasswordGenerator::SYMBOL_CHARS));
    }
}

// ----------------------------------------------------------------------------
// 3. Ambiguous Characters Exclusion Tests
// ----------------------------------------------------------------------------

TEST_F(PasswordGeneratorTest, ExcludesAmbiguousCharactersWhenConfigured) {
    core::PasswordGeneratorConfig config{.length = 64,
                                         .include_uppercase = true,
                                         .include_lowercase = true,
                                         .include_digits = true,
                                         .include_symbols = true,
                                         .exclude_ambiguous = true};

    for (int trial = 0; trial < 30; ++trial) {
        const auto res = generator.generate(config);
        ASSERT_TRUE(res.has_value());
        const std::string& pwd = res.value();

        // Must NOT contain 'I', 'O', 'l', '0', '1'
        EXPECT_FALSE(contains_any(pwd, core::PasswordGenerator::AMBIGUOUS_CHARS));

        // Category guarantees must remain satisfied
        EXPECT_TRUE(contains_any(pwd, "ABCDEFGHJKLMNPQRSTUVWXYZ"));
        EXPECT_TRUE(contains_any(pwd, "abcdefghijkmnopqrstuvwxyz"));
        EXPECT_TRUE(contains_any(pwd, "23456789"));
        EXPECT_TRUE(contains_any(pwd, core::PasswordGenerator::SYMBOL_CHARS));
    }
}

// ----------------------------------------------------------------------------
// 4. Validation & Boundary Condition Tests
// ----------------------------------------------------------------------------

TEST_F(PasswordGeneratorTest, ValidatesMinimumAndMaximumLengthBoundaries) {
    // Exact minimum valid length (8)
    core::PasswordGeneratorConfig min_valid{.length = 8};
    EXPECT_TRUE(generator.generate(min_valid).has_value());

    // Length below minimum (7)
    core::PasswordGeneratorConfig below_min{.length = 7};
    auto res_below = generator.generate(below_min);
    ASSERT_FALSE(res_below.has_value());
    EXPECT_EQ(res_below.error().code, core::VaultErrorCode::InvalidConfiguration);

    // Exact maximum valid length (256)
    core::PasswordGeneratorConfig max_valid{.length = 256};
    EXPECT_TRUE(generator.generate(max_valid).has_value());

    // Length above maximum (257)
    core::PasswordGeneratorConfig above_max{.length = 257};
    auto res_above = generator.generate(above_max);
    ASSERT_FALSE(res_above.has_value());
    EXPECT_EQ(res_above.error().code, core::VaultErrorCode::InvalidConfiguration);
}

TEST_F(PasswordGeneratorTest, RejectsNoEnabledCategories) {
    core::PasswordGeneratorConfig no_categories{.length = 16,
                                                .include_uppercase = false,
                                                .include_lowercase = false,
                                                .include_digits = false,
                                                .include_symbols = false};

    const auto res = generator.generate(no_categories);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, core::VaultErrorCode::InvalidConfiguration);
}

TEST_F(PasswordGeneratorTest, RejectsInsufficientLengthForSelectedCategories) {
    // If length check were bypassed or customized to 3 with 4 categories
    core::PasswordGeneratorConfig config{.length = 3,
                                         .include_uppercase = true,
                                         .include_lowercase = true,
                                         .include_digits = true,
                                         .include_symbols = true};

    const auto res = generator.generate(config);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, core::VaultErrorCode::InvalidConfiguration);
}

// ----------------------------------------------------------------------------
// 5. Security & Property Constraints Tests
// ----------------------------------------------------------------------------

TEST_F(PasswordGeneratorTest, OutputContainsOnlyPermittedCharacters) {
    core::PasswordGeneratorConfig config{.length = 32,
                                         .include_uppercase = true,
                                         .include_lowercase = true,
                                         .include_digits = true,
                                         .include_symbols = true,
                                         .exclude_ambiguous = false};

    const std::string all_allowed = std::string(core::PasswordGenerator::UPPERCASE_CHARS) +
                                    std::string(core::PasswordGenerator::LOWERCASE_CHARS) +
                                    std::string(core::PasswordGenerator::DIGIT_CHARS) +
                                    std::string(core::PasswordGenerator::SYMBOL_CHARS);

    for (int trial = 0; trial < 20; ++trial) {
        const auto res = generator.generate(config);
        ASSERT_TRUE(res.has_value());
        EXPECT_TRUE(contains_only(res.value(), all_allowed));
    }
}

}  // namespace password_manager::testing
