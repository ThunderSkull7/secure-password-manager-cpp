#include <gtest/gtest.h>

#include <chrono>
#include <regex>

#include "core/Timestamp.hpp"

namespace password_manager::testing {

class MockClock final : public core::IClock {
  public:
    explicit MockClock(std::chrono::system_clock::time_point fixed_time)
        : current_time_(fixed_time) {}

    [[nodiscard]] std::chrono::system_clock::time_point now() const override {
        return current_time_;
    }

    void advance(std::chrono::seconds delta) { current_time_ += delta; }

  private:
    std::chrono::system_clock::time_point current_time_;
};

TEST(TimestampTest, GeneratesValidIso8601UtcFormat) {
    const std::string ts = core::Timestamp::now_utc();

    // Strictly YYYY-MM-DDTHH:MM:SSZ
    const std::regex iso8601_regex(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$)");
    EXPECT_TRUE(std::regex_match(ts, iso8601_regex)) << "Got invalid timestamp format: " << ts;
    EXPECT_EQ(ts.back(), 'Z');
}

TEST(TimestampTest, FormatsKnownTimestampCorrectly) {
    // 2026-01-15 12:30:45 UTC
    std::tm fixed_tm{};
    fixed_tm.tm_year = 2026 - 1900;
    fixed_tm.tm_mon = 0;  // January
    fixed_tm.tm_mday = 15;
    fixed_tm.tm_hour = 12;
    fixed_tm.tm_min = 30;
    fixed_tm.tm_sec = 45;

#if defined(_WIN32) || defined(_WIN64)
    const std::time_t tt = _mkgmtime(&fixed_tm);
#else
    const std::time_t tt = timegm(&fixed_tm);
#endif

    const auto tp = std::chrono::system_clock::from_time_t(tt);
    MockClock mock_clock(tp);

    EXPECT_EQ(core::Timestamp::now_utc(mock_clock), "2026-01-15T12:30:45Z");

    mock_clock.advance(std::chrono::seconds(15));
    EXPECT_EQ(core::Timestamp::now_utc(mock_clock), "2026-01-15T12:31:00Z");
}

TEST(TimestampTest, TwoRapidConsecutiveCallsSucceedWithoutError) {
    const std::string ts1 = core::Timestamp::now_utc();
    const std::string ts2 = core::Timestamp::now_utc();

    EXPECT_EQ(ts1.size(), 20u);
    EXPECT_EQ(ts2.size(), 20u);
    EXPECT_EQ(ts1.back(), 'Z');
    EXPECT_EQ(ts2.back(), 'Z');
}

}  // namespace password_manager::testing
