#include "core/Timestamp.hpp"

#include <cstdio>
#include <ctime>

namespace password_manager::core {

std::chrono::system_clock::time_point SystemClock::now() const {
    return std::chrono::system_clock::now();
}

std::string Timestamp::format_utc(std::chrono::system_clock::time_point tp) {
    const std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm gm{};

#if defined(_WIN32) || defined(_WIN64)
    gmtime_s(&gm, &tt);
#else
    gmtime_r(&tt, &gm);
#endif

    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02dZ", gm.tm_year + 1900,
                  gm.tm_mon + 1, gm.tm_mday, gm.tm_hour, gm.tm_min, gm.tm_sec);

    return std::string(buffer);
}

std::string Timestamp::now_utc() {
    SystemClock default_clock;
    return now_utc(default_clock);
}

std::string Timestamp::now_utc(const IClock& clock) {
    return format_utc(clock.now());
}

}  // namespace password_manager::core
