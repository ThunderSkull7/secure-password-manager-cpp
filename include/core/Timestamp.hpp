#pragma once

#include <chrono>
#include <string>

namespace password_manager::core {

class IClock {
  public:
    virtual ~IClock() = default;
    [[nodiscard]] virtual std::chrono::system_clock::time_point now() const = 0;
};

class SystemClock final : public IClock {
  public:
    [[nodiscard]] std::chrono::system_clock::time_point now() const override;
};

class Timestamp {
  public:
    [[nodiscard]] static std::string format_utc(std::chrono::system_clock::time_point tp);
    [[nodiscard]] static std::string now_utc();
    [[nodiscard]] static std::string now_utc(const IClock& clock);
};

}  // namespace password_manager::core
