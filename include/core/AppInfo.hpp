#pragma once

#include <string_view>

namespace password_manager::core {

class AppInfo {
  public:
    static constexpr std::string_view APP_NAME = "SECURE PASSWORD MANAGER";
    static constexpr std::string_view VERSION = "1.0.0";
    static constexpr std::string_view STATUS = "Initialized";

    [[nodiscard]] static constexpr std::string_view get_build_type() noexcept {
#if defined(_DEBUG) || defined(DEBUG)
        return "Debug";
#else
        return "Release";
#endif
    }
};

}  // namespace password_manager::core
