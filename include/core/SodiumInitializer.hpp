#pragma once

#include "core/Result.hpp"

namespace password_manager::core {

class SodiumInitializer {
  public:
    [[nodiscard]] static bool is_initialized() noexcept;
    static Result<void> initialize();
};

}  // namespace password_manager::core
