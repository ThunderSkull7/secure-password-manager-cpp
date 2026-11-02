#include "core/SodiumInitializer.hpp"

#include <sodium.h>

#include <mutex>

namespace password_manager::core {

namespace {

bool g_initialized = false;
std::once_flag g_init_flag;
Result<void> g_init_result = Result<void>::success();

}  // namespace

bool SodiumInitializer::is_initialized() noexcept {
    return g_initialized;
}

Result<void> SodiumInitializer::initialize() {
    std::call_once(g_init_flag, []() {
        const int ret = sodium_init();
        if (ret < 0) {
            g_init_result =
                Result<void>::failure(VaultErrorCode::InitializationError,
                                      "Failed to initialize libsodium cryptographic library.");
            g_initialized = false;
        } else {
            g_init_result = Result<void>::success();
            g_initialized = true;
        }
    });
    return g_init_result;
}

}  // namespace password_manager::core
