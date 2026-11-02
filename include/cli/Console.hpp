#pragma once

#include <sodium.h>

#include <iostream>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace password_manager::cli {

/**
 * @brief Zeroizes sensitive character data in a std::string before clearing it.
 */
inline void secure_zero_string(std::string& str) noexcept {
    if (!str.empty()) {
        sodium_memzero(str.data(), str.size());
        str.clear();
    }
}

/**
 * @brief RAII helper to automatically zeroize a string when leaving a scope.
 */
class ScopedStringScrubber {
  public:
    explicit ScopedStringScrubber(std::string& str) noexcept : str_(str) {}
    ~ScopedStringScrubber() { secure_zero_string(str_); }

    ScopedStringScrubber(const ScopedStringScrubber&) = delete;
    ScopedStringScrubber& operator=(const ScopedStringScrubber&) = delete;

  private:
    std::string& str_;
};

#ifdef _WIN32
/**
 * @brief RAII guard to safely disable console echo and ensure restoration on every exit path.
 */
class ConsoleEchoGuard {
  public:
    explicit ConsoleEchoGuard(HANDLE hConsole)
        : hConsole_(hConsole), original_mode_(0), active_(false) {
        if (hConsole_ != INVALID_HANDLE_VALUE && GetConsoleMode(hConsole_, &original_mode_)) {
            DWORD new_mode = original_mode_ & ~ENABLE_ECHO_INPUT;
            if (SetConsoleMode(hConsole_, new_mode)) {
                active_ = true;
            }
        }
    }

    ~ConsoleEchoGuard() { restore(); }

    void restore() noexcept {
        if (active_) {
            SetConsoleMode(hConsole_, original_mode_);
            active_ = false;
        }
    }

    [[nodiscard]] bool is_active() const noexcept { return active_; }

    ConsoleEchoGuard(const ConsoleEchoGuard&) = delete;
    ConsoleEchoGuard& operator=(const ConsoleEchoGuard&) = delete;
    ConsoleEchoGuard(ConsoleEchoGuard&&) = delete;
    ConsoleEchoGuard& operator=(ConsoleEchoGuard&&) = delete;

  private:
    HANDLE hConsole_;
    DWORD original_mode_;
    bool active_;
};
#endif

/**
 * @brief Console I/O abstraction supporting masked password input and stream injection.
 */
class Console {
  public:
    explicit Console(std::istream& in = std::cin, std::ostream& out = std::cout);

    void print(std::string_view msg);
    void println(std::string_view msg = "");

    [[nodiscard]] std::string read_line(std::string_view prompt = "");
    [[nodiscard]] std::string read_password(std::string_view prompt = "");
    [[nodiscard]] bool read_confirmation(std::string_view prompt, bool default_yes = false);

    void clear_screen();
    void pause(std::string_view prompt = "Press Enter to continue...");

    [[nodiscard]] bool is_eof() const noexcept { return in_.eof() || !in_.good(); }

    [[nodiscard]] bool is_interactive() const noexcept { return is_interactive_; }
    void set_interactive(bool interactive) noexcept { is_interactive_ = interactive; }

    [[nodiscard]] std::istream& in() noexcept { return in_; }
    [[nodiscard]] std::ostream& out() noexcept { return out_; }

  private:
    std::istream& in_;
    std::ostream& out_;
    bool is_interactive_{false};
};

}  // namespace password_manager::cli
