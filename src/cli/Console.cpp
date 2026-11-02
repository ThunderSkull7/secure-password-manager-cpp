#include "cli/Console.hpp"

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#endif

#include <algorithm>
#include <cctype>

namespace password_manager::cli {

Console::Console(std::istream& in, std::ostream& out) : in_(in), out_(out) {
#ifdef _WIN32
    DWORD mode = 0;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    is_interactive_ = (&in_ == &std::cin) && (_isatty(_fileno(stdin)) != 0) &&
                      (hStdin != INVALID_HANDLE_VALUE && GetConsoleMode(hStdin, &mode));
#else
    is_interactive_ = (&in_ == &std::cin);
#endif
}

void Console::print(std::string_view msg) {
    out_ << msg;
    out_.flush();
}

void Console::println(std::string_view msg) {
    out_ << msg << "\n";
    out_.flush();
}

std::string Console::read_line(std::string_view prompt) {
    if (!prompt.empty()) {
        print(prompt);
    }

    std::string line;
    if (!std::getline(in_, line)) {
        return "";
    }

    // Strip carriage return if present (Windows CRLF normalization)
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    return line;
}

std::string Console::read_password(std::string_view prompt) {
    if (!prompt.empty()) {
        print(prompt);
    }

    if (!is_interactive_) {
        std::string password;
        if (!std::getline(in_, password)) {
            return "";
        }
        if (!password.empty() && password.back() == '\r') {
            password.pop_back();
        }
        return password;
    }

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    ConsoleEchoGuard guard(hStdin);

    std::string password;
    while (true) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            break;
        } else if (ch == '\b' || ch == 127) {
            // Handle backspace safely
            if (!password.empty()) {
                password.pop_back();
            }
        } else if (ch == 3) {
            // Ctrl+C signal handling
            secure_zero_string(password);
            println();
            return "";
        } else if (ch == 0 || ch == 0xE0) {
            // Extended key code (arrow keys, function keys) - consume trailing code byte
            (void)_getch();
        } else {
            password.push_back(static_cast<char>(ch));
        }
    }
    println();
    return password;
#else
    std::string password;
    std::getline(in_, password);
    return password;
#endif
}

bool Console::read_confirmation(std::string_view prompt, bool default_yes) {
    const std::string suffix = default_yes ? " [Y/n]: " : " [y/N]: ";
    print(std::string(prompt) + suffix);

    std::string input = read_line();
    auto first = input.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return default_yes;
    }

    char ch = static_cast<char>(std::tolower(static_cast<unsigned char>(input[first])));
    return ch == 'y';
}

void Console::clear_screen() {
    if (!is_interactive_) {
        return;
    }
#ifdef _WIN32
    print("\033[2J\033[H");
#endif
}

void Console::pause(std::string_view prompt) {
    print(prompt);
    if (is_interactive_) {
#ifdef _WIN32
        (void)_getch();
        println();
        return;
#endif
    }
    std::string dummy;
    (void)std::getline(in_, dummy);
}

}  // namespace password_manager::cli
