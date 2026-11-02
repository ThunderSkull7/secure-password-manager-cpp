#pragma once

#include <type_traits>
#include <utility>
#include <variant>

#include "core/VaultError.hpp"

namespace password_manager::core {

struct Unit {};

template <typename T = void>
class Result {
  private:
    using StorageType = std::conditional_t<std::is_void_v<T>, Unit, T>;
    std::variant<StorageType, VaultError> state_;

  public:
    Result(const StorageType& value)
        requires(!std::is_void_v<T> && std::is_copy_constructible_v<StorageType>)
        : state_(value) {}

    Result(StorageType&& value)
        requires(!std::is_void_v<T> && std::is_move_constructible_v<StorageType>)
        : state_(std::move(value)) {}

    Result()
        requires(std::is_void_v<T>)
        : state_(Unit{}) {}

    Result(const VaultError& error) : state_(error) {}

    Result(VaultError&& error) : state_(std::move(error)) {}

    Result(const Result&) = default;
    Result& operator=(const Result&) = default;
    Result(Result&&) noexcept = default;
    Result& operator=(Result&&) noexcept = default;

    [[nodiscard]] bool has_value() const noexcept {
        return std::holds_alternative<StorageType>(state_);
    }

    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] const StorageType& value() const& { return std::get<StorageType>(state_); }

    [[nodiscard]] StorageType& value() & { return std::get<StorageType>(state_); }

    [[nodiscard]] StorageType&& value() && { return std::get<StorageType>(std::move(state_)); }

    [[nodiscard]] const VaultError& error() const { return std::get<VaultError>(state_); }

    [[nodiscard]] VaultError& error() { return std::get<VaultError>(state_); }

    static Result<void> success()
        requires(std::is_void_v<T>)
    {
        return Result<void>();
    }

    static Result<T> failure(VaultErrorCode code, std::string message) {
        return Result<T>(VaultError{code, std::move(message)});
    }
};

}  // namespace password_manager::core
