cmake_minimum_required(VERSION 3.20)

# Automatic vcpkg toolchain file discovery if not explicitly specified
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(DEFINED ENV{VCPKG_ROOT} AND EXISTS "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "vcpkg toolchain file")
    elseif(EXISTS "C:/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "vcpkg toolchain file")
    endif()
endif()

# Option to build unit and integration tests
option(BUILD_TESTING "Build the test suite" ON)

# Enable vcpkg test features when testing is enabled
if(BUILD_TESTING)
    list(APPEND VCPKG_MANIFEST_FEATURES "tests")
endif()

project(PasswordManager
    VERSION 1.0.0
    DESCRIPTION "Secure Password Manager"
    LANGUAGES CXX
)

# Enforce C++20 standard globally as default baseline
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find third-party dependencies managed by vcpkg
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

# Standardized alias for libsodium
if(TARGET unofficial-sodium::sodium AND NOT TARGET libsodium::libsodium)
    add_library(libsodium::libsodium INTERFACE IMPORTED)
    target_link_libraries(libsodium::libsodium INTERFACE unofficial-sodium::sodium)
endif()

# -----------------------------------------------------------------------------
# Reusable Core Library Target
# -----------------------------------------------------------------------------
add_library(password_manager_lib STATIC
    src/ui/Banner.cpp
)

target_include_directories(password_manager_lib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(password_manager_lib PUBLIC cxx_std_20)

target_link_libraries(password_manager_lib
    PUBLIC
        libsodium::libsodium
        nlohmann_json::nlohmann_json
)

# Compiler-specific warnings and flags (MSVC)
if(MSVC)
    target_compile_options(password_manager_lib
        PRIVATE
            /W4
            /permissive-
            /EHsc
            /utf-8
    )
endif()

# -----------------------------------------------------------------------------
# CLI Application Executable Target
# -----------------------------------------------------------------------------
add_executable(password_manager_app
    src/main.cpp
)

set_target_properties(password_manager_app PROPERTIES
    OUTPUT_NAME "password_manager"
)

target_link_libraries(password_manager_app
    PRIVATE
        password_manager_lib
)

target_compile_features(password_manager_app PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(password_manager_app
        PRIVATE
            /W4
            /permissive-
            /EHsc
            /utf-8
    )
endif()

# -----------------------------------------------------------------------------
# Testing Configuration
# -----------------------------------------------------------------------------
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
