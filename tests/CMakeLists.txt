find_package(GTest CONFIG REQUIRED)

add_executable(password_manager_tests
    SmokeTest.cpp
    AppInfoTest.cpp
    BannerTest.cpp
    CredentialTests.cpp
    CredentialValidatorTests.cpp
    TimestampTests.cpp
    VaultTests.cpp
    PasswordGeneratorTests.cpp
)

target_link_libraries(password_manager_tests
    PRIVATE
        password_manager_lib
        GTest::gtest
        GTest::gtest_main
)

target_compile_features(password_manager_tests PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(password_manager_tests
        PRIVATE
            /W4
            /permissive-
            /EHsc
            /utf-8
    )
endif()

include(GoogleTest)
gtest_discover_tests(password_manager_tests)
