cmake_minimum_required(VERSION 3.15)

# Подключаем GoogleTest
add_subdirectory(googletest)

# Тест для Crypto
add_executable(test_crypto test_crypto.cpp)
target_link_libraries(test_crypto PRIVATE
    pm_core
    gtest_main
    OpenSSL::Crypto  # Добавляем OpenSSL
)
target_include_directories(test_crypto PRIVATE ${OPENSSL_INCLUDE_DIR})

# Тест для PasswordManager
add_executable(test_password_manager test_password_manager.cpp)
target_link_libraries(test_password_manager PRIVATE
    pm_core
    gtest_main
    OpenSSL::Crypto  # Добавляем OpenSSL
)
target_include_directories(test_password_manager PRIVATE ${OPENSSL_INCLUDE_DIR})

enable_testing()
add_test(NAME test_crypto COMMAND test_crypto)
add_test(NAME test_password_manager COMMAND test_password_manager)