cmake_minimum_required(VERSION 3.15)
project(PasswordManager VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Настройки компилятора
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

# Указываем путь к OpenSSL
set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
find_package(OpenSSL REQUIRED)

# Указываем путь к nlohmann/json
set(JSON_INCLUDE_DIR /opt/homebrew/Cellar/nlohmann-json/3.12.0/include)
include_directories(${JSON_INCLUDE_DIR})

# Основная библиотека
add_library(pm_core STATIC
    src/crypto.cpp
    src/password_manager.cpp
)
target_include_directories(pm_core PUBLIC include)
target_link_libraries(pm_core PRIVATE OpenSSL::Crypto OpenSSL::SSL)

# Основной исполняемый файл
add_executable(password_manager src/main.cpp)
target_link_libraries(password_manager PRIVATE pm_core)

# Тесты
option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    enable_testing()
    
    # Подключаем GoogleTest
    add_subdirectory(tests/googletest)
    
    # Ищем nlohmann_json
    find_package(nlohmann_json 3.12.0 QUIET)
    if(NOT nlohmann_json_FOUND)
        message(WARNING "nlohmann_json not found, using manual include path")
        target_include_directories(pm_core PRIVATE ${JSON_INCLUDE_DIR})
    else()
        target_link_libraries(pm_core PRIVATE nlohmann_json::nlohmann_json)
    endif()
    
    # Тест для Crypto
    add_executable(test_crypto tests/test_crypto.cpp)
    target_link_libraries(test_crypto PRIVATE pm_core gtest_main OpenSSL::Crypto)
    target_include_directories(test_crypto PRIVATE include ${JSON_INCLUDE_DIR})
    add_test(NAME test_crypto COMMAND test_crypto)

    # Тест для PasswordManager
    add_executable(test_password_manager tests/test_password_manager.cpp)
    target_link_libraries(test_password_manager PRIVATE pm_core gtest_main OpenSSL::Crypto)
    target_include_directories(test_password_manager PRIVATE include ${JSON_INCLUDE_DIR})
    add_test(NAME test_password_manager COMMAND test_password_manager)
endif()

# Документация
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in")
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
                  ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        COMMENT "Generating documentation..."
        VERBATIM
    )
endif()