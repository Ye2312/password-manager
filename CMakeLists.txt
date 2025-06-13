cmake_minimum_required(VERSION 3.15)
project(PasswordManager VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Настройки компилятора
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

# Указываем путь к OpenSSL (для macOS с Homebrew)
set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
find_package(OpenSSL REQUIRED)

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
    
    # Ищем nlohmann_json только если включены тесты
    find_package(nlohmann_json 3.2.0 QUIET)
    if(NOT nlohmann_json_FOUND)
        message(WARNING "nlohmann_json not found, tests will be built without it")
    else()
        target_link_libraries(pm_core PRIVATE nlohmann_json::nlohmann_json)
    endif()
    
    add_subdirectory(tests)
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