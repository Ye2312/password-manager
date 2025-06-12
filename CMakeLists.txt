cmake_minimum_required(VERSION 3.15)  
project(PasswordManager VERSION 1.0 LANGUAGES CXX)  

set(CMAKE_CXX_STANDARD 17)  
set(CMAKE_CXX_STANDARD_REQUIRED ON)  


find_package(OpenSSL REQUIRED)

option(BUILD_TESTING "Build the tests" ON)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()


add_executable(password_manager
    src/main.cpp
    src/crypto.cpp
    src/password_manager.cpp
)

target_include_directories(password_manager PRIVATE include)


target_link_libraries(password_manager PRIVATE OpenSSL::Crypto)

if(MSVC)
    target_compile_options(password_manager PRIVATE "/utf-8")
endif()