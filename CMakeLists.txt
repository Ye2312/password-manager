cmake_minimum_required(VERSION 3.15)
project(PasswordManager VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")


find_package(OpenSSL REQUIRED)


add_executable(password_manager
    src/main.cpp
    src/crypto.cpp
    src/password_manager.cpp
    src/utils.cpp
)

target_include_directories(password_manager PRIVATE include)
target_link_libraries(password_manager PRIVATE OpenSSL::Crypto)


option(BUILD_TESTING "Build the tests" ON)
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()


find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
                   ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
endif()

find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})  
    message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")  
    target_link_libraries(password_manager PRIVATE OpenSSL::Crypto)
endif()
