
cmake_minimum_required(VERSION 2.6)

project(stunc)

include_directories(. c:/openssl-110/include)

# Source files to be used in the library
file (GLOB app_SOURCES *.cc)

set(OPENSSL_ROOT_DIR c:/openssl-110)

find_package(OpenSSL)

if (OPENSSL_FOUND)
add_executable(stunc ${app_SOURCES})
target_link_libraries(stunc ${OPENSSL_LIBRARIES})
else()
message(SEND_ERROR "no OpenSSL library found")
endif()
