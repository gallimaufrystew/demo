
cmake_minimum_required(VERSION 2.6)

project(stuns)

include_directories(. /opt/include)

# Source files to be used in the library
file (GLOB app_SOURCES *.cc)

set(OPENSSL_ROOT_DIR /opt)

find_package(OpenSSL)

if (OPENSSL_FOUND)
add_executable(stuns ${app_SOURCES})
target_link_libraries(stuns ${OPENSSL_LIBRARIES})
else()
message(SEND_ERROR "no openssl library found")
endif()

