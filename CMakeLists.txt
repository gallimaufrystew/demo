
cmake_minimum_required(VERSION 2.6)

project(backend)

include_directories(. C:/openssl-110/include E:/boost_1660)

# Source files to be used in the library
file (GLOB app_SOURCES *.cc)

add_executable(backend ${app_SOURCES})

link_directories(C:/openssl-110/bin E:/boost_1660/stage/lib)

#find_library(ssl_110_LIBS NAMES ssl PATHS C:/openssl-110/lib)
#find_library(crypto_110_LIBS NAMES crypto PATHS C:/openssl-110/lib)
#find_library(boost_thread_LIBS NAMES boost_thread PATHS E:/boost_1660/stage/lib)
#find_library(boost_system_LIBS NAMES boost_system PATHS E:/boost_1660/stage/lib)
#find_library(pthread_LIBS NAMES pthread /usr/lib /usr/local/lib /opt/lib)

target_link_libraries(backend C:/openssl-110/libcrypto.lib C:/openssl-110/libssl.lib
                      E:/boost_1660/stage/lib/libboost_system-vc110-mt-gd-x32-1_66.lib)
