cmake_minimum_required(VERSION 2.6)

project(strop)

include_directories(. $ENV{AXIS2C_HOME}/include/axis2-1.6.0/)

# Source files to be used in the library
file (GLOB svc_SOURCES *.cc)

set (axis_LIBS "")
set (LIBS "")
set (sub_LIBS axutil axis2_axiom axis2_parser axis2_engine)
list(APPEND sub_LIBS axis2_http_sender axis2_http_receiver)
list(APPEND LIBS ${sub_LIBS})

foreach(e ${LIBS})
    find_library(x_${e} ${e} $ENV{AXIS2C_HOME}/lib NO_DEFAULT_PATH)
    if (x_${e}-NOTFOUND)
        message("no ${e} found")
    else()
        list(APPEND axis_LIBS ${x})
    endif()
endforeach()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_library(strop SHARED ${svc_SOURCES})
target_link_libraries(strop ${axis_LIBS} Threads::Threads)
