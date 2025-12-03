cmake_minimum_required(VERSION 3.15)
project(yggdrasil-cpp-genkeys LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(libsodium REQUIRED)
find_package(clipp REQUIRED)

option(BUILD_TESTS "Build tests" ON)

add_subdirectory(src)

if(BUILD_TESTS)
    find_package(GTest REQUIRED)
    add_subdirectory(test)
endif()