cmake_minimum_required(VERSION 3.20)

# Function to get version information from Git
function(get_version_from_git)
    # 1. Find Git
    find_package(Git QUIET)
    if(NOT Git_FOUND)
        message(WARNING "Git not found. Using default version.")
        set(PROJECT_VERSION "0.0.0" PARENT_SCOPE)
        return()
    endif()

    # 2. Get the most recent tag and commit info
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_DESCRIBE_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE GIT_RESULT
    )

    # 3. Handle cases where git describe fails (e.g., no tags)
    if(NOT GIT_RESULT EQUAL 0 OR "${GIT_DESCRIBE_OUTPUT}" STREQUAL "")
        message(WARNING "Could not get version from Git tags. Using default.")
        set(PROJECT_VERSION "0.0.0" PARENT_SCOPE)
        return()
    endif()

    # 4. Parse the output (e.g., "v1.0.0-2-gabc1234-dirty")
    #    Remove leading 'v' if present
    string(REGEX REPLACE "^v" "" VERSION_STRING "${GIT_DESCRIBE_OUTPUT}")
    #    Extract the base version (e.g., "1.0.0") before any hyphen
    string(REGEX MATCH "^([0-9]+\\.[0-9]+\\.[0-9]+)" BASE_VERSION "${VERSION_STRING}")

    if(BASE_VERSION)
        set(PROJECT_VERSION ${BASE_VERSION} PARENT_SCOPE)
        message(STATUS "Version from Git: ${BASE_VERSION} (${GIT_DESCRIBE_OUTPUT})")
    else()
        message(WARNING "Git tag '${VERSION_STRING}' is not SemVer. Using default.")
        set(PROJECT_VERSION "0.0.0" PARENT_SCOPE)
    endif()
endfunction()

# Call the function to set PROJECT_VERSION variable
get_version_from_git()

# Project definition with version and description
project(yggdrasil-cpp-genkeys 
    VERSION ${PROJECT_VERSION}
    LANGUAGES CXX
    DESCRIPTION "Yggdrasil C++ Key Generator"
)

# Enable export of compile_commands.json for clang-tidy static analysis
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set C++23 standard with strict requirements
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include GNUInstallDirs for standard installation directories
include(GNUInstallDirs)

# Project configuration options
option(BUILD_TESTS "Build unit tests" ON)
option(INSTALL_TESTS "Install test binaries" OFF)

# Conan toolchain integration (if present)
if(EXISTS ${CMAKE_BINARY_DIR}/conan_toolchain.cmake)
    message(STATUS "Using Conan toolchain")
    include(${CMAKE_BINARY_DIR}/conan_toolchain.cmake)
else()
    message(WARNING "Conan toolchain not found. Run 'conan install' first.")
endif()

# Find dependencies managed by Conan
find_package(libsodium REQUIRED)
find_package(clipp REQUIRED)

# Add source directory for main executable
add_subdirectory(src)

# Test configuration
if(BUILD_TESTS)
    find_package(GTest REQUIRED)
    enable_testing()  # Enable CMake's testing framework
    add_subdirectory(test)
endif()
