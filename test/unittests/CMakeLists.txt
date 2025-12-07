# Create unit test executable
add_executable(unittests
    unittests.cpp
)

# Enforce C++23 standard for tests as well
set_target_properties(unittests PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Link test dependencies
target_link_libraries(unittests 
    libsodium::libsodium 
    GTest::gtest
    GTest::gtest_main  # gtest_main provides main() function
)

# Add include directories to access headers from src
target_include_directories(unittests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/src  # For generated version.hpp
)

# Register test with CTest framework
add_test(NAME UnitTests COMMAND unittests)

# Configure test properties
set_tests_properties(UnitTests PROPERTIES 
    TIMEOUT 30
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Optional installation of test binaries
if(INSTALL_TESTS)
    install(TARGETS unittests
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/tests
    )
endif()

# Custom target for convenient test execution
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS unittests
    COMMENT "Running unit tests with verbose output"
)