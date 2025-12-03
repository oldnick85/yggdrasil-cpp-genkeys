add_executable(unittests
    unittests.cpp
)

target_link_libraries(unittests 
    libsodium::libsodium 
    gtest::gtest
)

add_test(NAME UnitTests COMMAND unittests)

set_tests_properties(UnitTests PROPERTIES TIMEOUT 30)