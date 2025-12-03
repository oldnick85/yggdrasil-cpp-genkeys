add_executable(${PROJECT_NAME} 
    main.cpp
)

target_link_libraries(${PROJECT_NAME} 
    libsodium::libsodium 
    clipp::clipp
)
