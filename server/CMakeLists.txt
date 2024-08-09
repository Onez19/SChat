# Define the server executable
add_executable(server src/main.cc)

# Include OpenSSL directories
target_include_directories(server PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link OpenSSL libraries
target_link_libraries(server PRIVATE ${OPENSSL_LIBRARIES})
