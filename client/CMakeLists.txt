# Define the client executable
add_executable(client src/main.cc)

# Set the CMake policy for CMP0079 to NEW
cmake_policy(SET CMP0079 NEW)


# Include OpenSSL directories
target_include_directories(client PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link OpenSSL libraries
target_link_libraries(client PRIVATE ${OPENSSL_LIBRARIES})
