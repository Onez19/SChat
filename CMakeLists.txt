cmake_minimum_required(VERSION 3.10)
project(ClientServer)

find_package(OpenSSL REQUIRED)

add_subdirectory(client)
add_subdirectory(server)
