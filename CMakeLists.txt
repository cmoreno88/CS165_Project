set(CMAKE_CXX_STANDARD 11)

cmake_minimum_required(VERSION 3.10.0)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake;${CMAKE_MODULE_PATH}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build")

set(CLIENT_SRC	src/client/client.c)
add_executable(client ${CLIENT_SRC})
set(SERVER_SRC	src/server/server.c src/server/strlcpy.c)
add_executable(server ${SERVER_SRC})
find_package(LibreSSL REQUIRED)

#Make sure to find the right library include on hammer/bolt
target_link_libraries(client "/usr/lib64/libcrypto.so")
