set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake;${CMAKE_MODULE_PATH}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src")

set(CLIENT_SRC	src/client_dir/client.c)
add_executable(client ${CLIENT_SRC})
set(SERVER_SRC	src/server_dir/server.c src/server_dir/strlcpy.c)
add_executable(server ${SERVER_SRC})
find_package(LibreSSL 3.1.0 REQUIRED)

#Make sure to find the right library include on hammer/bolt
target_link_libraries(client "/usr/lib/x86_64-linux-gnu/libcrypto.so")
