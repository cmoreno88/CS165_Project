set(CLIENT_SRC client_solution/client.c)
add_executable(client_solution ${CLIENT_SRC})
target_link_libraries(client_solution LibreSSL::TLS)

set(SERVER_SRC server_solution/server.c)
add_executable(server_solution ${SERVER_SRC})
target_link_libraries(server_solution LibreSSL::TLS)

set(PROXY_SRC proxy_solution/proxy.c)
add_executable(proxy_solution ${PROXY_SRC})
target_link_libraries(proxy_solution LibreSSL::TLS)
