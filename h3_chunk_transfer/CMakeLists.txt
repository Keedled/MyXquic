set(
    H3_CHUNK_SHARED_SOURCES
    "h3_chunk_common.c"
    "${CMAKE_SOURCE_DIR}/chunk_transfer/chunk_common.c"
    "${CMAKE_SOURCE_DIR}/chunk_transfer/chunk_protocol.c"
)

set(
    H3_CHUNK_CLIENT_SOURCES
    ${H3_CHUNK_SHARED_SOURCES}
    "h3_chunk_client.c"
    "h3_chunk_client_cb.c"
    "h3_chunk_client_worker.c"
)

set(
    H3_CHUNK_SERVER_SOURCES
    ${H3_CHUNK_SHARED_SOURCES}
    "h3_chunk_server.c"
    "h3_chunk_server_cb.c"
    "h3_chunk_server_worker.c"
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(H3_CHUNK_CLIENT_SOURCES
        ${H3_CHUNK_CLIENT_SOURCES}
        ${GETOPT_SOURCES}
    )

    set(H3_CHUNK_SERVER_SOURCES
        ${H3_CHUNK_SERVER_SOURCES}
        ${GETOPT_SOURCES}
    )
endif()

include_directories(
    "${CMAKE_SOURCE_DIR}/"
    "${CMAKE_SOURCE_DIR}/include"
    ${CMAKE_SOURCE_DIR}
    ${CUNIT_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIR}
)

add_executable(h3_chunk_client ${H3_CHUNK_CLIENT_SOURCES})
add_executable(h3_chunk_server ${H3_CHUNK_SERVER_SOURCES})

target_link_libraries(h3_chunk_client ${APP_DEPEND_LIBS})
target_link_libraries(h3_chunk_server ${APP_DEPEND_LIBS})
