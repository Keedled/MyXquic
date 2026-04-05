set(
    CHUNK_SHARED_SOURCES
    "chunk_common.c"
    "chunk_protocol.c"
)

set(
    CHUNK_CLIENT_SOURCES
    ${CHUNK_SHARED_SOURCES}
    "chunk_client.c"
    "chunk_client_cb.c"
    "chunk_client_worker.c"
)

set(
    CHUNK_SERVER_SOURCES
    ${CHUNK_SHARED_SOURCES}
    "chunk_server.c"
    "chunk_server_cb.c"
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(CHUNK_CLIENT_SOURCES
        ${CHUNK_CLIENT_SOURCES}
        ${GETOPT_SOURCES}
    )

    set(CHUNK_SERVER_SOURCES
        ${CHUNK_SERVER_SOURCES}
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

add_executable(chunk_client ${CHUNK_CLIENT_SOURCES})
add_executable(chunk_server ${CHUNK_SERVER_SOURCES})

target_link_libraries(chunk_client ${APP_DEPEND_LIBS})
target_link_libraries(chunk_server ${APP_DEPEND_LIBS})
