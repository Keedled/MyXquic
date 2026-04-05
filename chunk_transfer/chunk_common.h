#ifndef CHUNK_COMMON_H
#define CHUNK_COMMON_H

#include <event2/event.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <xquic/xquic.h>

#ifdef XQC_SYS_WINDOWS
#include "../tests/getopt.h"
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "../tests/platform.h"
#include "chunk_protocol.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#define CHUNK_ALPN                "chunk-transfer"
#define CHUNK_DEFAULT_ADDR        "127.0.0.1"
#define CHUNK_DEFAULT_PORT        8443
#define CHUNK_DEFAULT_HOST        "localhost"
#define CHUNK_DEFAULT_CHUNK_SIZE  (1024U * 1024U)
#define CHUNK_DEFAULT_CONCURRENCY 4U
#define CHUNK_DEFAULT_RETRIES     3U
#define CHUNK_DEFAULT_TIMEOUT_SEC 10U
#define CHUNK_PACKET_BUF_LEN      1500U
#define CHUNK_LOG_TEXT_LEN        160U
#define CHUNK_SOCKET_BUF_SIZE     (1024 * 1024)
#define CHUNK_DEFAULT_CERT_FILE   "tests/server.crt"
#define CHUNK_DEFAULT_KEY_FILE    "tests/server.key"

extern xqc_usec_t xqc_now(void);

typedef enum chunk_log_level_e {
    CHUNK_LOG_ERROR = 0,
    CHUNK_LOG_WARN = 1,
    CHUNK_LOG_INFO = 2,
    CHUNK_LOG_DEBUG = 3
} chunk_log_level;

typedef enum chunk_error_code_e {
    CHUNK_ERR_NONE = 0,
    CHUNK_ERR_IO = 1,
    CHUNK_ERR_SOCKET = 2,
    CHUNK_ERR_ENGINE = 3,
    CHUNK_ERR_CONNECT = 4,
    CHUNK_ERR_STREAM = 5,
    CHUNK_ERR_TIMEOUT = 6,
    CHUNK_ERR_PROTOCOL = 7,
    CHUNK_ERR_ACK = 8,
    CHUNK_ERR_SERVER = 9
} chunk_error_code;

typedef struct chunk_client_config_s {
    char server_addr[PATH_MAX];
    uint16_t server_port;
    char server_host[PATH_MAX];
    char input_path[PATH_MAX];
    uint32_t chunk_size;
    uint32_t concurrency;
    uint32_t max_retries;
    uint32_t timeout_sec;
    int log_level;
} chunk_client_config;

typedef struct chunk_server_config_s {
    char listen_addr[PATH_MAX];
    uint16_t listen_port;
    char output_path[PATH_MAX];
    char cert_file[PATH_MAX];
    char key_file[PATH_MAX];
    uint32_t timeout_sec;
    int log_level;
} chunk_server_config;

typedef struct chunk_task_s {
    uint32_t chunk_id;
    uint32_t chunk_count;
    uint64_t offset;
    uint32_t chunk_len;
    uint32_t attempts;
} chunk_task;

typedef struct chunk_result_s {
    int finished;
    int success;
    int error_code;
    uint16_t ack_status;
    uint32_t ack_received_len;
    uint32_t ack_crc32;
    char error_text[CHUNK_LOG_TEXT_LEN];
} chunk_result;

typedef struct chunk_worker_ctx_s chunk_worker_ctx;
typedef struct chunk_stream_ctx_s chunk_stream_ctx;
typedef struct chunk_server_ctx_s chunk_server_ctx;
typedef struct server_conn_ctx_s server_conn_ctx;
typedef struct server_stream_ctx_s server_stream_ctx;

struct chunk_stream_ctx_s {
    chunk_worker_ctx *worker;
    xqc_stream_t *stream;
    uint8_t header_buf[CHUNK_HEADER_V1_LEN];
    size_t header_len;
    size_t header_sent;
    uint8_t *body_buf;
    size_t body_len;
    size_t body_sent;
    uint8_t ack_buf[CHUNK_ACK_V1_LEN];
    size_t ack_received;
};

struct chunk_worker_ctx_s {
    pthread_mutex_t *scheduler_mutex;
    pthread_cond_t *scheduler_cond;
    int finished;
    int close_requested;
    chunk_client_config config;
    uint64_t file_id;
    uint64_t file_size;
    chunk_task *task;
    chunk_result result;
    struct event_base *eb;
    struct event *ev_engine;
    struct event *ev_socket;
    struct event *ev_timeout;
    xqc_engine_t *engine;
    xqc_connection_t *conn;
    xqc_cid_t cid;
    int fd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    chunk_stream_ctx stream_ctx;
};

typedef struct file_assembly_ctx_s {
    int fd;
    uint64_t file_id;
    uint64_t file_size;
    uint32_t chunk_count;
    uint32_t received_count;
    size_t bitmap_len;
    uint8_t *bitmap;
    int initialized;
    int completed;
} file_assembly_ctx;

struct chunk_server_ctx_s {
    chunk_server_config config;
    struct event_base *eb;
    struct event *ev_engine;
    struct event *ev_socket;
    xqc_engine_t *engine;
    int listen_fd;
    int current_fd;
    struct sockaddr_storage listen_addr;
    socklen_t listen_addrlen;
    file_assembly_ctx assembly;
};

struct server_conn_ctx_s {
    chunk_server_ctx *server;
    xqc_connection_t *conn;
    xqc_cid_t cid;
    uint32_t stream_count;
    int close_requested;
};

struct server_stream_ctx_s {
    server_conn_ctx *conn_ctx;
    xqc_stream_t *stream;
    uint8_t header_buf[CHUNK_HEADER_V1_LEN];
    size_t header_received;
    int header_parsed;
    int duplicate;
    chunk_header_v1 header;
    uint8_t *body_buf;
    size_t body_received;
    uint32_t crc_state;
    uint8_t ack_buf[CHUNK_ACK_V1_LEN];
    size_t ack_len;
    size_t ack_sent;
    int ack_ready;
};

void chunk_log_print(int configured_level, int level, const char *component, const char *fmt, ...);
int chunk_parse_address(const char *host, uint16_t port, struct sockaddr_storage *addr, socklen_t *addrlen);
int chunk_socket_set_nonblocking(int fd);
int chunk_socket_set_buffers(int fd, int size);
int chunk_create_udp_socket(const struct sockaddr *bind_addr, socklen_t bind_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, int reuse_addr, int connect_peer);
int chunk_get_local_addr(int fd, struct sockaddr_storage *addr, socklen_t *addrlen);
uint64_t chunk_make_file_id(const char *path, const struct stat *st);
int chunk_read_chunk_file(const char *path, uint64_t offset, uint8_t *buf, size_t len);
int chunk_write_all_at(int fd, const uint8_t *buf, size_t len, uint64_t offset);
int chunk_resize_file(int fd, uint64_t size);
int chunk_fsync_file(int fd);
size_t chunk_bitmap_bytes(uint32_t bit_count);
int chunk_bitmap_get(const uint8_t *bitmap, uint32_t bit_index);
void chunk_bitmap_set(uint8_t *bitmap, uint32_t bit_index);
void chunk_result_set(chunk_result *result, int success, int error_code, uint16_t ack_status,
    const char *fmt, ...);
void chunk_mark_worker_finished(chunk_worker_ctx *worker);

int chunk_client_run_worker(chunk_worker_ctx *worker);
void *chunk_client_worker_thread_main(void *arg);
int chunk_client_register_alpn(xqc_engine_t *engine);
int chunk_client_stream_send(xqc_stream_t *stream, chunk_stream_ctx *stream_ctx);

void chunk_client_engine_cb(int fd, short what, void *arg);
void chunk_client_set_event_timer(xqc_usec_t wake_after, void *user_data);
void chunk_client_write_log(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);
void chunk_client_write_qlog(qlog_event_importance_t imp, const void *buf, size_t size,
    void *engine_user_data);
void chunk_client_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data);
ssize_t chunk_client_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data);
ssize_t chunk_client_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
void chunk_client_save_token(const unsigned char *token, unsigned token_len, void *user_data);
void chunk_client_save_session(const char *data, size_t data_len, void *user_data);
void chunk_client_save_tp(const char *data, size_t data_len, void *user_data);
int chunk_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data);
int chunk_client_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data);
void chunk_client_conn_handshake_finished(xqc_connection_t *conn, void *user_data,
    void *conn_proto_data);
int chunk_client_stream_write_notify(xqc_stream_t *stream, void *user_data);
int chunk_client_stream_read_notify(xqc_stream_t *stream, void *user_data);
int chunk_client_stream_close_notify(xqc_stream_t *stream, void *user_data);

int chunk_server_register_alpn(xqc_engine_t *engine);
int chunk_server_stream_send_ack(xqc_stream_t *stream, server_stream_ctx *stream_ctx);

void chunk_server_engine_cb(int fd, short what, void *arg);
void chunk_server_set_event_timer(xqc_usec_t wake_after, void *user_data);
void chunk_server_write_log(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);
void chunk_server_write_qlog(qlog_event_importance_t imp, const void *buf, size_t size,
    void *engine_user_data);
void chunk_server_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data);
int chunk_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data);
ssize_t chunk_server_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data);
ssize_t chunk_server_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
int chunk_server_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data);
int chunk_server_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data);
void chunk_server_conn_handshake_finished(xqc_connection_t *conn, void *user_data,
    void *conn_proto_data);
int chunk_server_stream_create_notify(xqc_stream_t *stream, void *user_data);
int chunk_server_stream_write_notify(xqc_stream_t *stream, void *user_data);
int chunk_server_stream_read_notify(xqc_stream_t *stream, void *user_data);
int chunk_server_stream_close_notify(xqc_stream_t *stream, void *user_data);

#endif
