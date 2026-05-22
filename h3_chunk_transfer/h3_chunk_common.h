#ifndef H3_CHUNK_COMMON_H
#define H3_CHUNK_COMMON_H

#include "../chunk_transfer/chunk_common.h"
#include <xquic/xqc_http3.h>

#ifdef XQC_SYS_WINDOWS
#define H3_CHUNK_THREAD_LOCAL __declspec(thread)
#else
#define H3_CHUNK_THREAD_LOCAL __thread
#endif

#define H3_CHUNK_DEFAULT_ADDR        CHUNK_DEFAULT_ADDR
#define H3_CHUNK_DEFAULT_PORT        CHUNK_DEFAULT_PORT
#define H3_CHUNK_DEFAULT_HOST        CHUNK_DEFAULT_HOST
#define H3_CHUNK_DEFAULT_CHUNK_SIZE  CHUNK_DEFAULT_CHUNK_SIZE
#define H3_CHUNK_DEFAULT_CONCURRENCY CHUNK_DEFAULT_CONCURRENCY
#define H3_CHUNK_DEFAULT_RETRIES     CHUNK_DEFAULT_RETRIES
#define H3_CHUNK_DEFAULT_TIMEOUT_SEC CHUNK_DEFAULT_TIMEOUT_SEC
#define H3_CHUNK_DEFAULT_CERT_FILE   CHUNK_DEFAULT_CERT_FILE
#define H3_CHUNK_DEFAULT_KEY_FILE    CHUNK_DEFAULT_KEY_FILE
#define H3_CHUNK_PACKET_BUF_LEN      CHUNK_PACKET_BUF_LEN
#define H3_CHUNK_SOCKET_BUF_SIZE     CHUNK_SOCKET_BUF_SIZE
#define H3_CHUNK_LOG_TEXT_LEN        CHUNK_LOG_TEXT_LEN
#define H3_CHUNK_DEFAULT_PATH        "/xquic-h3-chunk"

#define H3_CHUNK_HDR_FILE_ID         "x-h3-chunk-file-id"
#define H3_CHUNK_HDR_FILE_SIZE       "x-h3-chunk-file-size"
#define H3_CHUNK_HDR_CHUNK_ID        "x-h3-chunk-id"
#define H3_CHUNK_HDR_CHUNK_COUNT     "x-h3-chunk-count"
#define H3_CHUNK_HDR_OFFSET          "x-h3-chunk-offset"
#define H3_CHUNK_HDR_CHUNK_LEN       "x-h3-chunk-len"
#define H3_CHUNK_HDR_CRC32           "x-h3-chunk-crc32"
#define H3_CHUNK_HDR_STATUS          "x-h3-chunk-status"
#define H3_CHUNK_HDR_RECEIVED_LEN    "x-h3-chunk-received-len"
#define H3_CHUNK_SERVER_WORKER_MAGIC 0x4833574BU
#define H3_CHUNK_SERVER_CONN_MAGIC   0x4833434EU

typedef struct h3_chunk_client_config_s {
    char server_addr[PATH_MAX];
    uint16_t server_port;
    char server_host[PATH_MAX];
    char input_path[PATH_MAX];
    uint32_t chunk_size;
    uint32_t concurrency;
    uint32_t max_retries;
    uint32_t timeout_sec;
    int log_level;
} h3_chunk_client_config;

typedef struct h3_chunk_server_config_s {
    char listen_addr[PATH_MAX];
    uint16_t listen_port;
    char output_path[PATH_MAX];
    char cert_file[PATH_MAX];
    char key_file[PATH_MAX];
    uint32_t worker_count;
    uint32_t timeout_sec;
    int log_level;
} h3_chunk_server_config;

typedef struct h3_chunk_client_worker_ctx_s h3_chunk_client_worker_ctx;
typedef struct h3_chunk_client_request_ctx_s h3_chunk_client_request_ctx;
typedef struct h3_chunk_server_shared_ctx_s h3_chunk_server_shared_ctx;
typedef struct h3_chunk_server_worker_ctx_s h3_chunk_server_worker_ctx;
typedef struct h3_chunk_server_conn_ctx_s h3_chunk_server_conn_ctx;
typedef struct h3_chunk_server_request_ctx_s h3_chunk_server_request_ctx;

struct h3_chunk_client_request_ctx_s {
    h3_chunk_client_worker_ctx *worker;
    xqc_h3_request_t *request;
    uint8_t *body_buf;
    size_t body_len;
    size_t body_sent;
    int header_sent;
    int recv_header;
    int recv_fin;
};

struct h3_chunk_client_worker_ctx_s {
    pthread_mutex_t *scheduler_mutex;
    pthread_cond_t *scheduler_cond;
    int finished;
    int close_requested;
    h3_chunk_client_config config;
    uint64_t file_id;
    uint64_t file_size;
    chunk_task *task;
    chunk_result result;
    struct event_base *eb;
    struct event *ev_engine;
    struct event *ev_socket;
    struct event *ev_timeout;
    xqc_engine_t *engine;
    xqc_h3_conn_t *h3_conn;
    xqc_cid_t cid;
    int fd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    h3_chunk_client_request_ctx request_ctx;
};

struct h3_chunk_server_shared_ctx_s {
    h3_chunk_server_config config;
    pthread_mutex_t assembly_mutex;
    file_assembly_ctx assembly;
};

struct h3_chunk_server_worker_ctx_s {
    uint32_t magic;
    uint32_t worker_id;
    h3_chunk_server_shared_ctx *shared;
    struct event_base *eb;
    struct event *ev_engine;
    struct event *ev_socket;
    xqc_engine_t *engine;
    int listen_fd;
    int current_fd;
    struct sockaddr_storage listen_addr;
    socklen_t listen_addrlen;
};

struct h3_chunk_server_conn_ctx_s {
    uint32_t magic;
    h3_chunk_server_worker_ctx *worker;
    xqc_h3_conn_t *h3_conn;
    xqc_cid_t cid;
    int close_requested;
};

struct h3_chunk_server_request_ctx_s {
    h3_chunk_server_conn_ctx *conn_ctx;
    xqc_h3_request_t *request;
    int header_parsed;
    int duplicate;
    int ack_ready;
    int response_sent;
    int failed;
    chunk_header_v1 header;
    uint8_t *body_buf;
    size_t body_received;
    uint32_t crc_state;
    uint16_t ack_status;
    uint32_t ack_received_len;
    uint32_t ack_crc32;
};

extern H3_CHUNK_THREAD_LOCAL h3_chunk_server_worker_ctx *h3_chunk_current_server_worker;

int h3_chunk_parse_u32_arg(const char *text, uint32_t *value);
void h3_chunk_mark_worker_finished(h3_chunk_client_worker_ctx *worker);

void h3_chunk_set_header(xqc_http_header_t *hdr, const char *name, const char *value);
int h3_chunk_header_value_to_u64(const xqc_http_headers_t *headers, const char *name, uint64_t *value);
int h3_chunk_header_value_to_u32(const xqc_http_headers_t *headers, const char *name, uint32_t *value);
int h3_chunk_header_value_equals(const xqc_http_headers_t *headers, const char *name,
    const char *expected);
int h3_chunk_parse_request_headers(const xqc_http_headers_t *headers, chunk_header_v1 *header);
int h3_chunk_parse_ack_headers(const xqc_http_headers_t *headers, chunk_ack_v1 *ack);

int h3_chunk_client_run_worker(h3_chunk_client_worker_ctx *worker);
void *h3_chunk_client_worker_thread_main(void *arg);
int h3_chunk_client_request_send(xqc_h3_request_t *request, h3_chunk_client_request_ctx *request_ctx);

void h3_chunk_client_engine_cb(int fd, short what, void *arg);
void h3_chunk_client_set_event_timer(xqc_usec_t wake_after, void *user_data);
void h3_chunk_client_write_log(xqc_log_level_t lvl, const void *buf, size_t size,
    void *engine_user_data);
void h3_chunk_client_write_qlog(qlog_event_importance_t imp, const void *buf, size_t size,
    void *engine_user_data);
void h3_chunk_client_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data);
ssize_t h3_chunk_client_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
ssize_t h3_chunk_client_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
void h3_chunk_client_save_token(const unsigned char *token, unsigned token_len, void *user_data);
void h3_chunk_client_save_session(const char *data, size_t data_len, void *user_data);
void h3_chunk_client_save_tp(const char *data, size_t data_len, void *user_data);
int h3_chunk_client_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *user_data);
int h3_chunk_client_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *user_data);
void h3_chunk_client_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data);
int h3_chunk_client_request_close_notify(xqc_h3_request_t *request, void *user_data);
int h3_chunk_client_request_read_notify(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flag, void *user_data);
int h3_chunk_client_request_write_notify(xqc_h3_request_t *request, void *user_data);
void h3_chunk_client_request_closing_notify(xqc_h3_request_t *request, xqc_int_t err,
    void *user_data);

int h3_chunk_server_run_worker(h3_chunk_server_worker_ctx *worker);
void *h3_chunk_server_worker_thread_main(void *arg);
int h3_chunk_server_request_send_response(h3_chunk_server_request_ctx *request_ctx);

void h3_chunk_server_engine_cb(int fd, short what, void *arg);
void h3_chunk_server_set_event_timer(xqc_usec_t wake_after, void *user_data);
void h3_chunk_server_write_log(xqc_log_level_t lvl, const void *buf, size_t size,
    void *engine_user_data);
void h3_chunk_server_write_qlog(qlog_event_importance_t imp, const void *buf, size_t size,
    void *engine_user_data);
void h3_chunk_server_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data);
int h3_chunk_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data);
ssize_t h3_chunk_server_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
ssize_t h3_chunk_server_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
int h3_chunk_server_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *user_data);
int h3_chunk_server_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *user_data);
void h3_chunk_server_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data);
int h3_chunk_server_request_create_notify(xqc_h3_request_t *request, void *user_data);
int h3_chunk_server_request_close_notify(xqc_h3_request_t *request, void *user_data);
int h3_chunk_server_request_read_notify(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flag, void *user_data);
int h3_chunk_server_request_write_notify(xqc_h3_request_t *request, void *user_data);

#endif
