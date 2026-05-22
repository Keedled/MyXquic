#include "h3_chunk_common.h"

static void
h3_chunk_client_force_close(h3_chunk_client_worker_ctx *worker)
{
    if (worker == NULL || worker->close_requested) {
        return;
    }

    worker->close_requested = 1;
    if (worker->engine != NULL && worker->cid.cid_len > 0) {
        xqc_h3_conn_close(worker->engine, &worker->cid);
        xqc_engine_main_logic(worker->engine);
    } else if (worker->eb != NULL) {
        event_base_loopbreak(worker->eb);
    }
}

void
h3_chunk_client_engine_cb(int fd, short what, void *arg)
{
    h3_chunk_client_worker_ctx *worker = (h3_chunk_client_worker_ctx *)arg;
    (void)fd;
    (void)what;

    if (worker != NULL && worker->engine != NULL) {
        xqc_engine_main_logic(worker->engine);
    }
}

void
h3_chunk_client_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    h3_chunk_client_worker_ctx *worker = (h3_chunk_client_worker_ctx *)user_data;
    struct timeval tv;

    if (worker == NULL || worker->ev_engine == NULL) {
        return;
    }

    tv.tv_sec = (time_t)(wake_after / 1000000U);
    tv.tv_usec = (suseconds_t)(wake_after % 1000000U);
    event_add(worker->ev_engine, &tv);
}

void
h3_chunk_client_write_log(xqc_log_level_t lvl, const void *buf, size_t size,
    void *engine_user_data)
{
    (void)lvl;
    (void)buf;
    (void)size;
    (void)engine_user_data;
}

void
h3_chunk_client_write_qlog(qlog_event_importance_t imp, const void *buf, size_t size,
    void *engine_user_data)
{
    (void)imp;
    (void)buf;
    (void)size;
    (void)engine_user_data;
}

void
h3_chunk_client_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data)
{
    (void)scid;
    (void)line;
    (void)engine_user_data;
}

ssize_t
h3_chunk_client_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    return h3_chunk_client_write_socket_ex(0, buf, size, peer_addr, peer_addrlen,
        conn_user_data);
}

ssize_t
h3_chunk_client_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    h3_chunk_client_worker_ctx *worker = (h3_chunk_client_worker_ctx *)conn_user_data;
    ssize_t rc;
    (void)path_id;

    if (worker == NULL) {
        return -1;
    }

    do {
        set_sys_errno(0);
        rc = sendto(worker->fd, (const char *)buf, size, 0, peer_addr, peer_addrlen);
        if (rc < 0 && get_sys_errno() == EAGAIN) {
            return XQC_SOCKET_EAGAIN;
        }
    } while (rc < 0 && get_sys_errno() == EINTR);

    return rc;
}

void
h3_chunk_client_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    (void)token;
    (void)token_len;
    (void)user_data;
}

void
h3_chunk_client_save_session(const char *data, size_t data_len, void *user_data)
{
    (void)data;
    (void)data_len;
    (void)user_data;
}

void
h3_chunk_client_save_tp(const char *data, size_t data_len, void *user_data)
{
    (void)data;
    (void)data_len;
    (void)user_data;
}

int
h3_chunk_client_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *user_data)
{
    h3_chunk_client_worker_ctx *worker = (h3_chunk_client_worker_ctx *)user_data;

    if (worker == NULL) {
        return -1;
    }

    worker->h3_conn = h3_conn;
    memcpy(&worker->cid, cid, sizeof(*cid));
    return 0;
}

int
h3_chunk_client_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *user_data)
{
    h3_chunk_client_worker_ctx *worker = (h3_chunk_client_worker_ctx *)user_data;
    (void)cid;

    if (worker == NULL) {
        return 0;
    }

    if (!worker->result.success && worker->result.error_code == CHUNK_ERR_NONE) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_CONNECT, 0,
            "HTTP/3 connection closed before a valid ack, h3_err=%d",
            xqc_h3_conn_get_errno(h3_conn));
    }

    if (worker->eb != NULL) {
        event_base_loopbreak(worker->eb);
    }

    return 0;
}

void
h3_chunk_client_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    (void)user_data;
}

int
h3_chunk_client_request_send(xqc_h3_request_t *request, h3_chunk_client_request_ctx *request_ctx)
{
    h3_chunk_client_worker_ctx *worker;
    chunk_task *task;
    char content_len[32];
    char file_id[32];
    char file_size[32];
    char chunk_id[32];
    char chunk_count[32];
    char offset[32];
    char chunk_len[32];
    char crc32[32];
    xqc_http_header_t header[13];
    xqc_http_headers_t headers;
    ssize_t rc;

    if (request_ctx == NULL || request_ctx->worker == NULL) {
        return -1;
    }

    worker = request_ctx->worker;
    task = worker->task;

    if (!request_ctx->header_sent) {
        snprintf(content_len, sizeof(content_len), "%zu", request_ctx->body_len);
        snprintf(file_id, sizeof(file_id), "%" PRIu64, worker->file_id);
        snprintf(file_size, sizeof(file_size), "%" PRIu64, worker->file_size);
        snprintf(chunk_id, sizeof(chunk_id), "%u", task->chunk_id);
        snprintf(chunk_count, sizeof(chunk_count), "%u", task->chunk_count);
        snprintf(offset, sizeof(offset), "%" PRIu64, task->offset);
        snprintf(chunk_len, sizeof(chunk_len), "%u", task->chunk_len);
        snprintf(crc32, sizeof(crc32), "%u",
            chunk_crc32_buffer(request_ctx->body_buf, request_ctx->body_len));

        h3_chunk_set_header(&header[0], ":method", "POST");
        h3_chunk_set_header(&header[1], ":scheme", "https");
        h3_chunk_set_header(&header[2], "host", worker->config.server_host);
        h3_chunk_set_header(&header[3], ":path", H3_CHUNK_DEFAULT_PATH);
        h3_chunk_set_header(&header[4], "content-type", "application/octet-stream");
        h3_chunk_set_header(&header[5], "content-length", content_len);
        h3_chunk_set_header(&header[6], H3_CHUNK_HDR_FILE_ID, file_id);
        h3_chunk_set_header(&header[7], H3_CHUNK_HDR_FILE_SIZE, file_size);
        h3_chunk_set_header(&header[8], H3_CHUNK_HDR_CHUNK_ID, chunk_id);
        h3_chunk_set_header(&header[9], H3_CHUNK_HDR_CHUNK_COUNT, chunk_count);
        h3_chunk_set_header(&header[10], H3_CHUNK_HDR_OFFSET, offset);
        h3_chunk_set_header(&header[11], H3_CHUNK_HDR_CHUNK_LEN, chunk_len);
        h3_chunk_set_header(&header[12], H3_CHUNK_HDR_CRC32, crc32);

        memset(&headers, 0, sizeof(headers));
        headers.headers = header;
        headers.count = sizeof(header) / sizeof(header[0]);

        rc = xqc_h3_request_send_headers(request, &headers, request_ctx->body_len == 0);
        if (rc == -XQC_EAGAIN) {
            return 0;
        }
        if (rc < 0) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_STREAM, 0,
                "xqc_h3_request_send_headers failed, ret=%zd", rc);
            h3_chunk_client_force_close(worker);
            return 0;
        }
        request_ctx->header_sent = 1;
    }

    while (request_ctx->body_sent < request_ctx->body_len) {
        rc = xqc_h3_request_send_body(request,
            request_ctx->body_buf + request_ctx->body_sent,
            request_ctx->body_len - request_ctx->body_sent, 1);
        if (rc == -XQC_EAGAIN) {
            return 0;
        }
        if (rc < 0) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_STREAM, 0,
                "xqc_h3_request_send_body failed, ret=%zd", rc);
            h3_chunk_client_force_close(worker);
            return 0;
        }
        request_ctx->body_sent += (size_t)rc;
    }

    return 0;
}

int
h3_chunk_client_request_write_notify(xqc_h3_request_t *request, void *user_data)
{
    return h3_chunk_client_request_send(request, (h3_chunk_client_request_ctx *)user_data);
}

int
h3_chunk_client_request_read_notify(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flag, void *user_data)
{
    h3_chunk_client_request_ctx *request_ctx = (h3_chunk_client_request_ctx *)user_data;
    h3_chunk_client_worker_ctx *worker;
    chunk_ack_v1 ack;
    uint8_t fin = 0;
    uint8_t body_buf[128];
    ssize_t read_bytes;

    if (request_ctx == NULL || request_ctx->worker == NULL) {
        return -1;
    }

    worker = request_ctx->worker;

    if ((flag & XQC_REQ_NOTIFY_READ_HEADER) || (flag & XQC_REQ_NOTIFY_READ_TRAILER)) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(request, &fin);
        if (headers == NULL) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, 0,
                "xqc_h3_request_recv_headers failed");
            h3_chunk_client_force_close(worker);
            return 0;
        }

        if (!request_ctx->recv_header) {
            if (h3_chunk_parse_ack_headers(headers, &ack) != 0) {
                chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, 0,
                    "failed to parse HTTP/3 ack headers");
                h3_chunk_client_force_close(worker);
                return 0;
            }

            if (ack.file_id != worker->file_id || ack.chunk_id != worker->task->chunk_id) {
                chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, ack.status,
                    "ack does not match requested chunk");
                h3_chunk_client_force_close(worker);
                return 0;
            }

            worker->result.ack_received_len = ack.received_len;
            worker->result.ack_crc32 = ack.crc32;

            if (ack.status != CHUNK_STATUS_OK) {
                chunk_result_set(&worker->result, 0, CHUNK_ERR_SERVER, ack.status,
                    "server rejected chunk %u with status=%u",
                    worker->task->chunk_id, (unsigned int)ack.status);
                h3_chunk_client_force_close(worker);
                return 0;
            }

            if (ack.received_len != worker->task->chunk_len) {
                chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, ack.status,
                    "ack length mismatch, expected=%u actual=%u",
                    worker->task->chunk_len, ack.received_len);
                h3_chunk_client_force_close(worker);
                return 0;
            }

            if (ack.crc32 != chunk_crc32_buffer(request_ctx->body_buf, request_ctx->body_len)) {
                chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, ack.status,
                    "ack crc32 mismatch");
                h3_chunk_client_force_close(worker);
                return 0;
            }

            request_ctx->recv_header = 1;
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        do {
            read_bytes = xqc_h3_request_recv_body(request, body_buf, sizeof(body_buf), &fin);
            if (read_bytes == -XQC_EAGAIN) {
                break;
            }
            if (read_bytes < 0) {
                chunk_result_set(&worker->result, 0, CHUNK_ERR_STREAM, 0,
                    "xqc_h3_request_recv_body failed, ret=%zd", read_bytes);
                h3_chunk_client_force_close(worker);
                return 0;
            }
        } while (read_bytes > 0 && !fin);
    }

    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;
    }

    if (fin && request_ctx->recv_header) {
        request_ctx->recv_fin = 1;
        chunk_result_set(&worker->result, 1, CHUNK_ERR_NONE, CHUNK_STATUS_OK,
            "chunk %u completed", worker->task->chunk_id);
        h3_chunk_client_force_close(worker);
    }

    return 0;
}

int
h3_chunk_client_request_close_notify(xqc_h3_request_t *request, void *user_data)
{
    h3_chunk_client_request_ctx *request_ctx = (h3_chunk_client_request_ctx *)user_data;
    (void)request;

    if (request_ctx != NULL && request_ctx->worker != NULL
        && !request_ctx->worker->result.success
        && request_ctx->worker->result.error_code == CHUNK_ERR_NONE)
    {
        chunk_result_set(&request_ctx->worker->result, 0, CHUNK_ERR_STREAM, 0,
            "HTTP/3 request closed before success");
    }

    return 0;
}

void
h3_chunk_client_request_closing_notify(xqc_h3_request_t *request, xqc_int_t err,
    void *user_data)
{
    (void)request;
    (void)err;
    (void)user_data;
}
