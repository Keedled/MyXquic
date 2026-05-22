#include "h3_chunk_common.h"

H3_CHUNK_THREAD_LOCAL h3_chunk_server_worker_ctx *h3_chunk_current_server_worker = NULL;

static void
h3_chunk_server_close_conn(h3_chunk_server_conn_ctx *conn_ctx)
{
    if (conn_ctx == NULL || conn_ctx->close_requested || conn_ctx->worker == NULL
        || conn_ctx->worker->engine == NULL || conn_ctx->cid.cid_len == 0)
    {
        return;
    }

    conn_ctx->close_requested = 1;
    xqc_h3_conn_close(conn_ctx->worker->engine, &conn_ctx->cid);
}

static int
h3_chunk_server_validate_header(h3_chunk_server_request_ctx *request_ctx)
{
    h3_chunk_server_shared_ctx *shared;
    file_assembly_ctx *assembly;
    uint64_t end_offset;
    int status = CHUNK_STATUS_OK;

    if (request_ctx->header.magic != CHUNK_PROTOCOL_MAGIC) {
        return CHUNK_STATUS_BAD_MAGIC;
    }
    if (request_ctx->header.version != CHUNK_PROTOCOL_VERSION) {
        return CHUNK_STATUS_BAD_VERSION;
    }
    if (request_ctx->header.chunk_count == 0
        || request_ctx->header.chunk_id >= request_ctx->header.chunk_count)
    {
        return CHUNK_STATUS_BAD_RANGE;
    }
    if (request_ctx->header.offset > request_ctx->header.file_size) {
        return CHUNK_STATUS_BAD_RANGE;
    }

    end_offset = request_ctx->header.offset + request_ctx->header.chunk_len;
    if (end_offset < request_ctx->header.offset || end_offset > request_ctx->header.file_size) {
        return CHUNK_STATUS_BAD_RANGE;
    }

    shared = request_ctx->conn_ctx->worker->shared;
    assembly = &shared->assembly;
    pthread_mutex_lock(&shared->assembly_mutex);

    if (assembly->initialized
        && assembly->completed
        && assembly->file_id != request_ctx->header.file_id)
    {
        chunk_log_print(shared->config.log_level, CHUNK_LOG_INFO, "h3_chunk_server",
            "starting new file assembly file_id=%" PRIu64 " previous_file_id=%" PRIu64,
            request_ctx->header.file_id, assembly->file_id);
        chunk_assembly_reset(assembly);
    }

    if (!assembly->initialized) {
        assembly->file_id = request_ctx->header.file_id;
        assembly->file_size = request_ctx->header.file_size;
        assembly->chunk_count = request_ctx->header.chunk_count;
        assembly->bitmap_len = chunk_bitmap_bytes(assembly->chunk_count);
        assembly->bitmap = (uint8_t *)calloc(1, assembly->bitmap_len);
        if (assembly->bitmap == NULL) {
            status = CHUNK_STATUS_INTERNAL;
            goto finish;
        }
        if (chunk_resize_file(assembly->fd, assembly->file_size) != 0) {
            chunk_assembly_reset(assembly);
            status = CHUNK_STATUS_IO_ERROR;
            goto finish;
        }
        assembly->initialized = 1;
    } else if (assembly->file_id != request_ctx->header.file_id
        || assembly->file_size != request_ctx->header.file_size
        || assembly->chunk_count != request_ctx->header.chunk_count)
    {
        status = CHUNK_STATUS_BAD_HEADER;
        goto finish;
    }

    request_ctx->duplicate = chunk_bitmap_get(assembly->bitmap, request_ctx->header.chunk_id);

finish:
    pthread_mutex_unlock(&shared->assembly_mutex);
    return status;
}

static int
h3_chunk_server_finalize_request(h3_chunk_server_request_ctx *request_ctx)
{
    h3_chunk_server_shared_ctx *shared;
    file_assembly_ctx *assembly;
    uint32_t crc32;
    int status = CHUNK_STATUS_OK;

    if (request_ctx == NULL) {
        return CHUNK_STATUS_INTERNAL;
    }

    crc32 = chunk_crc32_final(request_ctx->crc_state);
    request_ctx->ack_crc32 = crc32;
    request_ctx->ack_received_len = (uint32_t)request_ctx->body_received;

    if (!request_ctx->header_parsed) {
        return CHUNK_STATUS_BAD_HEADER;
    }
    if (request_ctx->body_received != request_ctx->header.chunk_len) {
        return CHUNK_STATUS_BAD_RANGE;
    }
    if (crc32 != request_ctx->header.crc32) {
        return CHUNK_STATUS_BAD_CRC32;
    }

    shared = request_ctx->conn_ctx->worker->shared;
    assembly = &shared->assembly;

    pthread_mutex_lock(&shared->assembly_mutex);
    request_ctx->duplicate = chunk_bitmap_get(assembly->bitmap, request_ctx->header.chunk_id);
    if (!request_ctx->duplicate && request_ctx->header.chunk_len > 0) {
        if (chunk_write_all_at(assembly->fd, request_ctx->body_buf,
                request_ctx->header.chunk_len, request_ctx->header.offset) != 0)
        {
            status = CHUNK_STATUS_IO_ERROR;
            goto finish;
        }
    }

    if (!request_ctx->duplicate) {
        chunk_bitmap_set(assembly->bitmap, request_ctx->header.chunk_id);
        assembly->received_count++;
        if (assembly->received_count == assembly->chunk_count && !assembly->completed) {
            if (chunk_fsync_file(assembly->fd) != 0) {
                status = CHUNK_STATUS_IO_ERROR;
                goto finish;
            }
            assembly->completed = 1;
            chunk_log_print(shared->config.log_level, CHUNK_LOG_INFO,
                "h3_chunk_server", "file assembly completed file_id=%" PRIu64 " output=%s",
                assembly->file_id, shared->config.output_path);
        }
    }

finish:
    pthread_mutex_unlock(&shared->assembly_mutex);
    return status;
}

static void
h3_chunk_server_prepare_ack(h3_chunk_server_request_ctx *request_ctx, uint16_t status)
{
    request_ctx->ack_status = status;
    request_ctx->ack_ready = 1;
}

void
h3_chunk_server_engine_cb(int fd, short what, void *arg)
{
    h3_chunk_server_worker_ctx *worker = (h3_chunk_server_worker_ctx *)arg;
    (void)fd;
    (void)what;

    if (worker != NULL && worker->engine != NULL) {
        xqc_engine_main_logic(worker->engine);
    }
}

void
h3_chunk_server_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    h3_chunk_server_worker_ctx *worker = (h3_chunk_server_worker_ctx *)user_data;
    struct timeval tv;

    if (worker == NULL || worker->ev_engine == NULL) {
        return;
    }

    tv.tv_sec = (time_t)(wake_after / 1000000U);
    tv.tv_usec = (suseconds_t)(wake_after % 1000000U);
    event_add(worker->ev_engine, &tv);
}

void
h3_chunk_server_write_log(xqc_log_level_t lvl, const void *buf, size_t size,
    void *engine_user_data)
{
    (void)lvl;
    (void)buf;
    (void)size;
    (void)engine_user_data;
}

void
h3_chunk_server_write_qlog(qlog_event_importance_t imp, const void *buf, size_t size,
    void *engine_user_data)
{
    (void)imp;
    (void)buf;
    (void)size;
    (void)engine_user_data;
}

void
h3_chunk_server_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data)
{
    (void)scid;
    (void)line;
    (void)engine_user_data;
}

int
h3_chunk_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data)
{
    h3_chunk_server_worker_ctx *worker = (h3_chunk_server_worker_ctx *)user_data;
    h3_chunk_server_conn_ctx *conn_ctx;
    (void)engine;

    if (worker == NULL || worker->magic != H3_CHUNK_SERVER_WORKER_MAGIC) {
        worker = h3_chunk_current_server_worker;
    }
    if (worker == NULL) {
        return -1;
    }

    conn_ctx = (h3_chunk_server_conn_ctx *)calloc(1, sizeof(*conn_ctx));
    if (conn_ctx == NULL) {
        return -1;
    }

    conn_ctx->magic = H3_CHUNK_SERVER_CONN_MAGIC;
    conn_ctx->worker = worker;
    memcpy(&conn_ctx->cid, cid, sizeof(*cid));
    xqc_conn_set_transport_user_data(conn, conn_ctx);
    return 0;
}

ssize_t
h3_chunk_server_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    return h3_chunk_server_write_socket_ex(0, buf, size, peer_addr, peer_addrlen,
        conn_user_data);
}

ssize_t
h3_chunk_server_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    h3_chunk_server_conn_ctx *conn_ctx = (h3_chunk_server_conn_ctx *)conn_user_data;
    h3_chunk_server_worker_ctx *worker;
    ssize_t rc;
    (void)path_id;

    if (conn_ctx != NULL && conn_ctx->magic == H3_CHUNK_SERVER_CONN_MAGIC) {
        worker = conn_ctx->worker;
    } else if (conn_user_data != NULL
        && ((h3_chunk_server_worker_ctx *)conn_user_data)->magic == H3_CHUNK_SERVER_WORKER_MAGIC)
    {
        worker = (h3_chunk_server_worker_ctx *)conn_user_data;
    } else {
        worker = h3_chunk_current_server_worker;
    }
    if (worker == NULL) {
        return -1;
    }

    do {
        set_sys_errno(0);
        rc = sendto(worker->listen_fd, (const char *)buf, size, 0, peer_addr, peer_addrlen);
        if (rc < 0 && get_sys_errno() == EAGAIN) {
            return XQC_SOCKET_EAGAIN;
        }
    } while (rc < 0 && get_sys_errno() == EINTR);

    return rc;
}

int
h3_chunk_server_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *user_data)
{
    h3_chunk_server_worker_ctx *worker = NULL;
    h3_chunk_server_conn_ctx *existing_conn_ctx = NULL;
    h3_chunk_server_conn_ctx *conn_ctx;

    if (user_data != NULL
        && ((h3_chunk_server_conn_ctx *)user_data)->magic == H3_CHUNK_SERVER_CONN_MAGIC)
    {
        existing_conn_ctx = (h3_chunk_server_conn_ctx *)user_data;
        worker = existing_conn_ctx->worker;

    } else if (user_data != NULL
        && ((h3_chunk_server_worker_ctx *)user_data)->magic == H3_CHUNK_SERVER_WORKER_MAGIC)
    {
        worker = (h3_chunk_server_worker_ctx *)user_data;
    }

    if (worker == NULL) {
        worker = h3_chunk_current_server_worker;
    }
    if (worker == NULL) {
        return -1;
    }

    if (existing_conn_ctx != NULL) {
        conn_ctx = existing_conn_ctx;

    } else {
        conn_ctx = (h3_chunk_server_conn_ctx *)calloc(1, sizeof(*conn_ctx));
        if (conn_ctx == NULL) {
            return -1;
        }
        conn_ctx->magic = H3_CHUNK_SERVER_CONN_MAGIC;
        conn_ctx->worker = worker;
        memcpy(&conn_ctx->cid, cid, sizeof(*cid));
    }

    conn_ctx->h3_conn = h3_conn;
    xqc_h3_conn_set_user_data(h3_conn, conn_ctx);
    return 0;
}

int
h3_chunk_server_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *user_data)
{
    h3_chunk_server_conn_ctx *conn_ctx = (h3_chunk_server_conn_ctx *)user_data;
    (void)h3_conn;
    (void)cid;

    free(conn_ctx);
    return 0;
}

void
h3_chunk_server_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    (void)user_data;
}

int
h3_chunk_server_request_create_notify(xqc_h3_request_t *request, void *user_data)
{
    h3_chunk_server_conn_ctx *conn_ctx;
    h3_chunk_server_request_ctx *request_ctx;
    (void)user_data;

    conn_ctx = (h3_chunk_server_conn_ctx *)xqc_h3_get_conn_user_data_by_request(request);
    if (conn_ctx == NULL) {
        return -1;
    }

    request_ctx = (h3_chunk_server_request_ctx *)calloc(1, sizeof(*request_ctx));
    if (request_ctx == NULL) {
        return -1;
    }

    request_ctx->conn_ctx = conn_ctx;
    request_ctx->request = request;
    request_ctx->crc_state = chunk_crc32_init();
    xqc_h3_request_set_user_data(request, request_ctx);
    return 0;
}

int
h3_chunk_server_request_send_response(h3_chunk_server_request_ctx *request_ctx)
{
    char status_code[8];
    char ack_status[16];
    char file_id[32];
    char chunk_id[32];
    char received_len[32];
    char crc32[32];
    xqc_http_header_t header[6];
    xqc_http_headers_t headers;
    ssize_t rc;

    if (request_ctx == NULL || !request_ctx->ack_ready || request_ctx->response_sent) {
        return 0;
    }

    snprintf(status_code, sizeof(status_code), "%u",
        request_ctx->ack_status == CHUNK_STATUS_OK ? 200U : 400U);
    snprintf(ack_status, sizeof(ack_status), "%u", request_ctx->ack_status);
    snprintf(file_id, sizeof(file_id), "%" PRIu64, request_ctx->header.file_id);
    snprintf(chunk_id, sizeof(chunk_id), "%u", request_ctx->header.chunk_id);
    snprintf(received_len, sizeof(received_len), "%u", request_ctx->ack_received_len);
    snprintf(crc32, sizeof(crc32), "%u", request_ctx->ack_crc32);

    h3_chunk_set_header(&header[0], ":status", status_code);
    h3_chunk_set_header(&header[1], H3_CHUNK_HDR_STATUS, ack_status);
    h3_chunk_set_header(&header[2], H3_CHUNK_HDR_FILE_ID, file_id);
    h3_chunk_set_header(&header[3], H3_CHUNK_HDR_CHUNK_ID, chunk_id);
    h3_chunk_set_header(&header[4], H3_CHUNK_HDR_RECEIVED_LEN, received_len);
    h3_chunk_set_header(&header[5], H3_CHUNK_HDR_CRC32, crc32);

    memset(&headers, 0, sizeof(headers));
    headers.headers = header;
    headers.count = sizeof(header) / sizeof(header[0]);

    rc = xqc_h3_request_send_headers(request_ctx->request, &headers, 1);
    if (rc == -XQC_EAGAIN) {
        return 0;
    }
    if (rc < 0) {
        request_ctx->failed = 1;
        h3_chunk_server_close_conn(request_ctx->conn_ctx);
        return 0;
    }

    request_ctx->response_sent = 1;
    return 0;
}

int
h3_chunk_server_request_write_notify(xqc_h3_request_t *request, void *user_data)
{
    (void)request;
    return h3_chunk_server_request_send_response((h3_chunk_server_request_ctx *)user_data);
}

int
h3_chunk_server_request_read_notify(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flag, void *user_data)
{
    h3_chunk_server_request_ctx *request_ctx = (h3_chunk_server_request_ctx *)user_data;
    uint8_t fin = 0;
    uint8_t buf[4096];
    ssize_t read_bytes;

    if (request_ctx == NULL || request_ctx->ack_ready) {
        return 0;
    }

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(request, &fin);
        int status;

        if (headers == NULL || h3_chunk_parse_request_headers(headers, &request_ctx->header) != 0) {
            h3_chunk_server_prepare_ack(request_ctx, CHUNK_STATUS_BAD_HEADER);
            h3_chunk_server_request_send_response(request_ctx);
            return 0;
        }

        request_ctx->header_parsed = 1;
        status = h3_chunk_server_validate_header(request_ctx);
        if (status != CHUNK_STATUS_OK) {
            h3_chunk_server_prepare_ack(request_ctx, (uint16_t)status);
            h3_chunk_server_request_send_response(request_ctx);
            return 0;
        }

        if (request_ctx->header.chunk_len > 0) {
            request_ctx->body_buf = (uint8_t *)malloc(request_ctx->header.chunk_len);
            if (request_ctx->body_buf == NULL) {
                h3_chunk_server_prepare_ack(request_ctx, CHUNK_STATUS_INTERNAL);
                h3_chunk_server_request_send_response(request_ctx);
                return 0;
            }
        }
    }

    if ((flag & XQC_REQ_NOTIFY_READ_BODY) && request_ctx->header_parsed) {
        do {
            read_bytes = xqc_h3_request_recv_body(request, buf, sizeof(buf), &fin);
            if (read_bytes == -XQC_EAGAIN) {
                break;
            }
            if (read_bytes < 0) {
                h3_chunk_server_prepare_ack(request_ctx, CHUNK_STATUS_INTERNAL);
                h3_chunk_server_request_send_response(request_ctx);
                return 0;
            }

            if (request_ctx->body_received + (size_t)read_bytes > request_ctx->header.chunk_len) {
                h3_chunk_server_prepare_ack(request_ctx, CHUNK_STATUS_BAD_RANGE);
                h3_chunk_server_request_send_response(request_ctx);
                return 0;
            }

            if (read_bytes > 0) {
                if (request_ctx->body_buf != NULL) {
                    memcpy(request_ctx->body_buf + request_ctx->body_received, buf,
                        (size_t)read_bytes);
                }
                request_ctx->crc_state = chunk_crc32_update(request_ctx->crc_state, buf,
                    (size_t)read_bytes);
                request_ctx->body_received += (size_t)read_bytes;
            }
        } while (read_bytes > 0 && !fin);
    }

    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;
    }

    if (fin && request_ctx->header_parsed && !request_ctx->ack_ready) {
        int status = h3_chunk_server_finalize_request(request_ctx);
        h3_chunk_server_prepare_ack(request_ctx, (uint16_t)status);
        h3_chunk_server_request_send_response(request_ctx);
    }

    return 0;
}

int
h3_chunk_server_request_close_notify(xqc_h3_request_t *request, void *user_data)
{
    h3_chunk_server_request_ctx *request_ctx = (h3_chunk_server_request_ctx *)user_data;
    (void)request;

    if (request_ctx != NULL) {
        free(request_ctx->body_buf);
        free(request_ctx);
    }

    return 0;
}
