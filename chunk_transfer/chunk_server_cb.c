#include "chunk_common.h"

static void
chunk_server_close_conn(server_conn_ctx *conn_ctx, uint64_t err_code)
{
    if (conn_ctx == NULL || conn_ctx->close_requested || conn_ctx->conn == NULL) {
        return;
    }

    conn_ctx->close_requested = 1;
    if (err_code == 0) {
        xqc_conn_close(conn_ctx->server->engine, &conn_ctx->cid);
    } else {
        xqc_conn_close_with_error(conn_ctx->conn, err_code);
    }
}

static int
chunk_server_prepare_ack(server_stream_ctx *stream_ctx, uint16_t status, uint32_t received_len,
    uint32_t crc32)
{
    chunk_ack_v1 ack;

    if (stream_ctx == NULL) {
        return -1;
    }

    memset(&ack, 0, sizeof(ack));
    ack.magic = CHUNK_PROTOCOL_MAGIC;
    ack.version = CHUNK_PROTOCOL_VERSION;
    ack.status = status;
    ack.file_id = stream_ctx->header.file_id;
    ack.chunk_id = stream_ctx->header.chunk_id;
    ack.received_len = received_len;
    ack.crc32 = crc32;

    if (chunk_ack_encode(&ack, stream_ctx->ack_buf, sizeof(stream_ctx->ack_buf)) < 0) {
        return -1;
    }

    stream_ctx->ack_len = CHUNK_ACK_V1_LEN;
    stream_ctx->ack_sent = 0;
    stream_ctx->ack_ready = 1;
    return 0;
}

static int
chunk_server_validate_header(server_stream_ctx *stream_ctx)
{
    file_assembly_ctx *assembly;
    uint64_t end_offset;

    if (stream_ctx->header.magic != CHUNK_PROTOCOL_MAGIC) {
        return CHUNK_STATUS_BAD_MAGIC;
    }
    if (stream_ctx->header.version != CHUNK_PROTOCOL_VERSION) {
        return CHUNK_STATUS_BAD_VERSION;
    }
    if (stream_ctx->header.header_len != CHUNK_HEADER_V1_LEN) {
        return CHUNK_STATUS_BAD_HEADER;
    }
    if (stream_ctx->header.chunk_count == 0
        || stream_ctx->header.chunk_id >= stream_ctx->header.chunk_count)
    {
        return CHUNK_STATUS_BAD_RANGE;
    }
    if (stream_ctx->header.offset > stream_ctx->header.file_size) {
        return CHUNK_STATUS_BAD_RANGE;
    }

    end_offset = stream_ctx->header.offset + stream_ctx->header.chunk_len;
    if (end_offset < stream_ctx->header.offset || end_offset > stream_ctx->header.file_size) {
        return CHUNK_STATUS_BAD_RANGE;
    }

    assembly = &stream_ctx->conn_ctx->server->assembly;
    if (!assembly->initialized) {
        assembly->file_id = stream_ctx->header.file_id;
        assembly->file_size = stream_ctx->header.file_size;
        assembly->chunk_count = stream_ctx->header.chunk_count;
        assembly->bitmap_len = chunk_bitmap_bytes(assembly->chunk_count);
        assembly->bitmap = (uint8_t *)calloc(1, assembly->bitmap_len);
        if (assembly->bitmap == NULL) {
            return CHUNK_STATUS_INTERNAL;
        }
        if (chunk_resize_file(assembly->fd, assembly->file_size) != 0) {
            return CHUNK_STATUS_IO_ERROR;
        }
        assembly->initialized = 1;
    } else if (assembly->file_id != stream_ctx->header.file_id
        || assembly->file_size != stream_ctx->header.file_size
        || assembly->chunk_count != stream_ctx->header.chunk_count)
    {
        return CHUNK_STATUS_BAD_HEADER;
    }

    stream_ctx->duplicate = chunk_bitmap_get(assembly->bitmap, stream_ctx->header.chunk_id);
    return CHUNK_STATUS_OK;
}

static int
chunk_server_finalize_chunk(server_stream_ctx *stream_ctx)
{
    file_assembly_ctx *assembly;
    uint32_t crc32;

    if (stream_ctx == NULL) {
        return CHUNK_STATUS_INTERNAL;
    }

    crc32 = chunk_crc32_final(stream_ctx->crc_state);
    if (crc32 != stream_ctx->header.crc32) {
        if (chunk_server_prepare_ack(stream_ctx, CHUNK_STATUS_BAD_CRC32,
                (uint32_t)stream_ctx->body_received, crc32) != 0)
        {
            return CHUNK_STATUS_INTERNAL;
        }
        return CHUNK_STATUS_BAD_CRC32;
    }

    if (!stream_ctx->duplicate && stream_ctx->header.chunk_len > 0) {
        if (chunk_write_all_at(stream_ctx->conn_ctx->server->assembly.fd, stream_ctx->body_buf,
                stream_ctx->header.chunk_len, stream_ctx->header.offset) != 0)
        {
            if (chunk_server_prepare_ack(stream_ctx, CHUNK_STATUS_IO_ERROR,
                    (uint32_t)stream_ctx->body_received, crc32) != 0)
            {
                return CHUNK_STATUS_INTERNAL;
            }
            return CHUNK_STATUS_IO_ERROR;
        }
    }

    assembly = &stream_ctx->conn_ctx->server->assembly;
    if (!stream_ctx->duplicate) {
        chunk_bitmap_set(assembly->bitmap, stream_ctx->header.chunk_id);
        assembly->received_count++;
        if (assembly->received_count == assembly->chunk_count && !assembly->completed) {
            if (chunk_fsync_file(assembly->fd) != 0) {
                if (chunk_server_prepare_ack(stream_ctx, CHUNK_STATUS_IO_ERROR,
                        stream_ctx->header.chunk_len, crc32) != 0)
                {
                    return CHUNK_STATUS_INTERNAL;
                }
                return CHUNK_STATUS_IO_ERROR;
            }
            assembly->completed = 1;
            chunk_log_print(stream_ctx->conn_ctx->server->config.log_level, CHUNK_LOG_INFO,
                "chunk_server", "file assembly completed file_id=%" PRIu64 " output=%s",
                assembly->file_id, stream_ctx->conn_ctx->server->config.output_path);
        }
    }

    if (chunk_server_prepare_ack(stream_ctx, CHUNK_STATUS_OK, stream_ctx->header.chunk_len,
            crc32) != 0)
    {
        return CHUNK_STATUS_INTERNAL;
    }

    return CHUNK_STATUS_OK;
}

void
chunk_server_engine_cb(int fd, short what, void *arg)
{
    chunk_server_ctx *ctx = (chunk_server_ctx *)arg;
    (void)fd;
    (void)what;

    if (ctx != NULL && ctx->engine != NULL) {
        xqc_engine_main_logic(ctx->engine);
    }
}

void
chunk_server_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    chunk_server_ctx *ctx = (chunk_server_ctx *)user_data;
    struct timeval tv;

    if (ctx == NULL || ctx->ev_engine == NULL) {
        return;
    }

    tv.tv_sec = (time_t)(wake_after / 1000000U);
    tv.tv_usec = (suseconds_t)(wake_after % 1000000U);
    event_add(ctx->ev_engine, &tv);
}

void
chunk_server_write_log(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data)
{
    chunk_server_ctx *ctx = (chunk_server_ctx *)engine_user_data;
    (void)lvl;
    (void)buf;
    (void)size;
    (void)ctx;
}

void
chunk_server_write_qlog(qlog_event_importance_t imp, const void *buf, size_t size,
    void *engine_user_data)
{
    chunk_server_ctx *ctx = (chunk_server_ctx *)engine_user_data;
    (void)imp;
    (void)buf;
    (void)size;
    (void)ctx;
}

void
chunk_server_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data)
{
    chunk_server_ctx *ctx = (chunk_server_ctx *)engine_user_data;
    (void)scid;
    (void)line;
    (void)ctx;
}

int
chunk_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data)
{
    chunk_server_ctx *ctx = (chunk_server_ctx *)user_data;
    server_conn_ctx *conn_ctx;
    (void)engine;

    conn_ctx = (server_conn_ctx *)calloc(1, sizeof(*conn_ctx));
    if (conn_ctx == NULL) {
        return -1;
    }

    conn_ctx->server = ctx;
    conn_ctx->conn = conn;
    memcpy(&conn_ctx->cid, cid, sizeof(*cid));
    xqc_conn_set_transport_user_data(conn, conn_ctx);
    return 0;
}

ssize_t
chunk_server_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    server_conn_ctx *conn_ctx = (server_conn_ctx *)conn_user_data;
    ssize_t rc;

    if (conn_ctx == NULL || conn_ctx->server == NULL) {
        return -1;
    }

    do {
        set_sys_errno(0);
        rc = sendto(conn_ctx->server->listen_fd, (const char *)buf, size, 0, peer_addr, peer_addrlen);
        if (rc < 0 && get_sys_errno() == EAGAIN) {
            return XQC_SOCKET_EAGAIN;
        }
    } while (rc < 0 && get_sys_errno() == EINTR);

    return rc;
}

ssize_t
chunk_server_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    (void)path_id;
    return chunk_server_write_socket(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

int
chunk_server_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data)
{
    server_conn_ctx *conn_ctx = (server_conn_ctx *)user_data;
    (void)conn_proto_data;

    if (conn_ctx == NULL) {
        return -1;
    }

    conn_ctx->conn = conn;
    memcpy(&conn_ctx->cid, cid, sizeof(*cid));
    xqc_conn_set_alp_user_data(conn, conn_ctx);
    return 0;
}

int
chunk_server_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data)
{
    server_conn_ctx *conn_ctx = (server_conn_ctx *)user_data;
    (void)conn;
    (void)cid;
    (void)conn_proto_data;

    free(conn_ctx);
    return 0;
}

void
chunk_server_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    (void)conn;
    (void)user_data;
    (void)conn_proto_data;
}

int
chunk_server_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    server_conn_ctx *conn_ctx = (server_conn_ctx *)xqc_get_conn_user_data_by_stream(stream);
    server_stream_ctx *stream_ctx;
    (void)user_data;

    if (conn_ctx == NULL) {
        return -1;
    }

    if (conn_ctx->stream_count >= 1U) {
        chunk_server_close_conn(conn_ctx, CHUNK_STATUS_BAD_STREAM);
        return -1;
    }

    stream_ctx = (server_stream_ctx *)calloc(1, sizeof(*stream_ctx));
    if (stream_ctx == NULL) {
        return -1;
    }

    stream_ctx->conn_ctx = conn_ctx;
    stream_ctx->stream = stream;
    stream_ctx->crc_state = chunk_crc32_init();
    xqc_stream_set_user_data(stream, stream_ctx);
    conn_ctx->stream_count++;
    return 0;
}

int
chunk_server_stream_send_ack(xqc_stream_t *stream, server_stream_ctx *stream_ctx)
{
    ssize_t rc;

    if (stream_ctx == NULL || !stream_ctx->ack_ready) {
        return 0;
    }

    while (stream_ctx->ack_sent < stream_ctx->ack_len) {
        rc = xqc_stream_send(stream, stream_ctx->ack_buf + stream_ctx->ack_sent,
            stream_ctx->ack_len - stream_ctx->ack_sent, 1);
        if (rc == -XQC_EAGAIN) {
            return 0;
        }
        if (rc < 0) {
            chunk_server_close_conn(stream_ctx->conn_ctx, CHUNK_STATUS_INTERNAL);
            return 0;
        }
        stream_ctx->ack_sent += (size_t)rc;
    }

    return 0;
}

int
chunk_server_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    return chunk_server_stream_send_ack(stream, (server_stream_ctx *)user_data);
}

int
chunk_server_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    server_stream_ctx *stream_ctx = (server_stream_ctx *)user_data;
    unsigned char fin = 0;
    uint8_t buf[4096];
    ssize_t read_bytes;
    int status;

    if (stream_ctx == NULL) {
        return -1;
    }

    if (stream_ctx->ack_ready) {
        return 0;
    }

    do {
        size_t consumed = 0;

        read_bytes = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
        if (read_bytes == -XQC_EAGAIN) {
            break;
        }
        if (read_bytes < 0) {
            chunk_server_close_conn(stream_ctx->conn_ctx, CHUNK_STATUS_INTERNAL);
            return 0;
        }

        while (consumed < (size_t)read_bytes) {
            if (!stream_ctx->header_parsed) {
                size_t need = CHUNK_HEADER_V1_LEN - stream_ctx->header_received;
                size_t copy_len = need < (size_t)read_bytes - consumed ? need : (size_t)read_bytes - consumed;
                memcpy(stream_ctx->header_buf + stream_ctx->header_received, buf + consumed, copy_len);
                stream_ctx->header_received += copy_len;
                consumed += copy_len;

                if (stream_ctx->header_received == CHUNK_HEADER_V1_LEN) {
                    if (chunk_header_decode(&stream_ctx->header, stream_ctx->header_buf,
                            sizeof(stream_ctx->header_buf)) != 0)
                    {
                        chunk_server_close_conn(stream_ctx->conn_ctx, CHUNK_STATUS_BAD_HEADER);
                        return 0;
                    }

                    status = chunk_server_validate_header(stream_ctx);
                    if (status != CHUNK_STATUS_OK) {
                        if (chunk_server_prepare_ack(stream_ctx, (uint16_t)status, 0,
                                stream_ctx->header.crc32) != 0)
                        {
                            chunk_server_close_conn(stream_ctx->conn_ctx, CHUNK_STATUS_INTERNAL);
                            return 0;
                        }
                        chunk_server_stream_send_ack(stream, stream_ctx);
                        return 0;
                    }

                    stream_ctx->header_parsed = 1;
                    if (!stream_ctx->duplicate && stream_ctx->header.chunk_len > 0) {
                        stream_ctx->body_buf = (uint8_t *)malloc(stream_ctx->header.chunk_len);
                        if (stream_ctx->body_buf == NULL) {
                            chunk_server_prepare_ack(stream_ctx, CHUNK_STATUS_INTERNAL, 0,
                                stream_ctx->header.crc32);
                            chunk_server_stream_send_ack(stream, stream_ctx);
                            return 0;
                        }
                    }
                }
            }

            if (stream_ctx->header_parsed && consumed < (size_t)read_bytes) {
                size_t remaining = stream_ctx->header.chunk_len - stream_ctx->body_received;
                size_t copy_len = (size_t)read_bytes - consumed;

                if (copy_len > remaining) {
                    chunk_server_prepare_ack(stream_ctx, CHUNK_STATUS_BAD_RANGE,
                        (uint32_t)stream_ctx->body_received, stream_ctx->header.crc32);
                    chunk_server_stream_send_ack(stream, stream_ctx);
                    return 0;
                }

                if (copy_len > 0) {
                    stream_ctx->crc_state = chunk_crc32_update(stream_ctx->crc_state,
                        buf + consumed, copy_len);
                    if (!stream_ctx->duplicate && stream_ctx->body_buf != NULL) {
                        memcpy(stream_ctx->body_buf + stream_ctx->body_received, buf + consumed, copy_len);
                    }
                    stream_ctx->body_received += copy_len;
                    consumed += copy_len;
                }
            }
        }

        if (stream_ctx->header_parsed && stream_ctx->body_received == stream_ctx->header.chunk_len && fin) {
            status = chunk_server_finalize_chunk(stream_ctx);
            if (status == CHUNK_STATUS_INTERNAL) {
                chunk_server_close_conn(stream_ctx->conn_ctx, CHUNK_STATUS_INTERNAL);
                return 0;
            }
            chunk_server_stream_send_ack(stream, stream_ctx);
            return 0;
        }

        if (fin && (!stream_ctx->header_parsed || stream_ctx->body_received != stream_ctx->header.chunk_len)) {
            if (stream_ctx->header_parsed) {
                chunk_server_prepare_ack(stream_ctx, CHUNK_STATUS_BAD_RANGE,
                    (uint32_t)stream_ctx->body_received, stream_ctx->header.crc32);
                chunk_server_stream_send_ack(stream, stream_ctx);
            } else {
                chunk_server_close_conn(stream_ctx->conn_ctx, CHUNK_STATUS_BAD_HEADER);
            }
            return 0;
        }
    } while (read_bytes > 0 && !fin);

    return 0;
}

int
chunk_server_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    server_stream_ctx *stream_ctx = (server_stream_ctx *)user_data;
    (void)stream;

    if (stream_ctx == NULL) {
        return 0;
    }

    if (stream_ctx->conn_ctx != NULL) {
        chunk_server_close_conn(stream_ctx->conn_ctx, 0);
    }

    free(stream_ctx->body_buf);
    free(stream_ctx);
    return 0;
}

int
chunk_server_register_alpn(xqc_engine_t *engine)
{
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = chunk_server_conn_create_notify,
            .conn_close_notify = chunk_server_conn_close_notify,
            .conn_handshake_finished = chunk_server_conn_handshake_finished,
        },
        .stream_cbs = {
            .stream_create_notify = chunk_server_stream_create_notify,
            .stream_write_notify = chunk_server_stream_write_notify,
            .stream_read_notify = chunk_server_stream_read_notify,
            .stream_close_notify = chunk_server_stream_close_notify,
        },
    };

    return xqc_engine_register_alpn(engine, CHUNK_ALPN, strlen(CHUNK_ALPN), &ap_cbs, NULL);
}
