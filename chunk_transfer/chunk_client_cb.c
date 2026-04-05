#include "chunk_common.h"

static void
chunk_client_force_close(chunk_worker_ctx *worker)
{
    if (worker == NULL || worker->close_requested) {
        return;
    }

    worker->close_requested = 1;

    if (worker->engine != NULL && worker->cid.cid_len > 0) {
        xqc_conn_close(worker->engine, &worker->cid);
        xqc_engine_main_logic(worker->engine);
    } else if (worker->eb != NULL) {
        event_base_loopbreak(worker->eb);
    }
}

void
chunk_client_engine_cb(int fd, short what, void *arg)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)arg;
    (void)fd;
    (void)what;

    if (worker != NULL && worker->engine != NULL) {
        xqc_engine_main_logic(worker->engine);
    }
}

void
chunk_client_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)user_data;
    struct timeval tv;

    if (worker == NULL || worker->ev_engine == NULL) {
        return;
    }

    tv.tv_sec = (time_t)(wake_after / 1000000U);
    tv.tv_usec = (suseconds_t)(wake_after % 1000000U);
    event_add(worker->ev_engine, &tv);
}

void
chunk_client_write_log(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)engine_user_data;
    (void)lvl;
    (void)buf;
    (void)size;
    (void)worker;
}

void
chunk_client_write_qlog(qlog_event_importance_t imp, const void *buf, size_t size,
    void *engine_user_data)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)engine_user_data;
    (void)imp;
    (void)buf;
    (void)size;
    (void)worker;
}

void
chunk_client_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)engine_user_data;
    (void)scid;
    (void)line;
    (void)worker;
}

ssize_t
chunk_client_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    return chunk_client_write_socket_ex(0, buf, size, peer_addr, peer_addrlen, conn_user_data);
}

ssize_t
chunk_client_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)conn_user_data;
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
chunk_client_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    (void)token;
    (void)token_len;
    (void)user_data;
}

void
chunk_client_save_session(const char *data, size_t data_len, void *user_data)
{
    (void)data;
    (void)data_len;
    (void)user_data;
}

void
chunk_client_save_tp(const char *data, size_t data_len, void *user_data)
{
    (void)data;
    (void)data_len;
    (void)user_data;
}

int
chunk_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)user_data;
    (void)conn_proto_data;

    if (worker == NULL) {
        return -1;
    }

    worker->conn = conn;
    memcpy(&worker->cid, cid, sizeof(*cid));
    xqc_conn_set_alp_user_data(conn, worker);
    return 0;
}

int
chunk_client_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)user_data;
    (void)cid;
    (void)conn_proto_data;

    if (worker == NULL) {
        return 0;
    }

    if (!worker->result.success && worker->result.error_code == CHUNK_ERR_NONE) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_CONNECT, 0,
            "connection closed before a valid ack, conn_err=%d", xqc_conn_get_errno(conn));
    }

    if (worker->eb != NULL) {
        event_base_loopbreak(worker->eb);
    }

    return 0;
}

void
chunk_client_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    (void)conn;
    (void)user_data;
    (void)conn_proto_data;
}

int
chunk_client_stream_send(xqc_stream_t *stream, chunk_stream_ctx *stream_ctx)
{
    ssize_t rc;
    int fin;

    if (stream_ctx == NULL || stream_ctx->worker == NULL) {
        return -1;
    }

    while (stream_ctx->header_sent < stream_ctx->header_len) {
        fin = stream_ctx->body_len == 0 ? 1 : 0;
        rc = xqc_stream_send(stream, stream_ctx->header_buf + stream_ctx->header_sent,
            stream_ctx->header_len - stream_ctx->header_sent, (uint8_t)fin);
        if (rc == -XQC_EAGAIN) {
            return 0;
        }
        if (rc < 0) {
            chunk_result_set(&stream_ctx->worker->result, 0, CHUNK_ERR_STREAM, 0,
                "failed to send chunk header, ret=%zd", rc);
            chunk_client_force_close(stream_ctx->worker);
            return 0;
        }
        stream_ctx->header_sent += (size_t)rc;
    }

    while (stream_ctx->body_sent < stream_ctx->body_len) {
        rc = xqc_stream_send(stream, stream_ctx->body_buf + stream_ctx->body_sent,
            stream_ctx->body_len - stream_ctx->body_sent, 1);
        if (rc == -XQC_EAGAIN) {
            return 0;
        }
        if (rc < 0) {
            chunk_result_set(&stream_ctx->worker->result, 0, CHUNK_ERR_STREAM, 0,
                "failed to send chunk body, ret=%zd", rc);
            chunk_client_force_close(stream_ctx->worker);
            return 0;
        }
        stream_ctx->body_sent += (size_t)rc;
    }

    return 0;
}

int
chunk_client_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    return chunk_client_stream_send(stream, (chunk_stream_ctx *)user_data);
}

int
chunk_client_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    chunk_stream_ctx *stream_ctx = (chunk_stream_ctx *)user_data;
    chunk_worker_ctx *worker;
    chunk_ack_v1 ack;
    unsigned char fin = 0;
    uint8_t buf[512];
    ssize_t read_bytes;

    if (stream_ctx == NULL || stream_ctx->worker == NULL) {
        return -1;
    }

    worker = stream_ctx->worker;

    do {
        read_bytes = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
        if (read_bytes == -XQC_EAGAIN) {
            break;
        }
        if (read_bytes < 0) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_STREAM, 0,
                "failed to receive ack, ret=%zd", read_bytes);
            chunk_client_force_close(worker);
            return 0;
        }

        if (stream_ctx->ack_received + (size_t)read_bytes > sizeof(stream_ctx->ack_buf)) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, 0,
                "ack is larger than expected");
            chunk_client_force_close(worker);
            return 0;
        }

        memcpy(stream_ctx->ack_buf + stream_ctx->ack_received, buf, (size_t)read_bytes);
        stream_ctx->ack_received += (size_t)read_bytes;
    } while (read_bytes > 0 && !fin);

    if (stream_ctx->ack_received == CHUNK_ACK_V1_LEN) {
        if (chunk_ack_decode(&ack, stream_ctx->ack_buf, sizeof(stream_ctx->ack_buf)) != 0) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, 0, "failed to decode ack");
            chunk_client_force_close(worker);
            return 0;
        }

        if (ack.magic != CHUNK_PROTOCOL_MAGIC || ack.version != CHUNK_PROTOCOL_VERSION) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, ack.status,
                "invalid ack magic/version");
            chunk_client_force_close(worker);
            return 0;
        }

        if (ack.file_id != worker->file_id || ack.chunk_id != worker->task->chunk_id) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, ack.status,
                "ack does not match the requested chunk");
            chunk_client_force_close(worker);
            return 0;
        }

        worker->result.ack_received_len = ack.received_len;
        worker->result.ack_crc32 = ack.crc32;

        if (ack.status != CHUNK_STATUS_OK) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_SERVER, ack.status,
                "server rejected chunk %u with status=%u",
                worker->task->chunk_id, (unsigned int)ack.status);
            chunk_client_force_close(worker);
            return 0;
        }

        if (ack.received_len != worker->task->chunk_len) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, ack.status,
                "ack length mismatch, expected=%u actual=%u",
                worker->task->chunk_len, ack.received_len);
            chunk_client_force_close(worker);
            return 0;
        }

        if (ack.crc32 != chunk_crc32_buffer(stream_ctx->body_buf, stream_ctx->body_len)) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, ack.status,
                "ack crc32 mismatch");
            chunk_client_force_close(worker);
            return 0;
        }

        chunk_result_set(&worker->result, 1, CHUNK_ERR_NONE, CHUNK_STATUS_OK,
            "chunk %u completed", worker->task->chunk_id);
        chunk_client_force_close(worker);
    } else if (fin) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_ACK, 0,
            "stream finished before a full ack was received");
        chunk_client_force_close(worker);
    }

    return 0;
}

int
chunk_client_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    chunk_stream_ctx *stream_ctx = (chunk_stream_ctx *)user_data;
    (void)stream;

    if (stream_ctx != NULL && stream_ctx->worker != NULL
        && !stream_ctx->worker->result.success
        && stream_ctx->worker->result.error_code == CHUNK_ERR_NONE)
    {
        chunk_result_set(&stream_ctx->worker->result, 0, CHUNK_ERR_STREAM, 0,
            "stream closed before success");
    }

    return 0;
}

int
chunk_client_register_alpn(xqc_engine_t *engine)
{
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = chunk_client_conn_create_notify,
            .conn_close_notify = chunk_client_conn_close_notify,
            .conn_handshake_finished = chunk_client_conn_handshake_finished,
        },
        .stream_cbs = {
            .stream_write_notify = chunk_client_stream_write_notify,
            .stream_read_notify = chunk_client_stream_read_notify,
            .stream_close_notify = chunk_client_stream_close_notify,
        },
    };

    return xqc_engine_register_alpn(engine, CHUNK_ALPN, strlen(CHUNK_ALPN), &ap_cbs, NULL);
}
