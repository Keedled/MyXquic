#include "chunk_common.h"

static void
chunk_client_socket_read_handler(chunk_worker_ctx *worker, int fd)
{
    ssize_t recv_size;
    uint8_t packet_buf[CHUNK_PACKET_BUF_LEN];
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    xqc_int_t rc;
    uint64_t recv_time;

    if (worker == NULL || worker->engine == NULL) {
        return;
    }

    do {
        peer_addrlen = sizeof(peer_addr);
        recv_size = recvfrom(fd, (char *)packet_buf, sizeof(packet_buf), 0,
            (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }
        if (recv_size < 0) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_SOCKET, 0,
                "recvfrom failed, errno=%d", get_sys_errno());
            worker->close_requested = 1;
            if (worker->eb != NULL) {
                event_base_loopbreak(worker->eb);
            }
            return;
        }

        recv_time = xqc_now();
        rc = xqc_engine_packet_process(worker->engine, packet_buf, (size_t)recv_size,
            (struct sockaddr *)&worker->local_addr, worker->local_addrlen,
            (struct sockaddr *)&peer_addr, peer_addrlen, (xqc_usec_t)recv_time, worker);
        if (rc != XQC_OK) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_ENGINE, 0,
                "xqc_engine_packet_process failed, ret=%d", rc);
            worker->close_requested = 1;
            if (worker->eb != NULL) {
                event_base_loopbreak(worker->eb);
            }
            return;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(worker->engine);
}

static void
chunk_client_socket_event_callback(int fd, short what, void *arg)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)arg;

    if (what & EV_READ) {
        chunk_client_socket_read_handler(worker, fd);
    }
}

static void
chunk_client_timeout_callback(int fd, short what, void *arg)
{
    chunk_worker_ctx *worker = (chunk_worker_ctx *)arg;
    (void)fd;
    (void)what;

    if (worker == NULL || worker->result.success) {
        return;
    }

    chunk_result_set(&worker->result, 0, CHUNK_ERR_TIMEOUT, 0,
        "chunk %u timed out after %u seconds",
        worker->task->chunk_id, worker->config.timeout_sec);

    if (!worker->close_requested && worker->engine != NULL && worker->cid.cid_len > 0) {
        worker->close_requested = 1;
        xqc_conn_close(worker->engine, &worker->cid);
        xqc_engine_main_logic(worker->engine);
    } else if (worker->eb != NULL) {
        event_base_loopbreak(worker->eb);
    }
}

static int
chunk_client_prepare_stream(chunk_worker_ctx *worker)
{
    chunk_header_v1 header;
    chunk_stream_ctx *stream_ctx;

    stream_ctx = &worker->stream_ctx;
    memset(stream_ctx, 0, sizeof(*stream_ctx));
    stream_ctx->worker = worker;
    stream_ctx->header_len = CHUNK_HEADER_V1_LEN;

    if (worker->task->chunk_len > 0) {
        stream_ctx->body_buf = (uint8_t *)malloc(worker->task->chunk_len);
        if (stream_ctx->body_buf == NULL) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_IO, 0,
                "failed to allocate chunk buffer");
            return -1;
        }

        if (chunk_read_chunk_file(worker->config.input_path, worker->task->offset,
                stream_ctx->body_buf, worker->task->chunk_len) != 0)
        {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_IO, 0,
                "failed to read input file");
            return -1;
        }
    }

    stream_ctx->body_len = worker->task->chunk_len;

    memset(&header, 0, sizeof(header));
    header.magic = CHUNK_PROTOCOL_MAGIC;
    header.version = CHUNK_PROTOCOL_VERSION;
    header.header_len = CHUNK_HEADER_V1_LEN;
    header.file_id = worker->file_id;
    header.file_size = worker->file_size;
    header.chunk_id = worker->task->chunk_id;
    header.chunk_count = worker->task->chunk_count;
    header.offset = worker->task->offset;
    header.chunk_len = worker->task->chunk_len;
    header.crc32 = chunk_crc32_buffer(stream_ctx->body_buf, stream_ctx->body_len);

    if (chunk_header_encode(&header, stream_ctx->header_buf, sizeof(stream_ctx->header_buf)) < 0) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_PROTOCOL, 0,
            "failed to encode chunk header");
        return -1;
    }

    worker->result.ack_crc32 = header.crc32;
    return 0;
}

static int
chunk_client_init_engine(chunk_worker_ctx *worker)
{
    xqc_config_t config;
    xqc_engine_callback_t callbacks = {
        .set_event_timer = chunk_client_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = chunk_client_write_log,
            .xqc_log_write_stat = chunk_client_write_log,
            .xqc_qlog_event_write = chunk_client_write_qlog,
        },
        .keylog_cb = chunk_client_keylog_cb,
    };
    xqc_transport_callbacks_t transport_cbs = {
        .write_socket = chunk_client_write_socket,
        .write_socket_ex = chunk_client_write_socket_ex,
        .save_token = chunk_client_save_token,
        .save_session_cb = chunk_client_save_session,
        .save_tp_cb = chunk_client_save_tp,
    };
    xqc_engine_ssl_config_t ssl_cfg = {
        .ciphers = XQC_TLS_CIPHERS,
        .groups = XQC_TLS_GROUPS,
    };

    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_ENGINE, 0,
            "failed to load default xquic config");
        return -1;
    }

    config.cfg_log_level = (xqc_log_level_t)worker->config.log_level;

    worker->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &ssl_cfg,
        &callbacks, &transport_cbs, worker);
    if (worker->engine == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_ENGINE, 0,
            "xqc_engine_create failed");
        return -1;
    }

    worker->ev_engine = event_new(worker->eb, -1, 0, chunk_client_engine_cb, worker);
    if (worker->ev_engine == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_ENGINE, 0,
            "failed to create engine timer event");
        return -1;
    }

    if (chunk_client_register_alpn(worker->engine) != XQC_OK) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_ENGINE, 0,
            "failed to register chunk-transfer alpn");
        return -1;
    }

    return 0;
}

static int
chunk_client_init_connection(chunk_worker_ctx *worker)
{
    const xqc_cid_t *cid;
    xqc_conn_settings_t conn_settings;
    xqc_conn_ssl_config_t conn_ssl_config;

    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.cong_ctrl_callback = xqc_bbr_cb;
    conn_settings.cc_params.customize_on = 1;
    conn_settings.cc_params.init_cwnd = 32;
    conn_settings.so_sndbuf = CHUNK_SOCKET_BUF_SIZE;
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.init_idle_time_out = worker->config.timeout_sec * 1000U;
    conn_settings.idle_time_out = worker->config.timeout_sec * 1000U;
    conn_settings.spurious_loss_detect_on = 1;
    conn_settings.anti_amplification_limit = 4;
    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    conn_settings.reinj_ctl_callback = xqc_deadline_reinj_ctl_cb;
    conn_settings.adaptive_ack_frequency = 1;

    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    cid = xqc_connect(worker->engine, &conn_settings, NULL, 0, worker->config.server_host, 0,
        &conn_ssl_config, (struct sockaddr *)&worker->peer_addr, worker->peer_addrlen,
        CHUNK_ALPN, worker);
    if (cid == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_CONNECT, 0,
            "xqc_connect failed");
        return -1;
    }

    memcpy(&worker->cid, cid, sizeof(*cid));
    worker->stream_ctx.stream = xqc_stream_create(worker->engine, &worker->cid, NULL,
        &worker->stream_ctx);
    if (worker->stream_ctx.stream == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_STREAM, 0,
            "xqc_stream_create failed");
        return -1;
    }

    if (chunk_client_stream_send(worker->stream_ctx.stream, &worker->stream_ctx) != 0) {
        return -1;
    }

    xqc_engine_main_logic(worker->engine);
    return 0;
}

static void
chunk_client_cleanup(chunk_worker_ctx *worker)
{
    if (worker->ev_socket != NULL) {
        event_del(worker->ev_socket);
        event_free(worker->ev_socket);
        worker->ev_socket = NULL;
    }

    if (worker->ev_timeout != NULL) {
        event_del(worker->ev_timeout);
        event_free(worker->ev_timeout);
        worker->ev_timeout = NULL;
    }

    if (worker->ev_engine != NULL) {
        event_free(worker->ev_engine);
        worker->ev_engine = NULL;
    }

    if (worker->engine != NULL) {
        xqc_engine_destroy(worker->engine);
        worker->engine = NULL;
    }

    if (worker->fd >= 0) {
        close(worker->fd);
        worker->fd = -1;
    }

    if (worker->stream_ctx.body_buf != NULL) {
        free(worker->stream_ctx.body_buf);
        worker->stream_ctx.body_buf = NULL;
    }

    if (worker->eb != NULL) {
        event_base_free(worker->eb);
        worker->eb = NULL;
    }
}

int
chunk_client_run_worker(chunk_worker_ctx *worker)
{
    struct timeval tv;

    if (worker == NULL) {
        return -1;
    }

    worker->fd = -1;
    worker->eb = event_base_new();
    if (worker->eb == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_ENGINE, 0,
            "failed to create event base");
        goto finish;
    }

    if (chunk_parse_address(worker->config.server_addr, worker->config.server_port,
            &worker->peer_addr, &worker->peer_addrlen) != 0)
    {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_SOCKET, 0,
            "failed to resolve server address");
        goto finish;
    }

    worker->fd = chunk_create_udp_socket(NULL, 0, (struct sockaddr *)&worker->peer_addr,
        worker->peer_addrlen, 0, 1);
    if (worker->fd < 0) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_SOCKET, 0,
            "failed to create client udp socket");
        goto finish;
    }

    if (chunk_get_local_addr(worker->fd, &worker->local_addr, &worker->local_addrlen) != 0) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_SOCKET, 0,
            "failed to get client local address");
        goto finish;
    }

    worker->ev_socket = event_new(worker->eb, worker->fd, EV_READ | EV_PERSIST,
        chunk_client_socket_event_callback, worker);
    if (worker->ev_socket == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_SOCKET, 0,
            "failed to create socket event");
        goto finish;
    }
    event_add(worker->ev_socket, NULL);

    worker->ev_timeout = event_new(worker->eb, -1, 0, chunk_client_timeout_callback, worker);
    if (worker->ev_timeout == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_TIMEOUT, 0,
            "failed to create timeout event");
        goto finish;
    }
    tv.tv_sec = (time_t)worker->config.timeout_sec;
    tv.tv_usec = 0;
    event_add(worker->ev_timeout, &tv);

    if (chunk_client_prepare_stream(worker) != 0) {
        goto finish;
    }

    if (chunk_client_init_engine(worker) != 0) {
        goto finish;
    }

    if (chunk_client_init_connection(worker) != 0) {
        goto finish;
    }

    event_base_dispatch(worker->eb);

finish:
    if (!worker->result.success && worker->result.error_code == CHUNK_ERR_NONE) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_SERVER, 0,
            "worker exited without a result");
    }
    chunk_client_cleanup(worker);
    chunk_mark_worker_finished(worker);
    return worker->result.success ? 0 : -1;
}

void *
chunk_client_worker_thread_main(void *arg)
{
    chunk_client_run_worker((chunk_worker_ctx *)arg);
    return NULL;
}
