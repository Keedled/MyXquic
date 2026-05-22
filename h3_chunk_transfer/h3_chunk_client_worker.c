#include "h3_chunk_common.h"

static void
h3_chunk_client_socket_read_handler(h3_chunk_client_worker_ctx *worker, int fd)
{
    ssize_t recv_size;
    uint8_t packet_buf[H3_CHUNK_PACKET_BUF_LEN];
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
h3_chunk_client_socket_event_callback(int fd, short what, void *arg)
{
    h3_chunk_client_worker_ctx *worker = (h3_chunk_client_worker_ctx *)arg;

    if (what & EV_READ) {
        h3_chunk_client_socket_read_handler(worker, fd);
    }
}

static void
h3_chunk_client_timeout_callback(int fd, short what, void *arg)
{
    h3_chunk_client_worker_ctx *worker = (h3_chunk_client_worker_ctx *)arg;
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
        xqc_h3_conn_close(worker->engine, &worker->cid);
        xqc_engine_main_logic(worker->engine);
    } else if (worker->eb != NULL) {
        event_base_loopbreak(worker->eb);
    }
}

static int
h3_chunk_client_prepare_request(h3_chunk_client_worker_ctx *worker)
{
    h3_chunk_client_request_ctx *request_ctx;

    request_ctx = &worker->request_ctx;
    memset(request_ctx, 0, sizeof(*request_ctx));
    request_ctx->worker = worker;

    if (worker->task->chunk_len > 0) {
        request_ctx->body_buf = (uint8_t *)malloc(worker->task->chunk_len);
        if (request_ctx->body_buf == NULL) {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_IO, 0,
                "failed to allocate chunk buffer");
            return -1;
        }

        if (chunk_read_chunk_file(worker->config.input_path, worker->task->offset,
                request_ctx->body_buf, worker->task->chunk_len) != 0)
        {
            chunk_result_set(&worker->result, 0, CHUNK_ERR_IO, 0,
                "failed to read input file");
            return -1;
        }
    }

    request_ctx->body_len = worker->task->chunk_len;
    worker->result.ack_crc32 = chunk_crc32_buffer(request_ctx->body_buf, request_ctx->body_len);
    return 0;
}

static int
h3_chunk_client_init_engine(h3_chunk_client_worker_ctx *worker)
{
    xqc_config_t config;
    xqc_engine_callback_t callbacks = {
        .set_event_timer = h3_chunk_client_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = h3_chunk_client_write_log,
            .xqc_log_write_stat = h3_chunk_client_write_log,
            .xqc_qlog_event_write = h3_chunk_client_write_qlog,
        },
        .keylog_cb = h3_chunk_client_keylog_cb,
    };
    xqc_transport_callbacks_t transport_cbs = {
        .write_socket = h3_chunk_client_write_socket,
        .write_socket_ex = h3_chunk_client_write_socket_ex,
        .save_token = h3_chunk_client_save_token,
        .save_session_cb = h3_chunk_client_save_session,
        .save_tp_cb = h3_chunk_client_save_tp,
    };
    xqc_engine_ssl_config_t ssl_cfg = {
        .ciphers = XQC_TLS_CIPHERS,
        .groups = XQC_TLS_GROUPS,
    };
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = h3_chunk_client_h3_conn_create_notify,
            .h3_conn_close_notify = h3_chunk_client_h3_conn_close_notify,
            .h3_conn_handshake_finished = h3_chunk_client_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_close_notify = h3_chunk_client_request_close_notify,
            .h3_request_read_notify = h3_chunk_client_request_read_notify,
            .h3_request_write_notify = h3_chunk_client_request_write_notify,
            .h3_request_closing_notify = h3_chunk_client_request_closing_notify,
        },
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

    worker->ev_engine = event_new(worker->eb, -1, 0, h3_chunk_client_engine_cb, worker);
    if (worker->ev_engine == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_ENGINE, 0,
            "failed to create engine timer event");
        return -1;
    }

    if (xqc_h3_ctx_init(worker->engine, &h3_cbs) != XQC_OK) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_ENGINE, 0,
            "xqc_h3_ctx_init failed");
        return -1;
    }

    return 0;
}

static int
h3_chunk_client_init_connection(h3_chunk_client_worker_ctx *worker)
{
    const xqc_cid_t *cid;
    xqc_conn_settings_t conn_settings;
    xqc_conn_ssl_config_t conn_ssl_config;

    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.cong_ctrl_callback = xqc_bbr_cb;
    conn_settings.cc_params.customize_on = 1;
    conn_settings.cc_params.init_cwnd = 32;
    conn_settings.so_sndbuf = H3_CHUNK_SOCKET_BUF_SIZE;
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.init_idle_time_out = worker->config.timeout_sec * 1000U;
    conn_settings.idle_time_out = worker->config.timeout_sec * 1000U;
    conn_settings.spurious_loss_detect_on = 1;
    conn_settings.anti_amplification_limit = 4;
    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    conn_settings.reinj_ctl_callback = xqc_deadline_reinj_ctl_cb;
    conn_settings.adaptive_ack_frequency = 1;

    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    cid = xqc_h3_connect(worker->engine, &conn_settings, NULL, 0, worker->config.server_host, 0,
        &conn_ssl_config, (struct sockaddr *)&worker->peer_addr, worker->peer_addrlen, worker);
    if (cid == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_CONNECT, 0,
            "xqc_h3_connect failed");
        return -1;
    }

    memcpy(&worker->cid, cid, sizeof(*cid));
    worker->request_ctx.request = xqc_h3_request_create(worker->engine, &worker->cid, NULL,
        &worker->request_ctx);
    if (worker->request_ctx.request == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_STREAM, 0,
            "xqc_h3_request_create failed");
        return -1;
    }

    if (h3_chunk_client_request_send(worker->request_ctx.request, &worker->request_ctx) != 0) {
        return -1;
    }

    xqc_engine_main_logic(worker->engine);
    return 0;
}

static void
h3_chunk_client_cleanup(h3_chunk_client_worker_ctx *worker)
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
        xqc_h3_ctx_destroy(worker->engine);
        xqc_engine_destroy(worker->engine);
        worker->engine = NULL;
    }

    if (worker->fd >= 0) {
        close(worker->fd);
        worker->fd = -1;
    }

    if (worker->request_ctx.body_buf != NULL) {
        free(worker->request_ctx.body_buf);
        worker->request_ctx.body_buf = NULL;
    }

    if (worker->eb != NULL) {
        event_base_free(worker->eb);
        worker->eb = NULL;
    }
}

int
h3_chunk_client_run_worker(h3_chunk_client_worker_ctx *worker)
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
        h3_chunk_client_socket_event_callback, worker);
    if (worker->ev_socket == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_SOCKET, 0,
            "failed to create socket event");
        goto finish;
    }
    event_add(worker->ev_socket, NULL);

    worker->ev_timeout = event_new(worker->eb, -1, 0, h3_chunk_client_timeout_callback, worker);
    if (worker->ev_timeout == NULL) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_TIMEOUT, 0,
            "failed to create timeout event");
        goto finish;
    }
    tv.tv_sec = (time_t)worker->config.timeout_sec;
    tv.tv_usec = 0;
    event_add(worker->ev_timeout, &tv);

    if (h3_chunk_client_prepare_request(worker) != 0) {
        goto finish;
    }
    if (h3_chunk_client_init_engine(worker) != 0) {
        goto finish;
    }
    if (h3_chunk_client_init_connection(worker) != 0) {
        goto finish;
    }

    event_base_dispatch(worker->eb);

finish:
    if (!worker->result.success && worker->result.error_code == CHUNK_ERR_NONE) {
        chunk_result_set(&worker->result, 0, CHUNK_ERR_SERVER, 0,
            "worker exited without a result");
    }
    h3_chunk_client_cleanup(worker);
    h3_chunk_mark_worker_finished(worker);
    return worker->result.success ? 0 : -1;
}

void *
h3_chunk_client_worker_thread_main(void *arg)
{
    h3_chunk_client_run_worker((h3_chunk_client_worker_ctx *)arg);
    return NULL;
}
