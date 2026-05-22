#include "h3_chunk_common.h"

static void
h3_chunk_server_socket_read_handler(h3_chunk_server_worker_ctx *worker, int fd)
{
    ssize_t recv_size;
    uint8_t packet_buf[H3_CHUNK_PACKET_BUF_LEN];
    struct sockaddr_storage peer_addr;
    struct sockaddr_storage local_addr;
    socklen_t peer_addrlen;
    socklen_t local_addrlen;
    xqc_int_t rc;
    uint64_t recv_time;

    h3_chunk_current_server_worker = worker;

    do {
        peer_addrlen = sizeof(peer_addr);
        recv_size = recvfrom(fd, (char *)packet_buf, sizeof(packet_buf), 0,
            (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }
        if (recv_size < 0) {
            chunk_log_print(worker->shared->config.log_level, CHUNK_LOG_ERROR,
                "h3_chunk_server", "recvfrom failed, errno=%d", get_sys_errno());
            break;
        }

        local_addrlen = sizeof(local_addr);
        if (getsockname(fd, (struct sockaddr *)&local_addr, &local_addrlen) != 0) {
            chunk_log_print(worker->shared->config.log_level, CHUNK_LOG_ERROR,
                "h3_chunk_server", "getsockname failed, errno=%d", get_sys_errno());
            break;
        }

        worker->current_fd = fd;
        recv_time = xqc_now();
        rc = xqc_engine_packet_process(worker->engine, packet_buf, (size_t)recv_size,
            (struct sockaddr *)&local_addr, local_addrlen,
            (struct sockaddr *)&peer_addr, peer_addrlen, (xqc_usec_t)recv_time, worker);
        if (rc != XQC_OK) {
            chunk_log_print(worker->shared->config.log_level, CHUNK_LOG_ERROR,
                "h3_chunk_server", "xqc_engine_packet_process failed, ret=%d", rc);
            break;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(worker->engine);
}

static void
h3_chunk_server_socket_event_callback(int fd, short what, void *arg)
{
    h3_chunk_server_worker_ctx *worker = (h3_chunk_server_worker_ctx *)arg;

    if (what & EV_READ) {
        h3_chunk_server_socket_read_handler(worker, fd);
    }
}

static int
h3_chunk_server_create_udp_socket(const struct sockaddr *bind_addr, socklen_t bind_addrlen)
{
    int fd;
    int opt = 1;

    fd = socket(bind_addr->sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    if (chunk_socket_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) != 0) {
        close(fd);
        return -1;
    }

#if defined(SO_REUSEPORT) && !defined(XQC_SYS_WINDOWS)
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&opt, sizeof(opt)) != 0) {
        close(fd);
        return -1;
    }
#endif

    if (chunk_socket_set_buffers(fd, H3_CHUNK_SOCKET_BUF_SIZE) != 0) {
        close(fd);
        return -1;
    }

#if !defined(XQC_SYS_WINDOWS) && !defined(__APPLE__)
    if (bind_addr->sa_family == AF_INET) {
        int val = IP_PMTUDISC_DO;
        setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
    }
#endif

    if (bind(fd, bind_addr, bind_addrlen) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int
h3_chunk_server_init_engine(h3_chunk_server_worker_ctx *worker)
{
    xqc_config_t config;
    xqc_engine_callback_t callbacks = {
        .set_event_timer = h3_chunk_server_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = h3_chunk_server_write_log,
            .xqc_log_write_stat = h3_chunk_server_write_log,
            .xqc_qlog_event_write = h3_chunk_server_write_qlog,
        },
        .keylog_cb = h3_chunk_server_keylog_cb,
    };
    xqc_transport_callbacks_t transport_cbs = {
        .server_accept = h3_chunk_server_accept,
        .write_socket = h3_chunk_server_write_socket,
        .write_socket_ex = h3_chunk_server_write_socket_ex,
    };
    xqc_engine_ssl_config_t ssl_cfg = {
        .private_key_file = worker->shared->config.key_file,
        .cert_file = worker->shared->config.cert_file,
        .ciphers = XQC_TLS_CIPHERS,
        .groups = XQC_TLS_GROUPS,
    };
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = h3_chunk_server_h3_conn_create_notify,
            .h3_conn_close_notify = h3_chunk_server_h3_conn_close_notify,
            .h3_conn_handshake_finished = h3_chunk_server_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_create_notify = h3_chunk_server_request_create_notify,
            .h3_request_close_notify = h3_chunk_server_request_close_notify,
            .h3_request_read_notify = h3_chunk_server_request_read_notify,
            .h3_request_write_notify = h3_chunk_server_request_write_notify,
        },
    };
    xqc_conn_settings_t conn_settings;

    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        return -1;
    }
    config.cfg_log_level = (xqc_log_level_t)worker->shared->config.log_level;

    worker->engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl_cfg,
        &callbacks, &transport_cbs, worker);
    if (worker->engine == NULL) {
        return -1;
    }

    worker->ev_engine = event_new(worker->eb, -1, 0, h3_chunk_server_engine_cb, worker);
    if (worker->ev_engine == NULL) {
        return -1;
    }

    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.cong_ctrl_callback = xqc_bbr_cb;
    conn_settings.cc_params.customize_on = 1;
    conn_settings.cc_params.init_cwnd = 32;
    conn_settings.so_sndbuf = H3_CHUNK_SOCKET_BUF_SIZE;
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.init_idle_time_out = worker->shared->config.timeout_sec * 1000U;
    conn_settings.idle_time_out = worker->shared->config.timeout_sec * 1000U;
    conn_settings.spurious_loss_detect_on = 1;
    conn_settings.anti_amplification_limit = 4;
    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    conn_settings.reinj_ctl_callback = xqc_deadline_reinj_ctl_cb;
    conn_settings.adaptive_ack_frequency = 1;
    xqc_server_set_conn_settings(worker->engine, &conn_settings);

    if (xqc_h3_ctx_init(worker->engine, &h3_cbs) != XQC_OK) {
        return -1;
    }

    return 0;
}

static void
h3_chunk_server_cleanup(h3_chunk_server_worker_ctx *worker)
{
    if (worker->ev_socket != NULL) {
        event_del(worker->ev_socket);
        event_free(worker->ev_socket);
        worker->ev_socket = NULL;
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

    if (worker->listen_fd >= 0) {
        close(worker->listen_fd);
        worker->listen_fd = -1;
    }

    if (worker->eb != NULL) {
        event_base_free(worker->eb);
        worker->eb = NULL;
    }
}

int
h3_chunk_server_run_worker(h3_chunk_server_worker_ctx *worker)
{
    if (worker == NULL || worker->shared == NULL) {
        return -1;
    }

    worker->magic = H3_CHUNK_SERVER_WORKER_MAGIC;
    h3_chunk_current_server_worker = worker;
    worker->listen_fd = -1;

    if (chunk_parse_address(worker->shared->config.listen_addr,
            worker->shared->config.listen_port, &worker->listen_addr,
            &worker->listen_addrlen) != 0)
    {
        fprintf(stderr, "worker %u failed to parse listen address\n", worker->worker_id);
        return -1;
    }

    worker->eb = event_base_new();
    if (worker->eb == NULL) {
        fprintf(stderr, "worker %u failed to create event base\n", worker->worker_id);
        return -1;
    }

    worker->listen_fd = h3_chunk_server_create_udp_socket((struct sockaddr *)&worker->listen_addr,
        worker->listen_addrlen);
    if (worker->listen_fd < 0) {
        fprintf(stderr, "worker %u failed to create/bind server udp socket\n", worker->worker_id);
        h3_chunk_server_cleanup(worker);
        return -1;
    }

    if (h3_chunk_server_init_engine(worker) != 0) {
        fprintf(stderr, "worker %u failed to initialize xquic server engine\n",
            worker->worker_id);
        h3_chunk_server_cleanup(worker);
        return -1;
    }

    worker->ev_socket = event_new(worker->eb, worker->listen_fd, EV_READ | EV_PERSIST,
        h3_chunk_server_socket_event_callback, worker);
    if (worker->ev_socket == NULL) {
        fprintf(stderr, "worker %u failed to create socket event\n", worker->worker_id);
        h3_chunk_server_cleanup(worker);
        return -1;
    }
    event_add(worker->ev_socket, NULL);

    event_base_dispatch(worker->eb);
    h3_chunk_server_cleanup(worker);
    return 0;
}

void *
h3_chunk_server_worker_thread_main(void *arg)
{
    h3_chunk_server_run_worker((h3_chunk_server_worker_ctx *)arg);
    return NULL;
}
