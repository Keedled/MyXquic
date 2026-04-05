#include "chunk_common.h"

static void
chunk_server_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -w <output> [-a addr] [-p port] [-t timeout_sec] [-l log_level]\n",
        prog);
}

static void
chunk_server_init_config(chunk_server_config *config)
{
    memset(config, 0, sizeof(*config));
    snprintf(config->listen_addr, sizeof(config->listen_addr), "%s", CHUNK_DEFAULT_ADDR);
    snprintf(config->cert_file, sizeof(config->cert_file), "%s", CHUNK_DEFAULT_CERT_FILE);
    snprintf(config->key_file, sizeof(config->key_file), "%s", CHUNK_DEFAULT_KEY_FILE);
    config->listen_port = CHUNK_DEFAULT_PORT;
    config->timeout_sec = CHUNK_DEFAULT_TIMEOUT_SEC;
    config->log_level = CHUNK_LOG_INFO;
}

static int
chunk_parse_u32_arg(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || value == NULL || *text == '\0') {
        return -1;
    }

    parsed = strtoul(text, &end, 10);
    if (end == NULL || *end != '\0' || parsed > UINT32_MAX) {
        return -1;
    }

    *value = (uint32_t)parsed;
    return 0;
}

static int
chunk_server_parse_args(chunk_server_config *config, int argc, char **argv)
{
    int opt;
    uint32_t parsed;

    while ((opt = getopt(argc, argv, "a:p:w:t:l:")) != -1) {
        switch (opt) {
        case 'a':
            snprintf(config->listen_addr, sizeof(config->listen_addr), "%s", optarg);
            break;
        case 'p':
            if (chunk_parse_u32_arg(optarg, &parsed) != 0 || parsed > UINT16_MAX) {
                return -1;
            }
            config->listen_port = (uint16_t)parsed;
            break;
        case 'w':
            snprintf(config->output_path, sizeof(config->output_path), "%s", optarg);
            break;
        case 't':
            if (chunk_parse_u32_arg(optarg, &config->timeout_sec) != 0 || config->timeout_sec == 0) {
                return -1;
            }
            break;
        case 'l':
            if (chunk_parse_u32_arg(optarg, &parsed) != 0 || parsed > CHUNK_LOG_DEBUG) {
                return -1;
            }
            config->log_level = (int)parsed;
            break;
        default:
            return -1;
        }
    }

    return config->output_path[0] == '\0' ? -1 : 0;
}

static void
chunk_server_socket_read_handler(chunk_server_ctx *ctx, int fd)
{
    ssize_t recv_size;
    uint8_t packet_buf[CHUNK_PACKET_BUF_LEN];
    struct sockaddr_storage peer_addr;
    struct sockaddr_storage local_addr;
    socklen_t peer_addrlen;
    socklen_t local_addrlen;
    xqc_int_t rc;
    uint64_t recv_time;

    do {
        peer_addrlen = sizeof(peer_addr);
        recv_size = recvfrom(fd, (char *)packet_buf, sizeof(packet_buf), 0,
            (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }
        if (recv_size < 0) {
            chunk_log_print(ctx->config.log_level, CHUNK_LOG_ERROR, "chunk_server",
                "recvfrom failed, errno=%d", get_sys_errno());
            break;
        }

        local_addrlen = sizeof(local_addr);
        if (getsockname(fd, (struct sockaddr *)&local_addr, &local_addrlen) != 0) {
            chunk_log_print(ctx->config.log_level, CHUNK_LOG_ERROR, "chunk_server",
                "getsockname failed, errno=%d", get_sys_errno());
            break;
        }

        ctx->current_fd = fd;
        recv_time = xqc_now();
        rc = xqc_engine_packet_process(ctx->engine, packet_buf, (size_t)recv_size,
            (struct sockaddr *)&local_addr, local_addrlen,
            (struct sockaddr *)&peer_addr, peer_addrlen, (xqc_usec_t)recv_time, ctx);
        if (rc != XQC_OK) {
            chunk_log_print(ctx->config.log_level, CHUNK_LOG_ERROR, "chunk_server",
                "xqc_engine_packet_process failed, ret=%d", rc);
            break;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(ctx->engine);
}

static void
chunk_server_socket_event_callback(int fd, short what, void *arg)
{
    chunk_server_ctx *ctx = (chunk_server_ctx *)arg;

    if (what & EV_READ) {
        chunk_server_socket_read_handler(ctx, fd);
    }
}

static int
chunk_server_init_engine(chunk_server_ctx *ctx)
{
    xqc_config_t config;
    xqc_engine_callback_t callbacks = {
        .set_event_timer = chunk_server_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = chunk_server_write_log,
            .xqc_log_write_stat = chunk_server_write_log,
            .xqc_qlog_event_write = chunk_server_write_qlog,
        },
        .keylog_cb = chunk_server_keylog_cb,
    };
    xqc_transport_callbacks_t transport_cbs = {
        .server_accept = chunk_server_accept,
        .write_socket = chunk_server_write_socket,
        .write_socket_ex = chunk_server_write_socket_ex,
    };
    xqc_engine_ssl_config_t ssl_cfg = {
        .private_key_file = ctx->config.key_file,
        .cert_file = ctx->config.cert_file,
        .ciphers = XQC_TLS_CIPHERS,
        .groups = XQC_TLS_GROUPS,
    };
    xqc_conn_settings_t conn_settings;

    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        return -1;
    }
    config.cfg_log_level = (xqc_log_level_t)ctx->config.log_level;

    ctx->engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl_cfg,
        &callbacks, &transport_cbs, ctx);
    if (ctx->engine == NULL) {
        return -1;
    }

    ctx->ev_engine = event_new(ctx->eb, -1, 0, chunk_server_engine_cb, ctx);
    if (ctx->ev_engine == NULL) {
        return -1;
    }

    if (chunk_server_register_alpn(ctx->engine) != XQC_OK) {
        return -1;
    }

    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.cong_ctrl_callback = xqc_bbr_cb;
    conn_settings.cc_params.customize_on = 1;
    conn_settings.cc_params.init_cwnd = 32;
    conn_settings.so_sndbuf = CHUNK_SOCKET_BUF_SIZE;
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.init_idle_time_out = ctx->config.timeout_sec * 1000U;
    conn_settings.idle_time_out = ctx->config.timeout_sec * 1000U;
    conn_settings.spurious_loss_detect_on = 1;
    conn_settings.anti_amplification_limit = 4;
    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    conn_settings.reinj_ctl_callback = xqc_deadline_reinj_ctl_cb;
    conn_settings.adaptive_ack_frequency = 1;
    xqc_server_set_conn_settings(ctx->engine, &conn_settings);

    return 0;
}

static void
chunk_server_cleanup(chunk_server_ctx *ctx)
{
    if (ctx->ev_socket != NULL) {
        event_del(ctx->ev_socket);
        event_free(ctx->ev_socket);
        ctx->ev_socket = NULL;
    }

    if (ctx->ev_engine != NULL) {
        event_free(ctx->ev_engine);
        ctx->ev_engine = NULL;
    }

    if (ctx->engine != NULL) {
        xqc_engine_destroy(ctx->engine);
        ctx->engine = NULL;
    }

    if (ctx->listen_fd >= 0) {
        close(ctx->listen_fd);
        ctx->listen_fd = -1;
    }

    if (ctx->assembly.bitmap != NULL) {
        free(ctx->assembly.bitmap);
        ctx->assembly.bitmap = NULL;
    }

    if (ctx->assembly.fd >= 0) {
        close(ctx->assembly.fd);
        ctx->assembly.fd = -1;
    }

    if (ctx->eb != NULL) {
        event_base_free(ctx->eb);
        ctx->eb = NULL;
    }
}

int
main(int argc, char **argv)
{
    chunk_server_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.listen_fd = -1;
    ctx.assembly.fd = -1;
    chunk_server_init_config(&ctx.config);

    if (chunk_server_parse_args(&ctx.config, argc, argv) != 0) {
        chunk_server_usage(argv[0]);
        return 1;
    }

    xqc_platform_init_env();

    if (chunk_parse_address(ctx.config.listen_addr, ctx.config.listen_port,
            &ctx.listen_addr, &ctx.listen_addrlen) != 0)
    {
        fprintf(stderr, "failed to parse listen address\n");
        return 1;
    }

    ctx.assembly.fd = open(ctx.config.output_path, O_CREAT | O_RDWR, 0644);
    if (ctx.assembly.fd < 0) {
        fprintf(stderr, "failed to open output file: %s\n", ctx.config.output_path);
        return 1;
    }
    chunk_resize_file(ctx.assembly.fd, 0);

    ctx.eb = event_base_new();
    if (ctx.eb == NULL) {
        fprintf(stderr, "failed to create event base\n");
        chunk_server_cleanup(&ctx);
        return 1;
    }

    ctx.listen_fd = chunk_create_udp_socket((struct sockaddr *)&ctx.listen_addr, ctx.listen_addrlen,
        NULL, 0, 1, 0);
    if (ctx.listen_fd < 0) {
        fprintf(stderr, "failed to create/bind server udp socket\n");
        chunk_server_cleanup(&ctx);
        return 1;
    }

    if (chunk_server_init_engine(&ctx) != 0) {
        fprintf(stderr, "failed to initialize xquic server engine\n");
        chunk_server_cleanup(&ctx);
        return 1;
    }

    ctx.ev_socket = event_new(ctx.eb, ctx.listen_fd, EV_READ | EV_PERSIST,
        chunk_server_socket_event_callback, &ctx);
    if (ctx.ev_socket == NULL) {
        fprintf(stderr, "failed to create server socket event\n");
        chunk_server_cleanup(&ctx);
        return 1;
    }
    event_add(ctx.ev_socket, NULL);

    chunk_log_print(ctx.config.log_level, CHUNK_LOG_INFO, "chunk_server",
        "listening on %s:%u output=%s",
        ctx.config.listen_addr, (unsigned int)ctx.config.listen_port, ctx.config.output_path);

    event_base_dispatch(ctx.eb);
    chunk_server_cleanup(&ctx);
    return 0;
}
