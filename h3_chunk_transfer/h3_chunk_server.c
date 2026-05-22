#include "h3_chunk_common.h"

typedef struct h3_chunk_server_slot_s {
    pthread_t thread;
    h3_chunk_server_worker_ctx *worker;
    int active;
} h3_chunk_server_slot;

static void
h3_chunk_server_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -w <output> [-a addr] [-p port] [-j workers] [-t timeout_sec] [-l log_level]\n",
        prog);
}

static void
h3_chunk_server_init_config(h3_chunk_server_config *config)
{
    memset(config, 0, sizeof(*config));
    snprintf(config->listen_addr, sizeof(config->listen_addr), "%s", H3_CHUNK_DEFAULT_ADDR);
    snprintf(config->cert_file, sizeof(config->cert_file), "%s", H3_CHUNK_DEFAULT_CERT_FILE);
    snprintf(config->key_file, sizeof(config->key_file), "%s", H3_CHUNK_DEFAULT_KEY_FILE);
    config->listen_port = H3_CHUNK_DEFAULT_PORT;
    config->worker_count = H3_CHUNK_DEFAULT_CONCURRENCY;
    config->timeout_sec = H3_CHUNK_DEFAULT_TIMEOUT_SEC;
    config->log_level = CHUNK_LOG_INFO;
}

static int
h3_chunk_server_parse_args(h3_chunk_server_config *config, int argc, char **argv)
{
    int opt;
    uint32_t parsed;

    while ((opt = getopt(argc, argv, "a:p:w:j:t:l:")) != -1) {
        switch (opt) {
        case 'a':
            snprintf(config->listen_addr, sizeof(config->listen_addr), "%s", optarg);
            break;
        case 'p':
            if (h3_chunk_parse_u32_arg(optarg, &parsed) != 0 || parsed > UINT16_MAX) {
                return -1;
            }
            config->listen_port = (uint16_t)parsed;
            break;
        case 'w':
            snprintf(config->output_path, sizeof(config->output_path), "%s", optarg);
            break;
        case 'j':
            if (h3_chunk_parse_u32_arg(optarg, &config->worker_count) != 0
                || config->worker_count == 0)
            {
                return -1;
            }
            break;
        case 't':
            if (h3_chunk_parse_u32_arg(optarg, &config->timeout_sec) != 0
                || config->timeout_sec == 0)
            {
                return -1;
            }
            break;
        case 'l':
            if (h3_chunk_parse_u32_arg(optarg, &parsed) != 0 || parsed > CHUNK_LOG_DEBUG) {
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
h3_chunk_server_shared_cleanup(h3_chunk_server_shared_ctx *shared)
{
    if (shared == NULL) {
        return;
    }

    chunk_assembly_reset(&shared->assembly);

    if (shared->assembly.fd >= 0) {
        close(shared->assembly.fd);
        shared->assembly.fd = -1;
    }

    pthread_mutex_destroy(&shared->assembly_mutex);
}

int
main(int argc, char **argv)
{
    h3_chunk_server_shared_ctx shared;
    h3_chunk_server_slot *slots = NULL;
    uint32_t i;
    int rc = 1;

    memset(&shared, 0, sizeof(shared));
    shared.assembly.fd = -1;
    h3_chunk_server_init_config(&shared.config);

    if (h3_chunk_server_parse_args(&shared.config, argc, argv) != 0) {
        h3_chunk_server_usage(argv[0]);
        return 1;
    }

    xqc_platform_init_env();

    shared.assembly.fd = open(shared.config.output_path, O_CREAT | O_RDWR, 0644);
    if (shared.assembly.fd < 0) {
        fprintf(stderr, "failed to open output file: %s\n", shared.config.output_path);
        return 1;
    }
    chunk_resize_file(shared.assembly.fd, 0);
    pthread_mutex_init(&shared.assembly_mutex, NULL);

    slots = (h3_chunk_server_slot *)calloc(shared.config.worker_count, sizeof(*slots));
    if (slots == NULL) {
        fprintf(stderr, "failed to allocate server worker slots\n");
        goto cleanup;
    }

    if (shared.config.worker_count == 1) {
        slots[0].worker = (h3_chunk_server_worker_ctx *)calloc(1, sizeof(*slots[0].worker));
        if (slots[0].worker == NULL) {
            fprintf(stderr, "failed to allocate server worker\n");
            goto cleanup;
        }
        slots[0].worker->magic = H3_CHUNK_SERVER_WORKER_MAGIC;
        slots[0].worker->worker_id = 0;
        slots[0].worker->shared = &shared;
        chunk_log_print(shared.config.log_level, CHUNK_LOG_INFO, "h3_chunk_server",
            "listening on %s:%u output=%s workers=1",
            shared.config.listen_addr, (unsigned int)shared.config.listen_port,
            shared.config.output_path);
        rc = h3_chunk_server_run_worker(slots[0].worker) == 0 ? 0 : 1;
        free(slots[0].worker);
        slots[0].worker = NULL;
        goto cleanup;
    }

    chunk_log_print(shared.config.log_level, CHUNK_LOG_INFO, "h3_chunk_server",
        "listening on %s:%u output=%s workers=%u",
        shared.config.listen_addr, (unsigned int)shared.config.listen_port,
        shared.config.output_path, shared.config.worker_count);

    for (i = 0; i < shared.config.worker_count; ++i) {
        slots[i].worker = (h3_chunk_server_worker_ctx *)calloc(1, sizeof(*slots[i].worker));
        if (slots[i].worker == NULL) {
            fprintf(stderr, "failed to allocate server worker\n");
            goto join;
        }
        slots[i].worker->magic = H3_CHUNK_SERVER_WORKER_MAGIC;
        slots[i].worker->worker_id = i;
        slots[i].worker->shared = &shared;
        if (pthread_create(&slots[i].thread, NULL, h3_chunk_server_worker_thread_main,
                slots[i].worker) != 0)
        {
            fprintf(stderr, "failed to launch server worker\n");
            free(slots[i].worker);
            slots[i].worker = NULL;
            goto join;
        }
        slots[i].active = 1;
    }

    rc = 0;

join:
    for (i = 0; i < shared.config.worker_count; ++i) {
        if (slots[i].active) {
            pthread_join(slots[i].thread, NULL);
            slots[i].active = 0;
        }
        free(slots[i].worker);
        slots[i].worker = NULL;
    }

cleanup:
    free(slots);
    h3_chunk_server_shared_cleanup(&shared);
    return rc;
}
