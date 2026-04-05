#include "chunk_common.h"

typedef struct chunk_worker_slot_s {
    pthread_t thread;
    chunk_worker_ctx *worker;
    int active;
} chunk_worker_slot;

static void
chunk_client_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -i <input> [-a addr] [-p port] [-h host] [-k chunk_size] "
        "[-j concurrency] [-r retries] [-t timeout_sec] [-l log_level]\n",
        prog);
}

static void
chunk_client_init_config(chunk_client_config *config)
{
    memset(config, 0, sizeof(*config));
    snprintf(config->server_addr, sizeof(config->server_addr), "%s", CHUNK_DEFAULT_ADDR);
    snprintf(config->server_host, sizeof(config->server_host), "%s", CHUNK_DEFAULT_HOST);
    config->server_port = CHUNK_DEFAULT_PORT;
    config->chunk_size = CHUNK_DEFAULT_CHUNK_SIZE;
    config->concurrency = CHUNK_DEFAULT_CONCURRENCY;
    config->max_retries = CHUNK_DEFAULT_RETRIES;
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
chunk_client_parse_args(chunk_client_config *config, int argc, char **argv)
{
    int opt;
    uint32_t parsed;

    while ((opt = getopt(argc, argv, "a:p:h:i:k:j:r:t:l:")) != -1) {
        switch (opt) {
        case 'a':
            snprintf(config->server_addr, sizeof(config->server_addr), "%s", optarg);
            break;
        case 'p':
            if (chunk_parse_u32_arg(optarg, &parsed) != 0 || parsed > UINT16_MAX) {
                return -1;
            }
            config->server_port = (uint16_t)parsed;
            break;
        case 'h':
            snprintf(config->server_host, sizeof(config->server_host), "%s", optarg);
            break;
        case 'i':
            snprintf(config->input_path, sizeof(config->input_path), "%s", optarg);
            break;
        case 'k':
            if (chunk_parse_u32_arg(optarg, &config->chunk_size) != 0 || config->chunk_size == 0) {
                return -1;
            }
            break;
        case 'j':
            if (chunk_parse_u32_arg(optarg, &config->concurrency) != 0 || config->concurrency == 0) {
                return -1;
            }
            break;
        case 'r':
            if (chunk_parse_u32_arg(optarg, &config->max_retries) != 0) {
                return -1;
            }
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

    return config->input_path[0] == '\0' ? -1 : 0;
}

static int
chunk_client_launch_worker(chunk_worker_slot *slot, const chunk_client_config *config,
    uint64_t file_id, uint64_t file_size, chunk_task *task, pthread_mutex_t *mutex,
    pthread_cond_t *cond)
{
    chunk_worker_ctx *worker;
    int rc;

    worker = (chunk_worker_ctx *)calloc(1, sizeof(*worker));
    if (worker == NULL) {
        return -1;
    }

    worker->scheduler_mutex = mutex;
    worker->scheduler_cond = cond;
    worker->config = *config;
    worker->file_id = file_id;
    worker->file_size = file_size;
    worker->task = task;
    worker->fd = -1;
    task->attempts++;

    rc = pthread_create(&slot->thread, NULL, chunk_client_worker_thread_main, worker);
    if (rc != 0) {
        free(worker);
        return -1;
    }

    slot->worker = worker;
    slot->active = 1;
    return 0;
}

static int
chunk_client_has_finished_worker(chunk_worker_slot *slots, uint32_t slot_count)
{
    uint32_t i;

    for (i = 0; i < slot_count; ++i) {
        if (slots[i].active && slots[i].worker != NULL && slots[i].worker->finished) {
            return 1;
        }
    }

    return 0;
}

static void
chunk_client_join_finished(chunk_worker_slot *slots, uint32_t slot_count, uint32_t chunk_count,
    const chunk_client_config *config, uint32_t *active_workers, uint32_t *completed_chunks,
    uint32_t *queue, size_t *queue_tail, int *exhausted)
{
    uint32_t i;

    for (i = 0; i < slot_count; ++i) {
        chunk_worker_ctx *worker;

        if (!slots[i].active || slots[i].worker == NULL || !slots[i].worker->finished) {
            continue;
        }

        pthread_join(slots[i].thread, NULL);
        worker = slots[i].worker;
        (*active_workers)--;

        if (worker->result.success) {
            (*completed_chunks)++;
            chunk_log_print(config->log_level, CHUNK_LOG_INFO, "chunk_client",
                "chunk %u/%u completed", worker->task->chunk_id + 1U, chunk_count);
        } else if (worker->task->attempts <= config->max_retries) {
            queue[(*queue_tail)++] = worker->task->chunk_id;
            chunk_log_print(config->log_level, CHUNK_LOG_WARN, "chunk_client",
                "chunk %u failed on attempt %u, requeue: %s",
                worker->task->chunk_id, worker->task->attempts, worker->result.error_text);
        } else {
            fprintf(stderr, "chunk %u exhausted retries: %s\n",
                worker->task->chunk_id, worker->result.error_text);
            *exhausted = 1;
        }

        free(worker);
        slots[i].worker = NULL;
        slots[i].active = 0;
    }
}

int
main(int argc, char **argv)
{
    chunk_client_config config;
    struct stat st;
    pthread_mutex_t scheduler_mutex;
    pthread_cond_t scheduler_cond;
    chunk_task *tasks = NULL;
    chunk_worker_slot *slots = NULL;
    uint32_t *queue = NULL;
    size_t queue_cap = 0;
    size_t queue_head = 0;
    size_t queue_tail = 0;
    uint32_t chunk_count;
    uint32_t i;
    uint32_t active_workers = 0;
    uint32_t completed_chunks = 0;
    int overall_success = 0;
    int retries_exhausted = 0;
    uint64_t file_id;
    uint64_t file_size;

    chunk_client_init_config(&config);
    if (chunk_client_parse_args(&config, argc, argv) != 0) {
        chunk_client_usage(argv[0]);
        return 1;
    }

    xqc_platform_init_env();

    if (stat(config.input_path, &st) != 0) {
        fprintf(stderr, "failed to stat input file: %s\n", config.input_path);
        return 1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "input path is not a regular file: %s\n", config.input_path);
        return 1;
    }

    file_size = (uint64_t)st.st_size;
    file_id = chunk_make_file_id(config.input_path, &st);
    chunk_count = file_size == 0 ? 1U
        : (uint32_t)((file_size + config.chunk_size - 1U) / config.chunk_size);
    if (chunk_count == 0) {
        fprintf(stderr, "failed to compute chunk count\n");
        return 1;
    }

    tasks = (chunk_task *)calloc(chunk_count, sizeof(*tasks));
    slots = (chunk_worker_slot *)calloc(config.concurrency, sizeof(*slots));
    queue_cap = (size_t)chunk_count * (size_t)(config.max_retries + 1U);
    queue = (uint32_t *)calloc(queue_cap, sizeof(*queue));
    if (tasks == NULL || slots == NULL || queue == NULL) {
        fprintf(stderr, "failed to allocate scheduler resources\n");
        goto cleanup;
    }

    for (i = 0; i < chunk_count; ++i) {
        tasks[i].chunk_id = i;
        tasks[i].chunk_count = chunk_count;
        tasks[i].offset = (uint64_t)i * config.chunk_size;
        if (file_size == 0) {
            tasks[i].chunk_len = 0;
        } else if (tasks[i].offset + config.chunk_size <= file_size) {
            tasks[i].chunk_len = config.chunk_size;
        } else {
            tasks[i].chunk_len = (uint32_t)(file_size - tasks[i].offset);
        }
        queue[queue_tail++] = i;
    }

    pthread_mutex_init(&scheduler_mutex, NULL);
    pthread_cond_init(&scheduler_cond, NULL);

    chunk_log_print(config.log_level, CHUNK_LOG_INFO, "chunk_client",
        "start transfer file=%s file_id=%" PRIu64 " size=%" PRIu64 " chunk_count=%u "
        "chunk_size=%u concurrency=%u retries=%u",
        config.input_path, file_id, file_size, chunk_count, config.chunk_size,
        config.concurrency, config.max_retries);

    while (completed_chunks < chunk_count && !retries_exhausted) {
        for (i = 0; i < config.concurrency && queue_head < queue_tail; ++i) {
            if (slots[i].active) {
                continue;
            }
            if (chunk_client_launch_worker(&slots[i], &config, file_id, file_size,
                    &tasks[queue[queue_head++]], &scheduler_mutex, &scheduler_cond) != 0)
            {
                fprintf(stderr, "failed to launch worker\n");
                goto join_active;
            }
            active_workers++;
        }

        if (active_workers == 0) {
            fprintf(stderr, "no active workers and no pending chunks left\n");
            goto join_active;
        }

        pthread_mutex_lock(&scheduler_mutex);
        while (!chunk_client_has_finished_worker(slots, config.concurrency)) {
            pthread_cond_wait(&scheduler_cond, &scheduler_mutex);
        }
        pthread_mutex_unlock(&scheduler_mutex);

        chunk_client_join_finished(slots, config.concurrency, chunk_count, &config,
            &active_workers, &completed_chunks, queue, &queue_tail, &retries_exhausted);
    }

    overall_success = !retries_exhausted && completed_chunks == chunk_count;

join_active:
    while (active_workers > 0) {
        pthread_mutex_lock(&scheduler_mutex);
        while (!chunk_client_has_finished_worker(slots, config.concurrency)) {
            pthread_cond_wait(&scheduler_cond, &scheduler_mutex);
        }
        pthread_mutex_unlock(&scheduler_mutex);

        chunk_client_join_finished(slots, config.concurrency, chunk_count, &config,
            &active_workers, &completed_chunks, queue, &queue_tail, &retries_exhausted);
    }

    if (overall_success) {
        chunk_log_print(config.log_level, CHUNK_LOG_INFO, "chunk_client",
            "transfer completed successfully, file_id=%" PRIu64, file_id);
    }

    pthread_cond_destroy(&scheduler_cond);
    pthread_mutex_destroy(&scheduler_mutex);

cleanup:
    free(queue);
    free(slots);
    free(tasks);
    return overall_success ? 0 : 1;
}
