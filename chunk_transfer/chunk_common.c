#include "chunk_common.h"

#ifdef XQC_SYS_WINDOWS
#define chunk_fseek64 _fseeki64
#else
#define chunk_fseek64 fseeko
#endif

static const char *
chunk_log_level_name(int level)
{
    switch (level) {
    case CHUNK_LOG_ERROR:
        return "ERROR";
    case CHUNK_LOG_WARN:
        return "WARN";
    case CHUNK_LOG_INFO:
        return "INFO";
    case CHUNK_LOG_DEBUG:
        return "DEBUG";
    default:
        return "LOG";
    }
}

void
chunk_log_print(int configured_level, int level, const char *component, const char *fmt, ...)
{
    va_list args;
    time_t now;
    struct tm tm_now;
    char time_buf[32];

    if (level > configured_level) {
        return;
    }

    now = time(NULL);
#ifdef XQC_SYS_WINDOWS
    localtime_s(&tm_now, &now);
#else
    localtime_r(&now, &tm_now);
#endif
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_now);

    fprintf(stderr, "[%s] [%s] [%s] ", time_buf, chunk_log_level_name(level),
        component == NULL ? "chunk" : component);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

int
chunk_parse_address(const char *host, uint16_t port, struct sockaddr_storage *addr, socklen_t *addrlen)
{
    int ret;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    char port_buf[16];

    if (host == NULL || addr == NULL || addrlen == NULL) {
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    snprintf(port_buf, sizeof(port_buf), "%u", (unsigned int)port);

    ret = getaddrinfo(host, port_buf, &hints, &result);
    if (ret != 0 || result == NULL) {
        return -1;
    }

    memcpy(addr, result->ai_addr, result->ai_addrlen);
    *addrlen = (socklen_t)result->ai_addrlen;
    freeaddrinfo(result);
    return 0;
}

int
chunk_socket_set_nonblocking(int fd)
{
#ifdef XQC_SYS_WINDOWS
    u_long mode = 1;
    if (ioctlsocket(fd, FIONBIO, &mode) == SOCKET_ERROR) {
        return -1;
    }
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        return -1;
    }
#endif
    return 0;
}

int
chunk_socket_set_buffers(int fd, int size)
{
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof(size)) != 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&size, sizeof(size)) != 0) {
        return -1;
    }
    return 0;
}

int
chunk_create_udp_socket(const struct sockaddr *bind_addr, socklen_t bind_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, int reuse_addr, int connect_peer)
{
    int fd;
    int opt = 1;
    int family;

    family = bind_addr != NULL ? bind_addr->sa_family : peer_addr->sa_family;
    fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    if (chunk_socket_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    if (reuse_addr) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) != 0) {
            close(fd);
            return -1;
        }
    }

    if (chunk_socket_set_buffers(fd, CHUNK_SOCKET_BUF_SIZE) != 0) {
        close(fd);
        return -1;
    }

#if !defined(XQC_SYS_WINDOWS) && !defined(__APPLE__)
    if (family == AF_INET) {
        int val = IP_PMTUDISC_DO;
        setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
    }
#endif

    if (bind_addr != NULL && bind(fd, bind_addr, bind_addrlen) != 0) {
        close(fd);
        return -1;
    }

    if (connect_peer && peer_addr != NULL && connect(fd, peer_addr, peer_addrlen) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int
chunk_get_local_addr(int fd, struct sockaddr_storage *addr, socklen_t *addrlen)
{
    socklen_t len;

    if (addr == NULL || addrlen == NULL) {
        return -1;
    }

    len = sizeof(*addr);
    if (getsockname(fd, (struct sockaddr *)addr, &len) != 0) {
        return -1;
    }

    *addrlen = len;
    return 0;
}

static void
chunk_hash_bytes(uint64_t *hash, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t i;

    for (i = 0; i < len; ++i) {
        *hash ^= bytes[i];
        *hash *= 1099511628211ULL;
    }
}

uint64_t
chunk_make_file_id(const char *path, const struct stat *st)
{
    uint64_t hash = 1469598103934665603ULL;
    uint64_t now = (uint64_t)xqc_now();

    if (path != NULL) {
        chunk_hash_bytes(&hash, path, strlen(path));
    }
    if (st != NULL) {
        chunk_hash_bytes(&hash, &st->st_size, sizeof(st->st_size));
        chunk_hash_bytes(&hash, &st->st_mtime, sizeof(st->st_mtime));
        chunk_hash_bytes(&hash, &st->st_ctime, sizeof(st->st_ctime));
    }
    chunk_hash_bytes(&hash, &now, sizeof(now));

    if (hash == 0) {
        hash = 1;
    }
    return hash;
}

int
chunk_read_chunk_file(const char *path, uint64_t offset, uint8_t *buf, size_t len)
{
    FILE *fp;
    size_t nread;

    if (path == NULL || buf == NULL) {
        return -1;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }

    if (chunk_fseek64(fp, (off_t)offset, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    nread = 0;
    while (nread < len) {
        size_t rc = fread(buf + nread, 1, len - nread, fp);
        if (rc == 0) {
            if (ferror(fp)) {
                fclose(fp);
                return -1;
            }
            break;
        }
        nread += rc;
    }

    fclose(fp);
    return nread == len ? 0 : -1;
}

int
chunk_write_all_at(int fd, const uint8_t *buf, size_t len, uint64_t offset)
{
    size_t written = 0;

    while (written < len) {
#ifdef XQC_SYS_WINDOWS
        if (_lseeki64(fd, (__int64)(offset + written), SEEK_SET) < 0) {
            return -1;
        }
        {
            int rc = _write(fd, buf + written, (unsigned int)(len - written));
            if (rc <= 0) {
                return -1;
            }
            written += (size_t)rc;
        }
#else
        ssize_t rc = pwrite(fd, buf + written, len - written, (off_t)(offset + written));
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            return -1;
        }
        written += (size_t)rc;
#endif
    }

    return 0;
}

int
chunk_resize_file(int fd, uint64_t size)
{
#ifdef XQC_SYS_WINDOWS
    return _chsize_s(fd, size) == 0 ? 0 : -1;
#else
    return ftruncate(fd, (off_t)size);
#endif
}

int
chunk_fsync_file(int fd)
{
#ifdef XQC_SYS_WINDOWS
    return _commit(fd) == 0 ? 0 : -1;
#else
    return fsync(fd);
#endif
}

size_t
chunk_bitmap_bytes(uint32_t bit_count)
{
    return (size_t)((bit_count + 7U) / 8U);
}

int
chunk_bitmap_get(const uint8_t *bitmap, uint32_t bit_index)
{
    if (bitmap == NULL) {
        return 0;
    }

    return (bitmap[bit_index / 8U] >> (bit_index % 8U)) & 0x1;
}

void
chunk_bitmap_set(uint8_t *bitmap, uint32_t bit_index)
{
    if (bitmap == NULL) {
        return;
    }

    bitmap[bit_index / 8U] |= (uint8_t)(1U << (bit_index % 8U));
}

void
chunk_result_set(chunk_result *result, int success, int error_code, uint16_t ack_status,
    const char *fmt, ...)
{
    va_list args;

    if (result == NULL) {
        return;
    }

    result->success = success;
    result->error_code = error_code;
    result->ack_status = ack_status;
    result->error_text[0] = '\0';

    if (fmt != NULL) {
        va_start(args, fmt);
        vsnprintf(result->error_text, sizeof(result->error_text), fmt, args);
        va_end(args);
    }
}

void
chunk_mark_worker_finished(chunk_worker_ctx *worker)
{
    if (worker == NULL || worker->scheduler_mutex == NULL || worker->scheduler_cond == NULL) {
        return;
    }

    pthread_mutex_lock(worker->scheduler_mutex);
    worker->finished = 1;
    worker->result.finished = 1;
    pthread_cond_signal(worker->scheduler_cond);
    pthread_mutex_unlock(worker->scheduler_mutex);
}
