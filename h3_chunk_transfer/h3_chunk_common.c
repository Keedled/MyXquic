#include "h3_chunk_common.h"

#ifndef XQC_SYS_WINDOWS
#include <strings.h>
#endif

int
h3_chunk_parse_u32_arg(const char *text, uint32_t *value)
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

void
h3_chunk_mark_worker_finished(h3_chunk_client_worker_ctx *worker)
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

void
h3_chunk_set_header(xqc_http_header_t *hdr, const char *name, const char *value)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->name.iov_base = (void *)name;
    hdr->name.iov_len = strlen(name);
    hdr->value.iov_base = (void *)value;
    hdr->value.iov_len = strlen(value);
}

static int
h3_chunk_header_name_equals(const xqc_http_header_t *hdr, const char *name)
{
    size_t name_len;

    if (hdr == NULL || name == NULL || hdr->name.iov_base == NULL) {
        return 0;
    }

    name_len = strlen(name);
#ifdef XQC_SYS_WINDOWS
    return hdr->name.iov_len == name_len
        && _strnicmp((const char *)hdr->name.iov_base, name, name_len) == 0;
#else
    return hdr->name.iov_len == name_len
        && strncasecmp((const char *)hdr->name.iov_base, name, name_len) == 0;
#endif
}

static const xqc_http_header_t *
h3_chunk_find_header(const xqc_http_headers_t *headers, const char *name)
{
    size_t i;

    if (headers == NULL || name == NULL) {
        return NULL;
    }

    for (i = 0; i < headers->count; ++i) {
        if (h3_chunk_header_name_equals(&headers->headers[i], name)) {
            return &headers->headers[i];
        }
    }

    return NULL;
}

static int
h3_chunk_header_value_to_ull(const xqc_http_headers_t *headers, const char *name,
    unsigned long long max_value, unsigned long long *value)
{
    const xqc_http_header_t *hdr;
    char buf[64];
    char *end = NULL;
    unsigned long long parsed;

    hdr = h3_chunk_find_header(headers, name);
    if (hdr == NULL || hdr->value.iov_base == NULL || hdr->value.iov_len == 0
        || hdr->value.iov_len >= sizeof(buf))
    {
        return -1;
    }

    memcpy(buf, hdr->value.iov_base, hdr->value.iov_len);
    buf[hdr->value.iov_len] = '\0';
    parsed = strtoull(buf, &end, 10);
    if (end == NULL || *end != '\0' || parsed > max_value) {
        return -1;
    }

    *value = parsed;
    return 0;
}

int
h3_chunk_header_value_to_u64(const xqc_http_headers_t *headers, const char *name, uint64_t *value)
{
    unsigned long long parsed;

    if (value == NULL) {
        return -1;
    }

    if (h3_chunk_header_value_to_ull(headers, name, UINT64_MAX, &parsed) != 0) {
        return -1;
    }

    *value = (uint64_t)parsed;
    return 0;
}

int
h3_chunk_header_value_to_u32(const xqc_http_headers_t *headers, const char *name, uint32_t *value)
{
    unsigned long long parsed;

    if (value == NULL) {
        return -1;
    }

    if (h3_chunk_header_value_to_ull(headers, name, UINT32_MAX, &parsed) != 0) {
        return -1;
    }

    *value = (uint32_t)parsed;
    return 0;
}

int
h3_chunk_header_value_equals(const xqc_http_headers_t *headers, const char *name,
    const char *expected)
{
    const xqc_http_header_t *hdr;
    size_t expected_len;

    hdr = h3_chunk_find_header(headers, name);
    if (hdr == NULL || expected == NULL || hdr->value.iov_base == NULL) {
        return 0;
    }

    expected_len = strlen(expected);
    return hdr->value.iov_len == expected_len
        && memcmp(hdr->value.iov_base, expected, expected_len) == 0;
}

int
h3_chunk_parse_request_headers(const xqc_http_headers_t *headers, chunk_header_v1 *header)
{
    if (headers == NULL || header == NULL) {
        return -1;
    }

    memset(header, 0, sizeof(*header));
    header->magic = CHUNK_PROTOCOL_MAGIC;
    header->version = CHUNK_PROTOCOL_VERSION;
    header->header_len = CHUNK_HEADER_V1_LEN;

    if (!h3_chunk_header_value_equals(headers, ":method", "POST")) {
        return -1;
    }
    if (h3_chunk_header_value_to_u64(headers, H3_CHUNK_HDR_FILE_ID, &header->file_id) != 0
        || h3_chunk_header_value_to_u64(headers, H3_CHUNK_HDR_FILE_SIZE, &header->file_size) != 0
        || h3_chunk_header_value_to_u32(headers, H3_CHUNK_HDR_CHUNK_ID, &header->chunk_id) != 0
        || h3_chunk_header_value_to_u32(headers, H3_CHUNK_HDR_CHUNK_COUNT, &header->chunk_count) != 0
        || h3_chunk_header_value_to_u64(headers, H3_CHUNK_HDR_OFFSET, &header->offset) != 0
        || h3_chunk_header_value_to_u32(headers, H3_CHUNK_HDR_CHUNK_LEN, &header->chunk_len) != 0
        || h3_chunk_header_value_to_u32(headers, H3_CHUNK_HDR_CRC32, &header->crc32) != 0)
    {
        return -1;
    }

    return 0;
}

int
h3_chunk_parse_ack_headers(const xqc_http_headers_t *headers, chunk_ack_v1 *ack)
{
    uint32_t status;

    if (headers == NULL || ack == NULL) {
        return -1;
    }

    memset(ack, 0, sizeof(*ack));
    ack->magic = CHUNK_PROTOCOL_MAGIC;
    ack->version = CHUNK_PROTOCOL_VERSION;

    if (h3_chunk_header_value_to_u32(headers, H3_CHUNK_HDR_STATUS, &status) != 0
        || status > UINT16_MAX)
    {
        return -1;
    }
    ack->status = (uint16_t)status;

    if (h3_chunk_header_value_to_u64(headers, H3_CHUNK_HDR_FILE_ID, &ack->file_id) != 0
        || h3_chunk_header_value_to_u32(headers, H3_CHUNK_HDR_CHUNK_ID, &ack->chunk_id) != 0
        || h3_chunk_header_value_to_u32(headers, H3_CHUNK_HDR_RECEIVED_LEN, &ack->received_len) != 0
        || h3_chunk_header_value_to_u32(headers, H3_CHUNK_HDR_CRC32, &ack->crc32) != 0)
    {
        return -1;
    }

    return 0;
}
