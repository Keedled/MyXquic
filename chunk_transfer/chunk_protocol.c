#include "chunk_protocol.h"

static void
chunk_store_u16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)(value >> 8);
    buf[1] = (uint8_t)(value & 0xFFu);
}

static void
chunk_store_u32(uint8_t *buf, uint32_t value)
{
    buf[0] = (uint8_t)(value >> 24);
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)(value & 0xFFu);
}

static void
chunk_store_u64(uint8_t *buf, uint64_t value)
{
    buf[0] = (uint8_t)(value >> 56);
    buf[1] = (uint8_t)(value >> 48);
    buf[2] = (uint8_t)(value >> 40);
    buf[3] = (uint8_t)(value >> 32);
    buf[4] = (uint8_t)(value >> 24);
    buf[5] = (uint8_t)(value >> 16);
    buf[6] = (uint8_t)(value >> 8);
    buf[7] = (uint8_t)(value & 0xFFu);
}

static uint16_t
chunk_load_u16(const uint8_t *buf)
{
    return (uint16_t)(((uint16_t)buf[0] << 8) | (uint16_t)buf[1]);
}

static uint32_t
chunk_load_u32(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24)
        | ((uint32_t)buf[1] << 16)
        | ((uint32_t)buf[2] << 8)
        | (uint32_t)buf[3];
}

static uint64_t
chunk_load_u64(const uint8_t *buf)
{
    return ((uint64_t)buf[0] << 56)
        | ((uint64_t)buf[1] << 48)
        | ((uint64_t)buf[2] << 40)
        | ((uint64_t)buf[3] << 32)
        | ((uint64_t)buf[4] << 24)
        | ((uint64_t)buf[5] << 16)
        | ((uint64_t)buf[6] << 8)
        | (uint64_t)buf[7];
}

int
chunk_header_encode(const chunk_header_v1 *header, uint8_t *buf, size_t buf_len)
{
    if (header == NULL || buf == NULL || buf_len < CHUNK_HEADER_V1_LEN) {
        return -1;
    }

    chunk_store_u32(buf, header->magic);
    chunk_store_u16(buf + 4, header->version);
    chunk_store_u16(buf + 6, header->header_len);
    chunk_store_u64(buf + 8, header->file_id);
    chunk_store_u64(buf + 16, header->file_size);
    chunk_store_u32(buf + 24, header->chunk_id);
    chunk_store_u32(buf + 28, header->chunk_count);
    chunk_store_u64(buf + 32, header->offset);
    chunk_store_u32(buf + 40, header->chunk_len);
    chunk_store_u32(buf + 44, header->crc32);

    return (int)CHUNK_HEADER_V1_LEN;
}

int
chunk_header_decode(chunk_header_v1 *header, const uint8_t *buf, size_t buf_len)
{
    if (header == NULL || buf == NULL || buf_len < CHUNK_HEADER_V1_LEN) {
        return -1;
    }

    header->magic = chunk_load_u32(buf);
    header->version = chunk_load_u16(buf + 4);
    header->header_len = chunk_load_u16(buf + 6);
    header->file_id = chunk_load_u64(buf + 8);
    header->file_size = chunk_load_u64(buf + 16);
    header->chunk_id = chunk_load_u32(buf + 24);
    header->chunk_count = chunk_load_u32(buf + 28);
    header->offset = chunk_load_u64(buf + 32);
    header->chunk_len = chunk_load_u32(buf + 40);
    header->crc32 = chunk_load_u32(buf + 44);

    return 0;
}

int
chunk_ack_encode(const chunk_ack_v1 *ack, uint8_t *buf, size_t buf_len)
{
    if (ack == NULL || buf == NULL || buf_len < CHUNK_ACK_V1_LEN) {
        return -1;
    }

    chunk_store_u32(buf, ack->magic);
    chunk_store_u16(buf + 4, ack->version);
    chunk_store_u16(buf + 6, ack->status);
    chunk_store_u64(buf + 8, ack->file_id);
    chunk_store_u32(buf + 16, ack->chunk_id);
    chunk_store_u32(buf + 20, ack->received_len);
    chunk_store_u32(buf + 24, ack->crc32);

    return (int)CHUNK_ACK_V1_LEN;
}

int
chunk_ack_decode(chunk_ack_v1 *ack, const uint8_t *buf, size_t buf_len)
{
    if (ack == NULL || buf == NULL || buf_len < CHUNK_ACK_V1_LEN) {
        return -1;
    }

    ack->magic = chunk_load_u32(buf);
    ack->version = chunk_load_u16(buf + 4);
    ack->status = chunk_load_u16(buf + 6);
    ack->file_id = chunk_load_u64(buf + 8);
    ack->chunk_id = chunk_load_u32(buf + 16);
    ack->received_len = chunk_load_u32(buf + 20);
    ack->crc32 = chunk_load_u32(buf + 24);

    return 0;
}

uint32_t
chunk_crc32_init(void)
{
    return 0xFFFFFFFFu;
}

uint32_t
chunk_crc32_update(uint32_t crc, const void *data, size_t data_len)
{
    size_t i;
    int bit;
    const uint8_t *bytes = (const uint8_t *)data;

    for (i = 0; i < data_len; ++i) {
        crc ^= bytes[i];
        for (bit = 0; bit < 8; ++bit) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
    }

    return crc;
}

uint32_t
chunk_crc32_final(uint32_t crc)
{
    return crc ^ 0xFFFFFFFFu;
}

uint32_t
chunk_crc32_buffer(const void *data, size_t data_len)
{
    return chunk_crc32_final(chunk_crc32_update(chunk_crc32_init(), data, data_len));
}
