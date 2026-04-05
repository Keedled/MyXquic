#ifndef CHUNK_PROTOCOL_H
#define CHUNK_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define CHUNK_PROTOCOL_MAGIC   0x43484E4BU
#define CHUNK_PROTOCOL_VERSION 1U

#define CHUNK_HEADER_V1_LEN 48U
#define CHUNK_ACK_V1_LEN    28U

typedef enum chunk_status_e {
    CHUNK_STATUS_OK = 0,
    CHUNK_STATUS_BAD_MAGIC = 1,
    CHUNK_STATUS_BAD_VERSION = 2,
    CHUNK_STATUS_BAD_HEADER = 3,
    CHUNK_STATUS_BAD_RANGE = 4,
    CHUNK_STATUS_BAD_CRC32 = 5,
    CHUNK_STATUS_BAD_STREAM = 6,
    CHUNK_STATUS_IO_ERROR = 7,
    CHUNK_STATUS_INTERNAL = 8
} chunk_status_t;

typedef struct chunk_header_v1_s {
    uint32_t magic;
    uint16_t version;
    uint16_t header_len;
    uint64_t file_id;
    uint64_t file_size;
    uint32_t chunk_id;
    uint32_t chunk_count;
    uint64_t offset;
    uint32_t chunk_len;
    uint32_t crc32;
} chunk_header_v1;

typedef struct chunk_ack_v1_s {
    uint32_t magic;
    uint16_t version;
    uint16_t status;
    uint64_t file_id;
    uint32_t chunk_id;
    uint32_t received_len;
    uint32_t crc32;
} chunk_ack_v1;

int chunk_header_encode(const chunk_header_v1 *header, uint8_t *buf, size_t buf_len);
int chunk_header_decode(chunk_header_v1 *header, const uint8_t *buf, size_t buf_len);

int chunk_ack_encode(const chunk_ack_v1 *ack, uint8_t *buf, size_t buf_len);
int chunk_ack_decode(chunk_ack_v1 *ack, const uint8_t *buf, size_t buf_len);

uint32_t chunk_crc32_init(void);
uint32_t chunk_crc32_update(uint32_t crc, const void *data, size_t data_len);
uint32_t chunk_crc32_final(uint32_t crc);
uint32_t chunk_crc32_buffer(const void *data, size_t data_len);

#endif
