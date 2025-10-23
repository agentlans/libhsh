#ifndef HSH_SHA1_H
#define HSH_SHA1_H

#include <stdint.h>
#include <stddef.h>

#define HSH_SHA1_BLOCK_SIZE 64
#define HSH_SHA1_DIGEST_SIZE 20

typedef struct {
    uint32_t h[5];
    uint8_t unprocessed[HSH_SHA1_BLOCK_SIZE];
    size_t unprocessed_len;
    uint64_t message_byte_length;
} hsh_sha1_ctx;

/* User-callable functions */
void hsh_sha1_init(hsh_sha1_ctx *ctx);
void hsh_sha1_update(hsh_sha1_ctx *ctx, const uint8_t *data, size_t len);
void hsh_sha1_finalize(hsh_sha1_ctx *ctx, uint8_t digest[HSH_SHA1_DIGEST_SIZE]);

#endif
