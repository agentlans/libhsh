#ifndef HSH_SHA3_H
#define HSH_SHA3_H

#include <stdint.h>
#include <stddef.h>

#define HSH_SHA3_STATE_SIZE 25
#define HSH_SHA3_NR 24

// ==== Structs ====
typedef struct {
    uint64_t state[HSH_SHA3_STATE_SIZE];
    uint8_t *buf;
    size_t buf_len;
    size_t rate_bytes;
    int finalized;
    int capacity_bits;
    int output_bits;
} hsh_sha3_ctx;

// ==== User-callable initialization ====
void hsh_sha3_224_init(hsh_sha3_ctx *ctx);
void hsh_sha3_256_init(hsh_sha3_ctx *ctx);
void hsh_sha3_384_init(hsh_sha3_ctx *ctx);
void hsh_sha3_512_init(hsh_sha3_ctx *ctx);

// ==== User-callable update/finalize ====
void hsh_sha3_update(hsh_sha3_ctx *ctx, const uint8_t *data, size_t len);
void hsh_sha3_finalize(hsh_sha3_ctx *ctx, uint8_t *out);

#endif
