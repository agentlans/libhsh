#ifndef HSH_BLAKE2_H
#define HSH_BLAKE2_H

#include <stdint.h>
#include <stddef.h>

/* ============================================
 * Structures
 * ============================================ */

/* BLAKE2b (64-bit) context */
typedef struct {
    uint64_t h[8];
    uint64_t t_low;      /* Low 64 bits of message byte counter */
    uint64_t t_high;     /* High 64 bits of message byte counter */
    uint8_t buffer[128];
    size_t buffer_len;
    size_t digest_size;
} hsh_blake2b_ctx;

/* BLAKE2s (32-bit) context */
typedef struct {
    uint32_t h[8];
    uint64_t t;
    uint8_t buffer[64];
    size_t buffer_len;
    size_t digest_size;
} hsh_blake2s_ctx;

/* ============================================
 * Public API
 * ============================================ */

int hsh_blake2b_init(hsh_blake2b_ctx *ctx, size_t digest_size,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *personal, size_t pers_len);

void hsh_blake2b_update(hsh_blake2b_ctx *ctx, const uint8_t *data, size_t len);

void hsh_blake2b_finalize(hsh_blake2b_ctx *ctx, uint8_t *digest);


int hsh_blake2s_init(hsh_blake2s_ctx *ctx, size_t digest_size,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *personal, size_t pers_len);

void hsh_blake2s_update(hsh_blake2s_ctx *ctx, const uint8_t *data, size_t len);

void hsh_blake2s_finalize(hsh_blake2s_ctx *ctx, uint8_t *digest);

#endif /* HSH_BLAKE2_H */

