#include "sha3.h"
#include <stdlib.h>
#include <string.h>

static const uint64_t HSH_SHA3_RC[HSH_SHA3_NR] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int HSH_SHA3_R[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14}
};

static inline uint64_t hsh_sha3_rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

// ===== Internal Keccak-f permutation =====
static void hsh_sha3_f(hsh_sha3_ctx *ctx) {
    uint64_t *A = ctx->state;
    for (int rnd = 0; rnd < HSH_SHA3_NR; rnd++) {
        uint64_t C[5], D[5], B[25], newA[25];

        for (int x = 0; x < 5; x++) {
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        }

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ hsh_sha3_rotl64(C[(x + 1) % 5], 1);
        }

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                A[x + 5 * y] ^= D[x];
            }
        }

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                B[y % 5 + 5 * ((2 * x + 3 * y) % 5)] = hsh_sha3_rotl64(A[x + 5 * y], HSH_SHA3_R[x][y]);
            }
        }

        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                newA[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);
            }
        }

        memcpy(A, newA, sizeof(uint64_t) * HSH_SHA3_STATE_SIZE);
        A[0] ^= HSH_SHA3_RC[rnd];
    }
}

// ====== Internal padding ======
static uint8_t *hsh_sha3_pad(hsh_sha3_ctx *ctx, size_t msg_len, size_t *pad_len_out) {
    size_t pad_len = ctx->rate_bytes - (msg_len % ctx->rate_bytes);
    *pad_len_out = pad_len;

    uint8_t *pad = (uint8_t *)malloc(pad_len);
    if (!pad) return NULL;

    memset(pad, 0, pad_len);
    pad[0] = 0x06;
    pad[pad_len - 1] |= 0x80;
    return pad;
}

// ====== Internal absorb ======
static void hsh_sha3_absorb(hsh_sha3_ctx *ctx, const uint8_t *block) {
    for (size_t i = 0; i < ctx->rate_bytes; i += 8) {
        uint64_t val = 0;
        memcpy(&val, block + i, 8);
        ctx->state[i / 8] ^= val;
    }
    hsh_sha3_f(ctx);
}

// ===== User-callable API =====
void hsh_sha3_update(hsh_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    if (ctx->finalized) return;

    size_t total_len = ctx->buf_len + len;
    uint8_t *newbuf = realloc(ctx->buf, total_len);
    if (!newbuf) return;
    memcpy(newbuf + ctx->buf_len, data, len);

    ctx->buf = newbuf;
    ctx->buf_len = total_len;

    while (ctx->buf_len >= ctx->rate_bytes) {
        hsh_sha3_absorb(ctx, ctx->buf);
        memmove(ctx->buf, ctx->buf + ctx->rate_bytes, ctx->buf_len - ctx->rate_bytes);
        ctx->buf_len -= ctx->rate_bytes;
        ctx->buf = realloc(ctx->buf, ctx->buf_len);
    }
}

void hsh_sha3_finalize(hsh_sha3_ctx *ctx, uint8_t *out) {
    if (ctx->finalized) return;

    size_t pad_len = 0;
    uint8_t *pad = hsh_sha3_pad(ctx, ctx->buf_len, &pad_len);
    if (!pad) return;

    size_t msg_len = ctx->buf_len + pad_len;
    uint8_t *msg = malloc(msg_len);
    memcpy(msg, ctx->buf, ctx->buf_len);
    memcpy(msg + ctx->buf_len, pad, pad_len);
    free(pad);

    for (size_t i = 0; i < msg_len; i += ctx->rate_bytes) {
        hsh_sha3_absorb(ctx, msg + i);
    }
    free(msg);
    free(ctx->buf);
    ctx->buf = NULL;

    ctx->finalized = 1;

    size_t out_len = ctx->output_bits / 8;
    uint8_t *p = out;
    size_t generated = 0;

    while (generated < out_len) {
        for (size_t i = 0; i < ctx->rate_bytes / 8 && generated < out_len; i++) {
            uint64_t val = ctx->state[i];
            memcpy(p + generated, &val, 8);
            generated += 8;
        }
        if (generated < out_len) {
            hsh_sha3_f(ctx);
        }
    }
}

// ===== Initialization Wrappers =====
static void hsh_sha3_init(hsh_sha3_ctx *ctx, int capacity_bits, int output_bits) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->capacity_bits = capacity_bits;
    ctx->output_bits = output_bits;
    ctx->rate_bytes = (1600 - capacity_bits) / 8;
    ctx->finalized = 0;
}

void hsh_sha3_224_init(hsh_sha3_ctx *ctx) { hsh_sha3_init(ctx, 448, 224); }
void hsh_sha3_256_init(hsh_sha3_ctx *ctx) { hsh_sha3_init(ctx, 512, 256); }
void hsh_sha3_384_init(hsh_sha3_ctx *ctx) { hsh_sha3_init(ctx, 768, 384); }
void hsh_sha3_512_init(hsh_sha3_ctx *ctx) { hsh_sha3_init(ctx, 1024, 512); }

