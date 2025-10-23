#include "sha3.h"
#include <string.h>
#include <stdint.h>

// ===== Round constants and rotation offsets =====
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

// ===== Keccak-f permutation =====
static void hsh_sha3_f(hsh_sha3_ctx *ctx) {
    uint64_t *A = ctx->state;
    for (int rnd = 0; rnd < HSH_SHA3_NR; rnd++) {
        uint64_t C[5], D[5], B[25], newA[25];

        for (int x = 0; x < 5; x++)
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];

        for (int x = 0; x < 5; x++)
            D[x] = C[(x + 4) % 5] ^ hsh_sha3_rotl64(C[(x + 1) % 5], 1);

        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                A[x + 5 * y] ^= D[x];

        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                B[y % 5 + 5 * ((2 * x + 3 * y) % 5)] =
                    hsh_sha3_rotl64(A[x + 5 * y], HSH_SHA3_R[x][y]);

        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                newA[x + 5 * y] =
                    B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) &
                                    B[(x + 2) % 5 + 5 * y]);

        memcpy(A, newA, sizeof(newA));
        A[0] ^= HSH_SHA3_RC[rnd];
    }
}

// ===== Padding (stack local only) =====
static void hsh_sha3_pad(uint8_t *buf, size_t msg_len, size_t rate_bytes, size_t *pad_len_out) {
    size_t pad_len = rate_bytes - (msg_len % rate_bytes);
    *pad_len_out = pad_len;

    buf[msg_len] = 0x06;
    memset(buf + msg_len + 1, 0, pad_len - 2);
    buf[msg_len + pad_len - 1] |= 0x80;
}

// ===== Absorb Block =====
static void hsh_sha3_absorb(hsh_sha3_ctx *ctx, const uint8_t *block) {
    for (size_t i = 0; i < ctx->rate_bytes; i += 8) {
        uint64_t val = 0;
        memcpy(&val, block + i, 8);
        ctx->state[i / 8] ^= val;
    }
    hsh_sha3_f(ctx);
}

// ===== Update =====
void hsh_sha3_update(hsh_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    if (ctx->finalized || len == 0) return;

    size_t offset = 0;
    while (offset < len) {
        size_t to_copy = ctx->rate_bytes - ctx->buf_len;
        if (to_copy > len - offset)
            to_copy = len - offset;

        memcpy(ctx->buf + ctx->buf_len, data + offset, to_copy);
        ctx->buf_len += to_copy;
        offset += to_copy;

        if (ctx->buf_len == ctx->rate_bytes) {
            hsh_sha3_absorb(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

// ===== Finalize =====
void hsh_sha3_finalize(hsh_sha3_ctx *ctx, uint8_t *out) {
    if (ctx->finalized) return;

    size_t pad_len = 0;
    hsh_sha3_pad(ctx->buf, ctx->buf_len, ctx->rate_bytes, &pad_len);
    size_t total = ctx->buf_len + pad_len;

    for (size_t i = 0; i < total; i += ctx->rate_bytes)
        hsh_sha3_absorb(ctx, ctx->buf + i);

    ctx->finalized = 1;
    size_t out_len = ctx->output_bits / 8;
    size_t generated = 0;

    while (generated < out_len) {
        for (size_t i = 0; i < ctx->rate_bytes / 8 && generated < out_len; i++) {
            uint64_t val = ctx->state[i];
            size_t to_copy = (out_len - generated < 8)
                                 ? out_len - generated
                                 : 8;
            memcpy(out + generated, &val, to_copy);
            generated += to_copy;
        }
        if (generated < out_len)
            hsh_sha3_f(ctx);
    }
}

// ===== Initialization =====
static void hsh_sha3_init(hsh_sha3_ctx *ctx, int capacity_bits, int output_bits) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->capacity_bits = capacity_bits;
    ctx->output_bits = output_bits;
    ctx->rate_bytes = (1600 - capacity_bits) / 8;
}

void hsh_sha3_224_init(hsh_sha3_ctx *ctx) { hsh_sha3_init(ctx, 448, 224); }
void hsh_sha3_256_init(hsh_sha3_ctx *ctx) { hsh_sha3_init(ctx, 512, 256); }
void hsh_sha3_384_init(hsh_sha3_ctx *ctx) { hsh_sha3_init(ctx, 768, 384); }
void hsh_sha3_512_init(hsh_sha3_ctx *ctx) { hsh_sha3_init(ctx, 1024, 512); }

