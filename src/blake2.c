#include "blake2.h"
#include <string.h>

/* ============================================
 * Private constants
 * ============================================ */

static const uint64_t HSH_BLAKE2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint32_t HSH_BLAKE2S_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL,
    0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL,
    0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t HSH_BLAKE2_SIGMA[10][16] = {
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
    {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
    {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
    {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
    {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
    {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
    {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
    {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
    {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}
};

/* ============================================
 * Utility macros
 * ============================================ */

#define ROTR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

/* ============================================
 * BLAKE2b (64-bit) Private Helper Functions
 * ============================================ */

static void hsh_blake2b_G(uint64_t v[16], int a, int b, int c, int d,
                          uint64_t x, uint64_t y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = ROTR64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = ROTR64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = ROTR64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ROTR64(v[b] ^ v[c], 63);
}

static void hsh_blake2b_compress(hsh_blake2b_ctx *ctx,
                                 const uint8_t block[128],
                                 int is_last)
{
    uint64_t m[16];
    uint64_t v[16];
    memcpy(m, block, 128);
    memcpy(v, ctx->h, 64);
    memcpy(v + 8, HSH_BLAKE2B_IV, 64);

    v[12] ^= ctx->t_low;
    v[13] ^= ctx->t_high;
    if (is_last) v[14] ^= 0xFFFFFFFFFFFFFFFFULL;

    for (int r = 0; r < 12; r++) {
        const uint8_t *s = HSH_BLAKE2_SIGMA[r % 10];
        hsh_blake2b_G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        hsh_blake2b_G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        hsh_blake2b_G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        hsh_blake2b_G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        hsh_blake2b_G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        hsh_blake2b_G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        hsh_blake2b_G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        hsh_blake2b_G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; i++)
        ctx->h[i] ^= v[i] ^ v[i + 8];
}

int hsh_blake2b_init(hsh_blake2b_ctx *ctx, size_t digest_size,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *personal, size_t pers_len)
{
    if (digest_size == 0 || digest_size > 64) return -1;
    if (key_len > 64) return -1;
    if (pers_len > 16) return -1;

    memcpy(ctx->h, HSH_BLAKE2B_IV, sizeof(HSH_BLAKE2B_IV));
    uint64_t param = 0x01010000UL ^ ((uint64_t)key_len << 8) ^ digest_size;
    ctx->h[0] ^= param;

    if (personal && pers_len > 0) {
        uint8_t buf[16] = {0};
        memcpy(buf, personal, pers_len);
        uint64_t lo, hi;
        memcpy(&lo, buf, 8);
        memcpy(&hi, buf + 8, 8);
        ctx->h[6] ^= lo;
        ctx->h[7] ^= hi;
    }

    ctx->t_low = 0;
    ctx->t_high = 0;
    ctx->buffer_len = 0;
    ctx->digest_size = digest_size;

    if (key && key_len > 0) {
        uint8_t block[128] = {0};
        memcpy(block, key, key_len);
        hsh_blake2b_update(ctx, block, 128);
    }

    return 0;
}

void hsh_blake2b_update(hsh_blake2b_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        size_t space = 128 - ctx->buffer_len;
        size_t take = (len - offset > space) ? space : len - offset;
        memcpy(ctx->buffer + ctx->buffer_len, data + offset, take);
        ctx->buffer_len += take;
        offset += take;

        if (ctx->buffer_len == 128) {
            /* Increment 128-bit counter */
            ctx->t_low += 128;
            if (ctx->t_low < 128)  /* overflow */
                ctx->t_high++;
            hsh_blake2b_compress(ctx, ctx->buffer, 0);
            ctx->buffer_len = 0;
        }
    }
}

void hsh_blake2b_finalize(hsh_blake2b_ctx *ctx, uint8_t *digest)
{
    ctx->t_low += ctx->buffer_len;
    if (ctx->t_low < ctx->buffer_len)
        ctx->t_high++;
    uint8_t block[128] = {0};
    memcpy(block, ctx->buffer, ctx->buffer_len);
    hsh_blake2b_compress(ctx, block, 1);
    memcpy(digest, ctx->h, ctx->digest_size);
}

/* ============================================
 * BLAKE2s (32-bit)
 * ============================================ */

static void hsh_blake2s_G(uint32_t v[16], int a, int b, int c, int d,
                          uint32_t x, uint32_t y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = ROTR32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = ROTR32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 7);
}

static void hsh_blake2s_compress(hsh_blake2s_ctx *ctx,
                                 const uint8_t block[64],
                                 int is_last)
{
    uint32_t m[16];
    uint32_t v[16];
    memcpy(m, block, 64);
    memcpy(v, ctx->h, 32);
    memcpy(v + 8, HSH_BLAKE2S_IV, 32);

    v[12] ^= (uint32_t)ctx->t;
    v[13] ^= (uint32_t)(ctx->t >> 32);
    if (is_last) v[14] ^= 0xFFFFFFFFU;

    for (int r = 0; r < 10; r++) {
        const uint8_t *s = HSH_BLAKE2_SIGMA[r];
        hsh_blake2s_G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        hsh_blake2s_G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        hsh_blake2s_G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        hsh_blake2s_G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        hsh_blake2s_G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        hsh_blake2s_G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        hsh_blake2s_G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        hsh_blake2s_G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; i++)
        ctx->h[i] ^= v[i] ^ v[i + 8];
}

int hsh_blake2s_init(hsh_blake2s_ctx *ctx, size_t digest_size,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *personal, size_t pers_len)
{
    if (digest_size == 0 || digest_size > 32) return -1;
    if (key_len > 32) return -1;
    if (pers_len > 8) return -1;

    memcpy(ctx->h, HSH_BLAKE2S_IV, sizeof(HSH_BLAKE2S_IV));
    uint32_t param = 0x01010000U ^ ((uint32_t)key_len << 8) ^ digest_size;
    ctx->h[0] ^= param;

    if (personal && pers_len > 0) {
        uint8_t buf[8] = {0};
        memcpy(buf, personal, pers_len);
        uint32_t lo, hi;
        memcpy(&lo, buf, 4);
        memcpy(&hi, buf + 4, 4);
        ctx->h[6] ^= lo;
        ctx->h[7] ^= hi;
    }

    ctx->t = 0;
    ctx->buffer_len = 0;
    ctx->digest_size = digest_size;

    if (key && key_len > 0) {
        uint8_t block[64] = {0};
        memcpy(block, key, key_len);
        hsh_blake2s_update(ctx, block, 64);
    }

    return 0;
}

void hsh_blake2s_update(hsh_blake2s_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        size_t space = 64 - ctx->buffer_len;
        size_t take = (len - offset > space) ? space : len - offset;
        memcpy(ctx->buffer + ctx->buffer_len, data + offset, take);
        ctx->buffer_len += take;
        offset += take;

        if (ctx->buffer_len == 64) {
            ctx->t += 64;
            hsh_blake2s_compress(ctx, ctx->buffer, 0);
            ctx->buffer_len = 0;
        }
    }
}

void hsh_blake2s_finalize(hsh_blake2s_ctx *ctx, uint8_t *digest)
{
    ctx->t += ctx->buffer_len;
    uint8_t block[64] = {0};
    memcpy(block, ctx->buffer, ctx->buffer_len);
    hsh_blake2s_compress(ctx, block, 1);
    memcpy(digest, ctx->h, ctx->digest_size);
}

