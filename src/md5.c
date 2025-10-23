/* hsh_md5.c */
#include "md5.h"
#include <stdlib.h>
#include <string.h>

static const uint32_t hsh_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

/* Precomputed MD5 K constants (hexadecimal, little-endian order) */
static const uint32_t hsh_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static uint32_t hsh_left_rotate(uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32 - c));
}

static void hsh_md5_process_chunk(hsh_md5_ctx *ctx, const unsigned char chunk[64]) {
    uint32_t X[16];
    for (int i = 0; i < 16; i++) {
        X[i] = (uint32_t)chunk[i*4]
             | ((uint32_t)chunk[i*4 + 1] << 8)
             | ((uint32_t)chunk[i*4 + 2] << 16)
             | ((uint32_t)chunk[i*4 + 3] << 24);
    }

    uint32_t A = ctx->A, B = ctx->B, C = ctx->C, D = ctx->D;
    uint32_t f, g, temp;

    for (int i = 0; i < 64; i++) {
        if (i < 16) {
            f = (B & C) | ((~B) & D);
            g = i;
        } else if (i < 32) {
            f = (B & D) | (C & (~D));
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = B ^ C ^ D;
            g = (3 * i + 5) % 16;
        } else {
            f = C ^ (B | (~D));
            g = (7 * i) % 16;
        }
        temp = D;
        D = C;
        C = B;
        B = (B + hsh_left_rotate(A + f + hsh_K[i] + X[g], hsh_S[i])) & 0xFFFFFFFF;
        A = temp;
    }

    ctx->A += A;
    ctx->B += B;
    ctx->C += C;
    ctx->D += D;
}

/* Public API */

void hsh_md5_init(hsh_md5_ctx *ctx) {
    ctx->A = 0x67452301;
    ctx->B = 0xefcdab89;
    ctx->C = 0x98badcfe;
    ctx->D = 0x10325476;
    ctx->counter = 0;
    ctx->buffer_len = 0;
}

void hsh_md5_update(hsh_md5_ctx *ctx, const unsigned char *data, size_t len) {
    ctx->counter += (uint64_t)len * 8;

    size_t i = 0;
    if (ctx->buffer_len > 0) {
        size_t fill = 64 - ctx->buffer_len;
        if (len < fill) {
            memcpy(ctx->buffer + ctx->buffer_len, data, len);
            ctx->buffer_len += len;
            return;
        } else {
            memcpy(ctx->buffer + ctx->buffer_len, data, fill);
            hsh_md5_process_chunk(ctx, ctx->buffer);
            ctx->buffer_len = 0;
            i += fill;
        }
    }

    for (; i + 64 <= len; i += 64) {
        hsh_md5_process_chunk(ctx, data + i);
    }

    if (i < len) {
        size_t rem = len - i;
        memcpy(ctx->buffer, data + i, rem);
        ctx->buffer_len = rem;
    }
}

void hsh_md5_finalize(hsh_md5_ctx *ctx, unsigned char digest[16]) {
    unsigned char padding[64] = {0x80};
    unsigned char length_encoded[8];
    uint64_t bits = ctx->counter;

    for (int i = 0; i < 8; i++)
        length_encoded[i] = (unsigned char)((bits >> (8 * i)) & 0xFF);

    size_t pad_len = (ctx->buffer_len < 56)
        ? (56 - ctx->buffer_len)
        : (120 - ctx->buffer_len);

    hsh_md5_update(ctx, padding, pad_len);
    hsh_md5_update(ctx, length_encoded, 8);

    uint32_t words[4] = {ctx->A, ctx->B, ctx->C, ctx->D};
    for (int i = 0; i < 4; i++) {
        digest[i*4 + 0] = (unsigned char)(words[i] & 0xFF);
        digest[i*4 + 1] = (unsigned char)((words[i] >> 8) & 0xFF);
        digest[i*4 + 2] = (unsigned char)((words[i] >> 16) & 0xFF);
        digest[i*4 + 3] = (unsigned char)((words[i] >> 24) & 0xFF);
    }
}
