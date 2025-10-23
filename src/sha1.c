#include "sha1.h"
#include <string.h>

static const uint32_t HSH_SHA1_INITIAL_STATE[5] = {
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0
};

static const uint32_t HSH_SHA1_K[4] = {
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
};

static inline uint32_t hsh_sha1_rotl(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

void hsh_sha1_init(hsh_sha1_ctx *ctx) {
    memcpy(ctx->h, HSH_SHA1_INITIAL_STATE, sizeof(HSH_SHA1_INITIAL_STATE));
    ctx->unprocessed_len = 0;
    ctx->message_byte_length = 0;
}

static void hsh_sha1_process_chunk(hsh_sha1_ctx *ctx, const uint8_t *chunk) {
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, k, temp;

    /* Convert 64-byte chunk to 16 big-endian 32-bit words */
    for (int i = 0; i < 16; i++) {
        w[i]  = (uint32_t)chunk[i*4] << 24;
        w[i] |= (uint32_t)chunk[i*4 + 1] << 16;
        w[i] |= (uint32_t)chunk[i*4 + 2] << 8;
        w[i] |= (uint32_t)chunk[i*4 + 3];
    }

    /* Extend the 16 words into 80 */
    for (int i = 16; i < 80; i++) {
        w[i] = hsh_sha1_rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];

    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = HSH_SHA1_K[0];
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = HSH_SHA1_K[1];
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = HSH_SHA1_K[2];
        } else {
            f = b ^ c ^ d;
            k = HSH_SHA1_K[3];
        }

        temp = hsh_sha1_rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = hsh_sha1_rotl(b, 30);
        b = a;
        a = temp;
    }

    ctx->h[0] = (ctx->h[0] + a) & 0xFFFFFFFF;
    ctx->h[1] = (ctx->h[1] + b) & 0xFFFFFFFF;
    ctx->h[2] = (ctx->h[2] + c) & 0xFFFFFFFF;
    ctx->h[3] = (ctx->h[3] + d) & 0xFFFFFFFF;
    ctx->h[4] = (ctx->h[4] + e) & 0xFFFFFFFF;
}

void hsh_sha1_update(hsh_sha1_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->message_byte_length += len;

    size_t total_len = ctx->unprocessed_len + len;
    size_t offset = 0;

    /* Process unprocessed + new data */
    if (total_len < HSH_SHA1_BLOCK_SIZE) {
        memcpy(ctx->unprocessed + ctx->unprocessed_len, data, len);
        ctx->unprocessed_len += len;
        return;
    }

    if (ctx->unprocessed_len > 0) {
        size_t fill = HSH_SHA1_BLOCK_SIZE - ctx->unprocessed_len;
        memcpy(ctx->unprocessed + ctx->unprocessed_len, data, fill);
        hsh_sha1_process_chunk(ctx, ctx->unprocessed);
        offset += fill;
        ctx->unprocessed_len = 0;
    }

    for (; offset + HSH_SHA1_BLOCK_SIZE <= len; offset += HSH_SHA1_BLOCK_SIZE) {
        hsh_sha1_process_chunk(ctx, data + offset);
    }

    if (offset < len) {
        ctx->unprocessed_len = len - offset;
        memcpy(ctx->unprocessed, data + offset, ctx->unprocessed_len);
    }
}

void hsh_sha1_finalize(hsh_sha1_ctx *ctx, uint8_t digest[HSH_SHA1_DIGEST_SIZE]) {
    uint64_t bit_len = ctx->message_byte_length * 8;
    uint8_t pad[HSH_SHA1_BLOCK_SIZE] = {0x80};
    size_t pad_len = (ctx->unprocessed_len < 56)
        ? (56 - ctx->unprocessed_len)
        : (120 - ctx->unprocessed_len);

    hsh_sha1_update(ctx, pad, pad_len);

    uint8_t length_bytes[8];
    for (int i = 0; i < 8; i++) {
        length_bytes[7 - i] = (uint8_t)((bit_len >> (i * 8)) & 0xFF);
    }
    hsh_sha1_update(ctx, length_bytes, 8);

    for (int i = 0; i < 5; i++) {
        digest[i * 4]     = (ctx->h[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx->h[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx->h[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = (ctx->h[i]) & 0xFF;
    }
}
