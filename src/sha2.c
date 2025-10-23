#include "sha2.h"
#include <string.h>

/* SHA-256 constants */
static const uint32_t hsh_sha2_K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* SHA-512 constants */
static const uint64_t hsh_sha2_K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

/* Helper macros */
#define hsh_sha2_ror32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define hsh_sha2_ror64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define hsh_sha2_ch(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define hsh_sha2_maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* SHA-256/224: process 64-byte chunk */
static void hsh_sha2_256_process_chunk(hsh_sha2_256_ctx *ctx, const unsigned char *chunk) {
    uint32_t w[64];
    uint32_t a,b,c,d,e,f,g,h;
    size_t i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)chunk[4*i] << 24) | ((uint32_t)chunk[4*i + 1] << 16) |
               ((uint32_t)chunk[4*i + 2] << 8)  | (uint32_t)chunk[4*i + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = hsh_sha2_ror32(w[i-15], 7) ^ hsh_sha2_ror32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = hsh_sha2_ror32(w[i-2], 17) ^ hsh_sha2_ror32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = hsh_sha2_ror32(e, 6) ^ hsh_sha2_ror32(e, 11) ^ hsh_sha2_ror32(e, 25);
        uint32_t temp1 = h + S1 + hsh_sha2_ch(e, f, g) + hsh_sha2_K256[i] + w[i];
        uint32_t S0 = hsh_sha2_ror32(a, 2) ^ hsh_sha2_ror32(a, 13) ^ hsh_sha2_ror32(a, 22);
        uint32_t temp2 = S0 + hsh_sha2_maj(a, b, c);

        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

/* SHA-512/384: process 128-byte chunk */
static void hsh_sha2_512_process_chunk(hsh_sha2_512_ctx *ctx, const unsigned char *chunk) {
    uint64_t w[80];
    uint64_t a,b,c,d,e,f,g,h;
    size_t i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint64_t)chunk[8*i] << 56) | ((uint64_t)chunk[8*i + 1] << 48) |
               ((uint64_t)chunk[8*i + 2] << 40) | ((uint64_t)chunk[8*i + 3] << 32) |
               ((uint64_t)chunk[8*i + 4] << 24) | ((uint64_t)chunk[8*i + 5] << 16) |
               ((uint64_t)chunk[8*i + 6] << 8)  | (uint64_t)chunk[8*i + 7];
    }
    for (i = 16; i < 80; i++) {
        uint64_t s0 = hsh_sha2_ror64(w[i-15], 1) ^ hsh_sha2_ror64(w[i-15], 8) ^ (w[i-15] >> 7);
        uint64_t s1 = hsh_sha2_ror64(w[i-2], 19) ^ hsh_sha2_ror64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];

    for (i = 0; i < 80; i++) {
        uint64_t S1 = hsh_sha2_ror64(e, 14) ^ hsh_sha2_ror64(e, 18) ^ hsh_sha2_ror64(e, 41);
        uint64_t temp1 = h + S1 + hsh_sha2_ch(e, f, g) + hsh_sha2_K512[i] + w[i];
        uint64_t S0 = hsh_sha2_ror64(a, 28) ^ hsh_sha2_ror64(a, 34) ^ hsh_sha2_ror64(a, 39);
        uint64_t temp2 = S0 + hsh_sha2_maj(a, b, c);

        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

/* === SHA-224/256 functions === */

void hsh_sha2_256_init(hsh_sha2_256_ctx *ctx) {
    static const uint32_t init[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(ctx->h, init, sizeof(init));
    ctx->buffer_size = 0;
    ctx->counter = 0;
}

void hsh_sha2_224_init(hsh_sha2_224_ctx *ctx) {
    static const uint32_t init[8] = {
        0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,
        0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4
    };
    memcpy(ctx->h, init, sizeof(init));
    ctx->buffer_size = 0;
    ctx->counter = 0;
}

void hsh_sha2_256_update(hsh_sha2_256_ctx *ctx, const unsigned char *data, size_t len) {
    ctx->counter += len * 8;

    while (len > 0) {
        size_t copy = 64 - ctx->buffer_size;
        if (copy > len) copy = len;
        memcpy(ctx->buffer + ctx->buffer_size, data, copy);
        ctx->buffer_size += copy;
        data += copy;
        len -= copy;

        if (ctx->buffer_size == 64) {
            hsh_sha2_256_process_chunk(ctx, ctx->buffer);
            ctx->buffer_size = 0;
        }
    }
}

void hsh_sha2_224_update(hsh_sha2_224_ctx *ctx, const unsigned char *data, size_t len) {
    hsh_sha2_256_update(ctx, data, len);
}

void hsh_sha2_256_finalize(hsh_sha2_256_ctx *ctx, unsigned char *digest) {
    size_t i;
    uint64_t bit_len = ctx->counter;

    ctx->buffer[ctx->buffer_size++] = 0x80;
    if (ctx->buffer_size > 56) {
        while (ctx->buffer_size < 64) ctx->buffer[ctx->buffer_size++] = 0;
        hsh_sha2_256_process_chunk(ctx, ctx->buffer);
        ctx->buffer_size = 0;
    }
    while (ctx->buffer_size < 56) ctx->buffer[ctx->buffer_size++] = 0;

    for (i = 0; i < 8; i++) {
        ctx->buffer[63 - i] = (unsigned char)(bit_len >> (8 * i));
    }
    hsh_sha2_256_process_chunk(ctx, ctx->buffer);

    for (i = 0; i < 8; i++) {
        digest[4*i] = (ctx->h[i] >> 24) & 0xff;
        digest[4*i + 1] = (ctx->h[i] >> 16) & 0xff;
        digest[4*i + 2] = (ctx->h[i] >> 8) & 0xff;
        digest[4*i + 3] = ctx->h[i] & 0xff;
    }
}

void hsh_sha2_224_finalize(hsh_sha2_224_ctx *ctx, unsigned char *digest) {
    unsigned char full[32];
    hsh_sha2_256_finalize(ctx, full);
    memcpy(digest, full, 28);
}

/* === SHA-384/512 functions === */

void hsh_sha2_512_init(hsh_sha2_512_ctx *ctx) {
    static const uint64_t init[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
    };
    memcpy(ctx->h, init, sizeof(init));
    ctx->buffer_size = 0;
    ctx->counter = 0;
}

void hsh_sha2_384_init(hsh_sha2_384_ctx *ctx) {
    static const uint64_t init[8] = {
        0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,
        0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,
        0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL
    };
    memcpy(ctx->h, init, sizeof(init));
    ctx->buffer_size = 0;
    ctx->counter = 0;
}

void hsh_sha2_512_update(hsh_sha2_512_ctx *ctx, const unsigned char *data, size_t len) {
    ctx->counter += len * 8;

    while (len > 0) {
        size_t copy = 128 - ctx->buffer_size;
        if (copy > len) copy = len;
        memcpy(ctx->buffer + ctx->buffer_size, data, copy);
        ctx->buffer_size += copy;
        data += copy;
        len -= copy;

        if (ctx->buffer_size == 128) {
            hsh_sha2_512_process_chunk(ctx, ctx->buffer);
            ctx->buffer_size = 0;
        }
    }
}

void hsh_sha2_384_update(hsh_sha2_384_ctx *ctx, const unsigned char *data, size_t len) {
    hsh_sha2_512_update(ctx, data, len);
}

void hsh_sha2_512_finalize(hsh_sha2_512_ctx *ctx, unsigned char *digest) {
    size_t i;
    uint64_t bit_len = ctx->counter;

    ctx->buffer[ctx->buffer_size++] = 0x80;
    if (ctx->buffer_size > 112) {
        while (ctx->buffer_size < 128) ctx->buffer[ctx->buffer_size++] = 0;
        hsh_sha2_512_process_chunk(ctx, ctx->buffer);
        ctx->buffer_size = 0;
    }
    while (ctx->buffer_size < 112) ctx->buffer[ctx->buffer_size++] = 0;

    memset(ctx->buffer + 112, 0, 8);
    for (i = 0; i < 8; i++) {
        ctx->buffer[127 - i] = (unsigned char)(bit_len >> (8 * i));
    }
    hsh_sha2_512_process_chunk(ctx, ctx->buffer);

    for (i = 0; i < 8; i++) {
        digest[8*i] = (ctx->h[i] >> 56) & 0xff;
        digest[8*i + 1] = (ctx->h[i] >> 48) & 0xff;
        digest[8*i + 2] = (ctx->h[i] >> 40) & 0xff;
        digest[8*i + 3] = (ctx->h[i] >> 32) & 0xff;
        digest[8*i + 4] = (ctx->h[i] >> 24) & 0xff;
        digest[8*i + 5] = (ctx->h[i] >> 16) & 0xff;
        digest[8*i + 6] = (ctx->h[i] >> 8) & 0xff;
        digest[8*i + 7] = ctx->h[i] & 0xff;
    }
}

void hsh_sha2_384_finalize(hsh_sha2_384_ctx *ctx, unsigned char *digest) {
    unsigned char full[64];
    hsh_sha2_512_finalize(ctx, full);
    memcpy(digest, full, 48);
}
