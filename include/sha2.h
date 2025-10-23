#ifndef HSH_SHA2_H
#define HSH_SHA2_H

#include <stdint.h>
#include <stddef.h>

/* SHA-256 context */
typedef struct {
    uint32_t h[8];
    uint64_t counter;         /* bit count */
    unsigned char buffer[64]; /* message buffer */
    size_t buffer_size;
} hsh_sha2_256_ctx;

/* SHA-224 context is typedef alias of SHA-256 context */
typedef hsh_sha2_256_ctx hsh_sha2_224_ctx;

/* SHA-512 context */
typedef struct {
    uint64_t h[8];
    unsigned char buffer[128];
    uint64_t counter;         /* bit count */
    size_t buffer_size;
} hsh_sha2_512_ctx;

/* SHA-384 context is typedef alias of SHA-512 context */
typedef hsh_sha2_512_ctx hsh_sha2_384_ctx;


/* Public APIs for SHA-224/256 */
void hsh_sha2_256_init(hsh_sha2_256_ctx *ctx);
void hsh_sha2_224_init(hsh_sha2_224_ctx *ctx);
void hsh_sha2_256_update(hsh_sha2_256_ctx *ctx, const unsigned char *data, size_t len);
void hsh_sha2_224_update(hsh_sha2_224_ctx *ctx, const unsigned char *data, size_t len);
void hsh_sha2_256_finalize(hsh_sha2_256_ctx *ctx, unsigned char *digest);
void hsh_sha2_224_finalize(hsh_sha2_224_ctx *ctx, unsigned char *digest);

/* Public APIs for SHA-384/512 */
void hsh_sha2_512_init(hsh_sha2_512_ctx *ctx);
void hsh_sha2_384_init(hsh_sha2_384_ctx *ctx);
void hsh_sha2_512_update(hsh_sha2_512_ctx *ctx, const unsigned char *data, size_t len);
void hsh_sha2_384_update(hsh_sha2_384_ctx *ctx, const unsigned char *data, size_t len);
void hsh_sha2_512_finalize(hsh_sha2_512_ctx *ctx, unsigned char *digest);
void hsh_sha2_384_finalize(hsh_sha2_384_ctx *ctx, unsigned char *digest);

#endif /* HSH_SHA2_H */
