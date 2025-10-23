/* hsh_md5.h */
#ifndef HSH_MD5_H
#define HSH_MD5_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t A, B, C, D;
    uint64_t counter;    // total bits processed
    unsigned char buffer[64];
    size_t buffer_len;
} hsh_md5_ctx;

/* User-callable API */
void hsh_md5_init(hsh_md5_ctx *ctx);
void hsh_md5_update(hsh_md5_ctx *ctx, const unsigned char *data, size_t len);
void hsh_md5_finalize(hsh_md5_ctx *ctx, unsigned char digest[16]);

#endif /* HSH_MD5_H */
