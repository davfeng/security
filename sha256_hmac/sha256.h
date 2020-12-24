#pragma once
#ifdef _MSC_VER
#ifndef uint8_t
typedef unsigned __int8 uint8_t;
#endif
#ifndef uint32_t
typedef unsigned __int32 uint32_t;
#endif
#ifndef uint64_t
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#endif
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

     typedef struct {
        uint8_t  buf[64];
        uint32_t hash[8];
        uint32_t bits[2];
        uint32_t len;
    } sha256_context;

    void sha256_init(sha256_context *ctx);
    void sha256_hash(sha256_context *ctx, const void *data, size_t len);
    void sha256_done(sha256_context *ctx, uint8_t *hash);

    void sha256(const void *data, size_t len, uint8_t *hash);

#ifdef __cplusplus
}
#endif