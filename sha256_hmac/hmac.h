#pragma once
#ifdef _MSC_VER
#include "sha256.h"

#define SHA256_DIGEST_LENGTH 32

#define B 64
#define L (SHA256_DIGEST_LENGTH)
//#define K (SHA256_DIGEST_LENGTH * 2)

#define I_PAD 0x36
#define O_PAD 0x5C


#define HMAC_SHA256_DIGEST_SIZE 32  /* Same as SHA-256's output size. */



void hmac_sha256(uint8_t out[HMAC_SHA256_DIGEST_SIZE], const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len);

#endif
