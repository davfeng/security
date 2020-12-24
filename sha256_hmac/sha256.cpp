// ConsoleApplication3.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "hmac.h"
#include "sha256.h"


#define SHA256_BYTES    32


#define FN_ inline static

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* -------------------------------------------------------------------------- */
FN_ uint8_t _shb(uint32_t x, uint32_t n)
{
    return ((x >> (n & 31)) & 0xff);
} /* _shb */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _shw(uint32_t x, uint32_t n)
{
    return ((x << (n & 31)) & 0xffffffff);
} /* _shw */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _r(uint32_t x, uint8_t n)
{
    return ((x >> n) | _shw(x, 32 - n));
} /* _r */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ ((~x) & z));
} /* _Ch */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _Ma(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ (x & z) ^ (y & z));
} /* _Ma */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _S0(uint32_t x)
{
    return (_r(x, 2) ^ _r(x, 13) ^ _r(x, 22));
} /* _S0 */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _S1(uint32_t x)
{
    return (_r(x, 6) ^ _r(x, 11) ^ _r(x, 25));
} /* _S1 */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _G0(uint32_t x)
{
    return (_r(x, 7) ^ _r(x, 18) ^ (x >> 3));
} /* _G0 */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _G1(uint32_t x)
{
    return (_r(x, 17) ^ _r(x, 19) ^ (x >> 10));
} /* _G1 */

/* -------------------------------------------------------------------------- */
FN_ uint32_t _word(uint8_t *c)
{
    return (_shw(c[0], 24) | _shw(c[1], 16) | _shw(c[2], 8) | (c[3]));
} /* _word */

/* -------------------------------------------------------------------------- */
FN_ void  _addbits(sha256_context *ctx, uint32_t n)
{
    if (ctx->bits[0] > (0xffffffff - n))
        ctx->bits[1] = (ctx->bits[1] + 1) & 0xFFFFFFFF;
    ctx->bits[0] = (ctx->bits[0] + n) & 0xFFFFFFFF;
} /* _addbits */

/* -------------------------------------------------------------------------- */
static void _hash(sha256_context *ctx)
{
    register uint32_t a, b, c, d, e, f, g, h, i;
    uint32_t t[2];

    uint32_t W[64];


    a = ctx->hash[0];
    b = ctx->hash[1];
    c = ctx->hash[2];
    d = ctx->hash[3];
    e = ctx->hash[4];
    f = ctx->hash[5];
    g = ctx->hash[6];
    h = ctx->hash[7];

    //
    // convert the 512 byte sequence into big-indian 32bits words
    //
    for (i = 0; i < 16; i++)
        W[i] = _word(&ctx->buf[_shw(i, 2)]);
    
    //
    // extends the 16 words to 64 words
    //
    for (i = 16; i < 64; i++)
        W[i] = _G1(W[i - 2]) + W[i - 7] + _G0(W[i - 15]) + W[i - 16];
        
    //
    // main loop to caculate the chunk's hash
    //
    for (i = 0; i < 64; i++) {

        t[0] = h + _S1(e) + _Ch(e, f, g) + K[i] + W[i];
        t[1] = _S0(a) + _Ma(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t[0];
        d = c;
        c = b;
        b = a;
        a = t[0] + t[1];
    }

    //
    // add this chunk's hash to the result
    //
    ctx->hash[0] += a;
    ctx->hash[1] += b;
    ctx->hash[2] += c;
    ctx->hash[3] += d;
    ctx->hash[4] += e;
    ctx->hash[5] += f;
    ctx->hash[6] += g;
    ctx->hash[7] += h;
} /* _hash */

/* -------------------------------------------------------------------------- */
void sha256_init(sha256_context *ctx)
{
    if (ctx != NULL) {
        ctx->bits[0] = ctx->bits[1] = 0;
        ctx->len = 0;
        ctx->hash[0] = 0x6a09e667;
        ctx->hash[1] = 0xbb67ae85;
        ctx->hash[2] = 0x3c6ef372;
        ctx->hash[3] = 0xa54ff53a;
        ctx->hash[4] = 0x510e527f;
        ctx->hash[5] = 0x9b05688c;
        ctx->hash[6] = 0x1f83d9ab;
        ctx->hash[7] = 0x5be0cd19;
    }
} /* sha256_init */

/* -------------------------------------------------------------------------- */
void sha256_hash(sha256_context *ctx, const void *data, size_t len)
{
    register size_t i;
    const uint8_t *bytes = (const uint8_t *)data;

    if ((ctx != NULL) && (bytes != NULL))
        for (i = 0; i < len; i++) {
            ctx->buf[ctx->len] = bytes[i];
            ctx->len++;
            if (ctx->len == sizeof(ctx->buf)) {
                _hash(ctx);
                _addbits(ctx, sizeof(ctx->buf) * 8);
                ctx->len = 0;
            }
        }
} /* sha256_hash */

/* -------------------------------------------------------------------------- */
void sha256_done(sha256_context *ctx, uint8_t *hash)
{
    register uint32_t i, j;

    if (ctx != NULL) {
        j = ctx->len % sizeof(ctx->buf);
        ctx->buf[j] = 0x80;
        for (i = j + 1; i < sizeof(ctx->buf); i++)
            ctx->buf[i] = 0x00;

        if (ctx->len > 55) {
            _hash(ctx);
            for (j = 0; j < sizeof(ctx->buf); j++)
                ctx->buf[j] = 0x00;
        }

        _addbits(ctx, ctx->len * 8);
        ctx->buf[63] = _shb(ctx->bits[0], 0);
        ctx->buf[62] = _shb(ctx->bits[0], 8);
        ctx->buf[61] = _shb(ctx->bits[0], 16);
        ctx->buf[60] = _shb(ctx->bits[0], 24);
        ctx->buf[59] = _shb(ctx->bits[1], 0);
        ctx->buf[58] = _shb(ctx->bits[1], 8);
        ctx->buf[57] = _shb(ctx->bits[1], 16);
        ctx->buf[56] = _shb(ctx->bits[1], 24);
        _hash(ctx);

        if (hash != NULL)
            for (i = 0, j = 24; i < 4; i++, j -= 8) {
                hash[i] = _shb(ctx->hash[0], j);
                hash[i + 4] = _shb(ctx->hash[1], j);
                hash[i + 8] = _shb(ctx->hash[2], j);
                hash[i + 12] = _shb(ctx->hash[3], j);
                hash[i + 16] = _shb(ctx->hash[4], j);
                hash[i + 20] = _shb(ctx->hash[5], j);
                hash[i + 24] = _shb(ctx->hash[6], j);
                hash[i + 28] = _shb(ctx->hash[7], j);
            }
    }
} /* sha256_done */

/* -------------------------------------------------------------------------- */
void sha256(const void *data, size_t len, uint8_t *hash)
{
    sha256_context ctx;

    sha256_init(&ctx);
    sha256_hash(&ctx, data, len);
    sha256_done(&ctx, hash);
} /* sha256 */


/* ========================================================================== */

#include <stdio.h>
#include <string.h>

void testsha256(void)
{
    const char *buf[] = {
        "",
        "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855",

        "abc",
        "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",

        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1",

        "The quick brown fox jumps over the lazy dog",
        "d7a8fbb3 07d78094 69ca9abc b0082e4f 8d5651e4 6d3cdb76 2d02d0bf 37c9e592",

        "The quick brown fox jumps over the lazy cog", /* avalanche effect test */
        "e4c4d8f3 bf76b692 de791a17 3e053211 50f7a345 b46484fe 427f6acc 7ecc81be",

        "bhn5bjmoniertqea40wro2upyflkydsibsk8ylkmgbvwi420t44cq034eou1szc1k0mk46oeb7ktzmlxqkbte2sy",
        "9085df2f 02e0cc45 5928d0f5 1b27b4bf 1d9cd260 a66ed1fd a11b0a3f f5756d99",

        "abcd",
        "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"
    };
    uint8_t hash[SHA256_BYTES];
    size_t i, j;

    for (i = 0; i < (sizeof(buf) / sizeof(buf[0])); i += 2) {
        sha256(buf[i], strlen(buf[i]), hash);
        printf("input = '%s'\ndigest: %s\nresult: ", buf[i], buf[i + 1]);
        for (j = 0; j < SHA256_BYTES; j++)
            printf("%02x%s", hash[j], ((j % 4) == 3) ? " " : "");

        printf("\n\n");
    }
}

void hmac_sha256(uint8_t out[HMAC_SHA256_DIGEST_SIZE], const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len);

void testhmac(void)
{
    int i, j, keylen, datalen;
    uint8_t digest[SHA256_DIGEST_LENGTH];

    const char *buf[] = {
    "12345",
    "This is a beautiful city",

    "abc",
    "I love programming",

    "abcdef",
    "Windows is an OS",

    "ab17cd",
    "visual studio code",

    "ab17cd",
    "#  The contents of this file are dedicated to the public domain.",

    "sdfsdfsdfdf",
    "codingMulti-Block Message84983e441c3bd26ebaae4aa1f95129e5e54670f1abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq Long Messagedea356a2cddd90c7a7ecedc5ebb563934f46045201234567 * 8001234567"
    "codingMulti-Block Message84983e441c3bd26ebaae4aa1f95129e5e54670f1abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq Long Messagedea356a2cddd90c7a7ecedc5ebb563934f46045201234567 * 8001234567"
    "codingMulti-Block Message84983e441c3bd26ebaae4aa1f95129e5e54670f1abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq Long Messagedea356a2cddd90c7a7ecedc5ebb563934f46045201234567 * 8001234567"
    };

    for (i = 0; i < (sizeof(buf) / sizeof(buf[0])); i += 2) {
        
        datalen = strlen(buf[i + 1]);
        keylen = strlen(buf[i]);

        hmac_sha256(digest, (const uint8_t*)buf[i+1], datalen, (const uint8_t*)buf[i], keylen);
        for (j = 0; j < SHA256_DIGEST_LENGTH; j++)
            printf("%02x", digest[j]);
        putchar('\n');
    }
}

int main(void)
{
    testsha256();
    testhmac();
}