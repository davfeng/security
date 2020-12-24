#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include "sha256.h"
#include "hmac.h"

void hmac_sha256(uint8_t *out, const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len)
{
    sha256_context ss;

    uint8_t kh[SHA256_DIGEST_LENGTH];

    /*

     * If the key length is bigger than the buffer size B, apply the hash

     * function to it first and use the result instead.

     */
    printf("key_len = %d, data_len=%d\n", key_len, data_len);
    if (key_len > B) {
        sha256_init(&ss);
        sha256_hash(&ss, key, key_len);
        sha256_done(&ss, kh);
        key_len = SHA256_DIGEST_LENGTH;
        key = kh;
    }


    /*

     * (1) append zeros to the end of K to create a B byte string

     *     (e.g., if K is of length 20 bytes and B=64, then K will be

     *     appended with 44 zero bytes 0x00)

     * (2) XOR (bitwise exclusive-OR) the B byte string computed in step

     *     (1) with ipad

     */

    printf("key_len = %d\n", key_len);
    uint8_t kx[B];

    for (size_t i = 0; i < key_len; i++)
        kx[i] = I_PAD ^ key[i];

    for (size_t i = key_len; i < B; i++)
        kx[i] = I_PAD ^ 0;


    /*

     * (3) append the stream of data 'text' to the B byte string resulting

     *     from step (2)

     * (4) apply H to the stream generated in step (3)

     */

    sha256_init(&ss);
    printf("sha256 initialized\n");
    sha256_hash(&ss, kx, B);
    printf("sha256 kx updated\n");
    sha256_hash(&ss, data, data_len);
    printf("sha256 data updated\n");
    sha256_done(&ss, out);
    printf("sha256 finalized\n");

    /*

     * (5) XOR (bitwise exclusive-OR) the B byte string computed in

     *     step (1) with opad

     *

     * NOTE: The "kx" variable is reused.

     */

    for (size_t i = 0; i < key_len; i++)
        kx[i] = O_PAD ^ key[i];

    for (size_t i = key_len; i < B; i++)
        kx[i] = O_PAD ^ 0;



    /*

     * (6) append the H result from step (4) to the B byte string

     *     resulting from step (5)

     * (7) apply H to the stream generated in step (6) and output

     *     the result

     */

    sha256_init(&ss);
    sha256_hash(&ss, kx, B);
    sha256_hash(&ss, out, SHA256_DIGEST_LENGTH);
    sha256_done(&ss, out);
}

