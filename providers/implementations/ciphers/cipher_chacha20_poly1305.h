/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for chacha20_poly1305 cipher */

#include "include/crypto/poly1305.h"
#include "cipher_chacha20.h"
#include <time.h>
#include <omp.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "gf2x.h"

#define NO_TLS_PAYLOAD_LENGTH ((size_t)-1)
#define CHACHA20_POLY1305_IVLEN 12

typedef struct {
    PROV_CIPHER_CTX base;       /* must be first */
    PROV_CHACHA20_CTX chacha;
    POLY1305 poly1305;
    unsigned int nonce[12 / 4];
    unsigned char tag[POLY1305_BLOCK_SIZE];
    unsigned char tls_aad[POLY1305_BLOCK_SIZE];
    struct { uint64_t aad, text; } len;
    unsigned int aad : 1;
    unsigned int mac_inited : 1;
    size_t tag_len;
    size_t tls_payload_length;
    size_t tls_aad_pad_sz;
} PROV_CHACHA20_POLY1305_CTX;

typedef struct prov_cipher_hw_chacha_aead_st {
    PROV_CIPHER_HW base; /* must be first */
    int (*aead_cipher)(PROV_CIPHER_CTX *dat, unsigned char *out, size_t *outl,
                       const unsigned char *in, size_t len);
    int (*initiv)(PROV_CIPHER_CTX *ctx);
    int (*tls_init)(PROV_CIPHER_CTX *ctx, unsigned char *aad, size_t alen);
    int (*tls_iv_set_fixed)(PROV_CIPHER_CTX *ctx, unsigned char *fixed,
                            size_t flen);
} PROV_CIPHER_HW_CHACHA20_POLY1305;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_chacha20_poly1305(size_t keybits);

/**
 * Performs a single-bit XOR operation between two input bits and stores the result in the output.
 *
 * @param out   Pointer to the output array of bits.
 * @param in_a  Pointer to the first input array of bits.
 * @param in_b  Pointer to the second input array of bits.
 * @param i     Index of the bit to set in the output.
 * @param a     Index of the bit in the first input array.
 * @param b     Index of the bit in the second input array.
 */
void xor_single(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b,
                int64_t i, int64_t a, int64_t b);

/**
 * Performs a single-bit XOR operation between three input bits and stores the result in the output.
 *
 * @param out   Pointer to the output array of bits.
 * @param in_a  Pointer to the first input array of bits.
 * @param in_b  Pointer to the second input array of bits.
 * @param in_c  Pointer to the third input array of bits.
 * @param i     Index of the bit to set in the output.
 * @param a     Index of the bit in the first input array.
 * @param b     Index of the bit in the second input array.
 * @param c     Index of the bit in the third input array.
 */
void xor3_single(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b, const uint64_t *in_c,
                 int64_t i, int64_t a, int64_t b, int64_t c);

/**
 * Performs a range XOR operation between two input arrays of bits and stores the result in the output.
 *
 * @param out      Pointer to the output array of bits.
 * @param in_a     Pointer to the first input array of bits.
 * @param in_b     Pointer to the second input array of bits.
 * @param i_begin  Starting index of the range in the output array.
 * @param i_end    Ending index (exclusive) of the range in the output array.
 * @param a        Starting index in the first input array.
 * @param b        Starting index in the second input array.
 */
void xor_range_v1(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b,
                 int64_t i_begin, int64_t i_end, int64_t a, int64_t b);

/**
 * Performs a range XOR operation between three input arrays of bits and stores the result in the output.
 *
 * @param out      Pointer to the output array of bits.
 * @param in_a     Pointer to the first input array of bits.
 * @param in_b     Pointer to the second input array of bits.
 * @param in_c     Pointer to the third input array of bits.
 * @param i_begin  Starting index of the range in the output array.
 * @param i_end    Ending index (exclusive) of the range in the output array.
 * @param a        Starting index in the first input array.
 * @param b        Starting index in the second input array.
 * @param c        Starting index in the third input array.
 */
void xor3_range_v1(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b, const uint64_t* in_c,
                  int64_t i_begin, int64_t i_end, int64_t a, int64_t b, int64_t c);

/**
 * Performs a range XOR operation between two input arrays of bits (version 2) and stores the result in the output.
 *
 * @param out      Pointer to the output array of bits.
 * @param in_a     Pointer to the first input array of bits.
 * @param in_b     Pointer to the second input array of bits.
 * @param i_begin  Starting index of the range in the output array.
 * @param i_end    Ending index (exclusive) of the range in the output array.
 * @param a        Starting index in the first input array.
 * @param b        Starting index in the second input array.
 */
void xor_range_v2(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b,
                 int64_t i_begin, int64_t i_end, int64_t a, int64_t b);

/**
 * Performs a range XOR operation between three input arrays of bits (version 2) and stores the result in the output.
 *
 * @param out      Pointer to the output array of bits.
 * @param in_a     Pointer to the first input array of bits.
 * @param in_b     Pointer to the second input array of bits.
 * @param in_c     Pointer to the third input array of bits.
 * @param i_begin  Starting index of the range in the output array.
 * @param i_end    Ending index (exclusive) of the range in the output array.
 * @param a        Starting index in the first input array.
 * @param b        Starting index in the second input array.
 * @param c        Starting index in the third input array.
 */
void xor3_range_v2(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b, const uint64_t *in_c,
                  int64_t i_begin, int64_t i_end, int64_t a, int64_t b, int64_t c);

/**
 * Selects and performs a range XOR operation between three input arrays based on the version.
 *
 * @param version  The version of the XOR range function to use (1 or 2).
 * @param ...      Variable arguments corresponding to the selected XOR range function.
 */
#define xor3_range_select(version, ...) do { \
  if(version == 1) { \
    xor3_range_v1(__VA_ARGS__); \
  } \
  else if(version == 2) { \
    xor3_range_v2(__VA_ARGS__); \
  } \
} while(0)

/**
 * Selects and performs a range XOR operation between two input arrays based on the version.
 *
 * @param version  The version of the XOR range function to use (1 or 2).
 * @param ...      Variable arguments corresponding to the selected XOR range function.
 */
#define xor_range_select(version, ...) do { \
  if(version == 1) { \
    xor_range_v1(__VA_ARGS__); \
  } \
  else if(version == 2) { \
    xor_range_v2(__VA_ARGS__); \
  } \
} while(0)

// Function Declarations for Reduction Operations

/**
 * Performs a reduction operation (version c=1) in a sequential manner.
 *
 * @param d           Input array for reduction.
 * @param Dred        Output array after reduction.
 * @param lenR_64     Length of R in 64-bit chunks.
 * @param lenR        Length of R in bits.
 * @param lenDred_64  Length of Dred in 64-bit chunks.
 * @param b           Parameter 'b' as per the reduction algorithm.
 */
void reduction_c1_seq(uint64_t *d, uint64_t *Dred, uint64_t lenR_64,
                      uint64_t lenR, uint64_t lenDred_64, uint64_t b);

/**
 * Performs a reduction operation (version c=1) in parallel using OpenMP.
 *
 * @param d           Input array for reduction.
 * @param Dred        Output array after reduction.
 * @param lenR_64     Length of R in 64-bit chunks.
 * @param lenR        Length of R in bits.
 * @param lenDred_64  Length of Dred in 64-bit chunks.
 * @param b           Parameter 'b' as per the reduction algorithm.
 */
void reduction_c1_par(uint64_t *d, uint64_t *Dred, uint64_t lenR_64,
                      uint64_t lenR, uint64_t lenDred_64, uint64_t b);

/**
 * Performs a batched reduction operation (version c=1) in a sequential manner.
 *
 * @param d           Input array for reduction.
 * @param Dred        Output array after reduction.
 * @param lenR_64     Length of R in 64-bit chunks.
 * @param lenR        Length of R in bits.
 * @param lenDred_64  Length of Dred in 64-bit chunks.
 * @param b           Parameter 'b' as per the reduction algorithm.
 */
void reduction_c1_batched_seq(uint64_t *d, uint64_t *Dred, uint64_t lenR_64,
                              uint64_t lenR, uint64_t lenDred_64, uint64_t b);

/**
 * Selects and performs a reduction operation based on the algorithm version.
 *
 * @param algorithm   The version of the reduction algorithm to use (1, 2, or 3).
 * @param poly_R      Input polynomial R.
 * @param fin_key     Output finite key after reduction.
 * @param lenR_64     Length of R in 64-bit chunks.
 * @param lenR        Length of R in bits.
 * @param lenX        Length parameter X as per the reduction algorithm.
 * @param lenDred_64  Length of Dred in 64-bit chunks.
 */
void reduction(int algorithm, uint64_t *poly_R, uint64_t *fin_key,
               uint64_t lenR_64, uint64_t lenR, uint64_t lenX,
               uint64_t lenDred_64);

// Function Declarations for GF2X Multiplication

/**
 * Performs simple binary polynomial multiplication in GF(2)[x] in a sequential manner.
 *
 * @param c         Output array to store the result.
 * @param a         Input polynomial A.
 * @param terms_a   Number of terms in polynomial A.
 * @param b         Input polynomial B.
 * @param terms_b   Number of terms in polynomial B.
 * @param d         Temporary array for intermediate results.
 * @param chunkSize Size of each chunk for multiplication.
 */
void simplemult_gf2x(uint64_t *c, uint64_t *a, unsigned terms_a,
                     uint64_t *b, unsigned terms_b, uint64_t *d,
                     unsigned chunkSize);

/**
 * Performs simple binary polynomial multiplication in GF(2)[x] in parallel using OpenMP.
 *
 * @param c         Output array to store the result.
 * @param a         Input polynomial A.
 * @param terms_a   Number of terms in polynomial A.
 * @param b         Input polynomial B.
 * @param terms_b   Number of terms in polynomial B.
 * @param d         Temporary array for intermediate results.
 * @param chunkSize Size of each chunk for multiplication.
 * @param locks     Array of OpenMP locks for thread synchronization.
 */
void simplemult_gf2x_par(uint64_t *c, uint64_t *a, unsigned terms_a,
                         uint64_t *b, unsigned terms_b, uint64_t *d,
                         unsigned chunkSize, omp_lock_t *locks);


// Function Declarations for Encryption

/**
 * Performs entropic encryption on the input data.
 *
 * @param in        Pointer to the input data.
 * @param out       Pointer to the output buffer where encrypted data will be stored.
 * @param lenM      Length of the input data in bytes.
 * @param key       Pointer to the encryption key.
 * @param len_key   Length of the encryption key in bytes.
 */
void entropic_encryption(const unsigned char *in, unsigned char *out,
                        size_t lenM, const void *key, size_t len_key);



/**
 * @brief Retrieves the value of a specific bit from an array of bits.
 *
 * @param bits Pointer to the array of bits (each uint64_t represents 64 bits).
 * @param i    The index of the bit to retrieve.
 * @return bool The value of the bit (true if set, false otherwise).
 */
bool get_bit(const uint64_t* bits, uint64_t i);

/**
 * @brief Aligns the given value `x` down to the nearest multiple of `align`.
 *
 * @param x     The value to align.
 * @param align The alignment boundary.
 * @return int64_t The aligned value.
 */
int64_t prev_align(int64_t x, int64_t align);

/**
 * @brief Sets or clears a specific bit in an array of bits.
 *
 * @param bits Pointer to the array of bits (each uint64_t represents 64 bits).
 * @param i    The index of the bit to set or clear.
 * @param flag If true, the bit is set; if false, the bit is cleared.
 */
void set_bit(uint64_t* bits, uint64_t i, bool flag);

/**
 * @brief Extracts a sequence of bits starting from a specific offset across two uint64_t elements.
 *
 * @param off  The bit offset from which to start extraction.
 * @param bits Pointer to the array of bits (each uint64_t represents 64 bits).
 * @return uint64_t The extracted bits combined into a single uint64_t.
 */
uint64_t extract_bits(uint64_t off, const uint64_t *bits);
