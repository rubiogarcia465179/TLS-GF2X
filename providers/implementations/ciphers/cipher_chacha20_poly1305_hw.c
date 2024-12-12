/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* chacha20_poly1305 cipher implementation */

#include "internal/endian.h"
#include "cipher_chacha20_poly1305.h"


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <omp.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "gf2x.h"

#define INDEX_I(X) (((X) % 64))  
#define INDEX_64(X, NUM64) (((X)/64))
#define MASK_ONE(X) ((uint64_t)1 << (X))
#define SHIFT_BACK(X, INDEX) (X >> INDEX)



static int chacha_poly1305_tls_init(PROV_CIPHER_CTX *bctx,
                                    unsigned char *aad, size_t alen)
{
    unsigned int len;
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;

    if (alen != EVP_AEAD_TLS1_AAD_LEN)
        return 0;

    memcpy(ctx->tls_aad, aad, EVP_AEAD_TLS1_AAD_LEN);
    len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8 | aad[EVP_AEAD_TLS1_AAD_LEN - 1];
    aad = ctx->tls_aad;
    if (!bctx->enc) {
        if (len < POLY1305_BLOCK_SIZE)
            return 0;
        len -= POLY1305_BLOCK_SIZE; /* discount attached tag */
        aad[EVP_AEAD_TLS1_AAD_LEN - 2] = (unsigned char)(len >> 8);
        aad[EVP_AEAD_TLS1_AAD_LEN - 1] = (unsigned char)len;
    }
    ctx->tls_payload_length = len;

    /* merge record sequence number as per RFC7905 */
    ctx->chacha.counter[1] = ctx->nonce[0];
    ctx->chacha.counter[2] = ctx->nonce[1] ^ CHACHA_U8TOU32(aad);
    ctx->chacha.counter[3] = ctx->nonce[2] ^ CHACHA_U8TOU32(aad+4);
    ctx->mac_inited = 0;

    return POLY1305_BLOCK_SIZE;         /* tag length */
}

static int chacha_poly1305_tls_iv_set_fixed(PROV_CIPHER_CTX *bctx,
                                            unsigned char *fixed, size_t flen)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;

    if (flen != CHACHA20_POLY1305_IVLEN)
        return 0;
    ctx->nonce[0] = ctx->chacha.counter[1] = CHACHA_U8TOU32(fixed);
    ctx->nonce[1] = ctx->chacha.counter[2] = CHACHA_U8TOU32(fixed + 4);
    ctx->nonce[2] = ctx->chacha.counter[3] = CHACHA_U8TOU32(fixed + 8);
    return 1;
}

static int chacha20_poly1305_initkey(PROV_CIPHER_CTX *bctx,
                                     const unsigned char *key, size_t keylen)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;

    ctx->len.aad = 0;
    ctx->len.text = 0;
    ctx->aad = 0;
    ctx->mac_inited = 0;
    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    if (bctx->enc)
        return ossl_chacha20_einit(&ctx->chacha, key, keylen, NULL, 0, NULL);
    else
        return ossl_chacha20_dinit(&ctx->chacha, key, keylen, NULL, 0, NULL);
}

static int chacha20_poly1305_initiv(PROV_CIPHER_CTX *bctx)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;
    unsigned char tempiv[CHACHA_CTR_SIZE] = { 0 };
    int ret = 1;
    size_t noncelen = CHACHA20_POLY1305_IVLEN;

    ctx->len.aad = 0;
    ctx->len.text = 0;
    ctx->aad = 0;
    ctx->mac_inited = 0;
    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    /* pad on the left */
    memcpy(tempiv + CHACHA_CTR_SIZE - noncelen, bctx->oiv,
           noncelen);

    if (bctx->enc)
        ret = ossl_chacha20_einit(&ctx->chacha, NULL, 0,
                                  tempiv, sizeof(tempiv), NULL);
    else
        ret = ossl_chacha20_dinit(&ctx->chacha, NULL, 0,
                                  tempiv, sizeof(tempiv), NULL);
    ctx->nonce[0] = ctx->chacha.counter[1];
    ctx->nonce[1] = ctx->chacha.counter[2];
    ctx->nonce[2] = ctx->chacha.counter[3];
    bctx->iv_set = 1;
    return ret;
}

#if !defined(OPENSSL_SMALL_FOOTPRINT)

# if defined(POLY1305_ASM) && (defined(__x86_64) || defined(__x86_64__) \
     || defined(_M_AMD64) || defined(_M_X64))
#  define XOR128_HELPERS
void *xor128_encrypt_n_pad(void *out, const void *inp, void *otp, size_t len);
void *xor128_decrypt_n_pad(void *out, const void *inp, void *otp, size_t len);
static const unsigned char zero[4 * CHACHA_BLK_SIZE] = { 0 };
# else
static const unsigned char zero[2 * CHACHA_BLK_SIZE] = { 0 };
# endif

static int chacha20_poly1305_tls_cipher(PROV_CIPHER_CTX *bctx,
                                        unsigned char *out,
                                        size_t *out_padlen,
                                        const unsigned char *in, size_t len)
{
    printf("Encryption happens somwehre inside here!! -> chacha20_poly1035_tls_cipher\n");
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;
    POLY1305 *poly = &ctx->poly1305;
    size_t tail, tohash_len, buf_len, plen = ctx->tls_payload_length;
    unsigned char *buf, *tohash, *ctr, storage[sizeof(zero) + 32];

    DECLARE_IS_ENDIAN;

    buf = storage + ((0 - (size_t)storage) & 15);   /* align */
    ctr = buf + CHACHA_BLK_SIZE;
    tohash = buf + CHACHA_BLK_SIZE - POLY1305_BLOCK_SIZE;

# ifdef XOR128_HELPERS
    if (plen <= 3 * CHACHA_BLK_SIZE) {
        ctx->chacha.counter[0] = 0;
        buf_len = (plen + 2 * CHACHA_BLK_SIZE - 1) & (0 - CHACHA_BLK_SIZE);
        ChaCha20_ctr32(buf, zero, buf_len, ctx->chacha.key.d, ctx->chacha.counter);
        Poly1305_Init(poly, buf);
        ctx->chacha.partial_len = 0;
        memcpy(tohash, ctx->tls_aad, POLY1305_BLOCK_SIZE);
        tohash_len = POLY1305_BLOCK_SIZE;
        ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
        ctx->len.text = plen;

        if (plen) {
            if (bctx->enc)
                ctr = xor128_encrypt_n_pad(out, in, ctr, plen);
            else
                ctr = xor128_decrypt_n_pad(out, in, ctr, plen);

            in += plen;
            out += plen;
            tohash_len = (size_t)(ctr - tohash);
        }
    }
# else
    if (plen <= CHACHA_BLK_SIZE) {
        size_t i;

        ctx->chacha.counter[0] = 0;
        ChaCha20_ctr32(buf, zero, (buf_len = 2 * CHACHA_BLK_SIZE),
                       ctx->chacha.key.d, ctx->chacha.counter);
        Poly1305_Init(poly, buf);
        ctx->chacha.partial_len = 0;
        memcpy(tohash, ctx->tls_aad, POLY1305_BLOCK_SIZE);
        tohash_len = POLY1305_BLOCK_SIZE;
        ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
        ctx->len.text = plen;

        if (bctx->enc) {
            for (i = 0; i < plen; i++)
                out[i] = ctr[i] ^= in[i];
        } else {
            for (i = 0; i < plen; i++) {
                unsigned char c = in[i];

                out[i] = ctr[i] ^ c;
                ctr[i] = c;
            }
        }

        in += i;
        out += i;

        tail = (0 - i) & (POLY1305_BLOCK_SIZE - 1);
        memset(ctr + i, 0, tail);
        ctr += i + tail;
        tohash_len += i + tail;
    }
# endif
    else {
        ctx->chacha.counter[0] = 0;
        ChaCha20_ctr32(buf, zero, (buf_len = CHACHA_BLK_SIZE),
                       ctx->chacha.key.d, ctx->chacha.counter);
        Poly1305_Init(poly, buf);
        ctx->chacha.counter[0] = 1;
        ctx->chacha.partial_len = 0;
        Poly1305_Update(poly, ctx->tls_aad, POLY1305_BLOCK_SIZE);
        tohash = ctr;
        tohash_len = 0;
        ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
        ctx->len.text = plen;

        if (bctx->enc) {
            ChaCha20_ctr32(out, in, plen, ctx->chacha.key.d, ctx->chacha.counter);
            Poly1305_Update(poly, out, plen);
        } else {
            Poly1305_Update(poly, in, plen);
            ChaCha20_ctr32(out, in, plen, ctx->chacha.key.d, ctx->chacha.counter);
        }

        in += plen;
        out += plen;
        tail = (0 - plen) & (POLY1305_BLOCK_SIZE - 1);
        Poly1305_Update(poly, zero, tail);
    }

    if (IS_LITTLE_ENDIAN) {
        memcpy(ctr, (unsigned char *)&ctx->len, POLY1305_BLOCK_SIZE);
    } else {
        ctr[0]  = (unsigned char)(ctx->len.aad);
        ctr[1]  = (unsigned char)(ctx->len.aad>>8);
        ctr[2]  = (unsigned char)(ctx->len.aad>>16);
        ctr[3]  = (unsigned char)(ctx->len.aad>>24);
        ctr[4]  = (unsigned char)(ctx->len.aad>>32);
        ctr[5]  = (unsigned char)(ctx->len.aad>>40);
        ctr[6]  = (unsigned char)(ctx->len.aad>>48);
        ctr[7]  = (unsigned char)(ctx->len.aad>>56);

        ctr[8]  = (unsigned char)(ctx->len.text);
        ctr[9]  = (unsigned char)(ctx->len.text>>8);
        ctr[10] = (unsigned char)(ctx->len.text>>16);
        ctr[11] = (unsigned char)(ctx->len.text>>24);
        ctr[12] = (unsigned char)(ctx->len.text>>32);
        ctr[13] = (unsigned char)(ctx->len.text>>40);
        ctr[14] = (unsigned char)(ctx->len.text>>48);
        ctr[15] = (unsigned char)(ctx->len.text>>56);
    }
    tohash_len += POLY1305_BLOCK_SIZE;

    Poly1305_Update(poly, tohash, tohash_len);
    OPENSSL_cleanse(buf, buf_len);
    Poly1305_Final(poly, bctx->enc ? ctx->tag : tohash);

    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    if (bctx->enc) {
        memcpy(out, ctx->tag, POLY1305_BLOCK_SIZE);
    } else {
        if (CRYPTO_memcmp(tohash, in, POLY1305_BLOCK_SIZE)) {
            if (len > POLY1305_BLOCK_SIZE)
                memset(out - (len - POLY1305_BLOCK_SIZE), 0,
                       len - POLY1305_BLOCK_SIZE);
            return 0;
        }
        /* Strip the tag */
        len -= POLY1305_BLOCK_SIZE;
    }

    *out_padlen = len;
    return 1;
}
#else
static const unsigned char zero[CHACHA_BLK_SIZE] = { 0 };
#endif /* OPENSSL_SMALL_FOOTPRINT */

static int chacha20_poly1305_aead_cipher(PROV_CIPHER_CTX *bctx,
                                         unsigned char *out, size_t *outl,
                                         const unsigned char *in, size_t inl)
{
    printf("\nchacha20_poly1305_aead_cipher - File cipher_chacha20_poly1305_hw.c\n");
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)bctx;
    POLY1305 *poly = &ctx->poly1305;
    size_t rem, plen = ctx->tls_payload_length;
    size_t olen = 0;
    int rv = 0;

    DECLARE_IS_ENDIAN;

    if (!ctx->mac_inited) {
        if (plen != NO_TLS_PAYLOAD_LENGTH && out != NULL) {
            if (inl != plen + POLY1305_BLOCK_SIZE)
                return 0;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
            return chacha20_poly1305_tls_cipher(bctx, out, outl, in, inl);
#endif
        }

        ctx->chacha.counter[0] = 0;
        printf("\nChaCha20_ctr32\n");
        ChaCha20_ctr32(ctx->chacha.buf, zero, CHACHA_BLK_SIZE,
                       ctx->chacha.key.d, ctx->chacha.counter);
        Poly1305_Init(poly, ctx->chacha.buf);
        ctx->chacha.counter[0] = 1;
        ctx->chacha.partial_len = 0;
        ctx->len.aad = ctx->len.text = 0;
        ctx->mac_inited = 1;
        if (plen != NO_TLS_PAYLOAD_LENGTH) {
            Poly1305_Update(poly, ctx->tls_aad, EVP_AEAD_TLS1_AAD_LEN);
            ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
            ctx->aad = 1;
        }
    }
if (in != NULL) { /* aad or text */
    if (out == NULL) { /* aad */
        printf("\nPoly1305 update\n");
        Poly1305_Update(poly, in, inl);
        ctx->len.aad += inl;
        ctx->aad = 1;
        goto finish;
    } else { /* plain- or ciphertext */
        if (ctx->aad) { /* wrap up aad */
            if ((rem = (size_t)ctx->len.aad % POLY1305_BLOCK_SIZE))
                Poly1305_Update(poly, zero, POLY1305_BLOCK_SIZE - rem);
            ctx->aad = 0;
        }

        ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
        if (plen == NO_TLS_PAYLOAD_LENGTH)
            plen = inl;
        else if (inl != plen + POLY1305_BLOCK_SIZE)
            goto err;

        if (bctx->enc) { /* plaintext */
            printf("\nHere, the input is the plaintext, and we are going to encrypt.\n");
            printf("Plaintext: %.*s\n", plen, in);
            printf("\nAbout to encrypt....\n");
            /*ChaCha20_ctr32(out, in, plen, ctx->chacha.key.d, ctx->chacha.counter); Take this function as example of how chachapoly does things....*/
            entropic_encryption(in, out, plen, ctx->chacha.key.d, 256);
            printf("\nFinished entropic encryption\n");
            //ctx->chacha.base.hw->cipher(&ctx->chacha.base, out, in, plen); /*Where chacha encryption happens. This cipher is effectively locate3d at cipher_chacha20_hw.c, inside function chacha20_cipher*/
            Poly1305_Update(poly, out, plen);
            printf("\nEncryption finished...\n");
            printf("\nCiphertext: %.*s\n", plen, out);
            in += plen;
            out += plen;
            ctx->len.text += plen;
        } else { /* ciphertext */
            printf("\nHere, the input is the ciphertext, and we are going to decrypt.\n");
            printf("Ciphertext: %.*s\n", plen, in);
            printf("\nAbout to decrypt....\n");
            Poly1305_Update(poly, in, plen);
            /*ChaCha20_ctr32(out, in, plen, ctx->chacha.key.d, ctx->chacha.counter); Take this function as example of how chachapoly does things....*/
            //entropic_decryption(in, out, len, ctx->chacha.key.d, 128); // Will give error here.
            ctx->chacha.base.hw->cipher(&ctx->chacha.base, out, in, plen);// Will give error here.
            printf("\nDecryption finished....\n");
            printf("Plaintext: %.*s\n", plen, out);
            in += plen;
            out += plen;
            ctx->len.text += plen;
        }
    }
}

    /* explicit final, or tls mode */
    if (in == NULL || inl != plen) {

        unsigned char temp[POLY1305_BLOCK_SIZE];

        if (ctx->aad) {                        /* wrap up aad */
            if ((rem = (size_t)ctx->len.aad % POLY1305_BLOCK_SIZE))
                Poly1305_Update(poly, zero, POLY1305_BLOCK_SIZE - rem);
            ctx->aad = 0;
        }

        if ((rem = (size_t)ctx->len.text % POLY1305_BLOCK_SIZE))
            Poly1305_Update(poly, zero, POLY1305_BLOCK_SIZE - rem);

        if (IS_LITTLE_ENDIAN) {
            Poly1305_Update(poly, (unsigned char *)&ctx->len,
                            POLY1305_BLOCK_SIZE);
        } else {
            printf("\nLogs here to check 1\n");
            temp[0]  = (unsigned char)(ctx->len.aad);
            temp[1]  = (unsigned char)(ctx->len.aad>>8);
            temp[2]  = (unsigned char)(ctx->len.aad>>16);
            temp[3]  = (unsigned char)(ctx->len.aad>>24);
            temp[4]  = (unsigned char)(ctx->len.aad>>32);
            temp[5]  = (unsigned char)(ctx->len.aad>>40);
            temp[6]  = (unsigned char)(ctx->len.aad>>48);
            temp[7]  = (unsigned char)(ctx->len.aad>>56);
            temp[8]  = (unsigned char)(ctx->len.text);
            temp[9]  = (unsigned char)(ctx->len.text>>8);
            temp[10] = (unsigned char)(ctx->len.text>>16);
            temp[11] = (unsigned char)(ctx->len.text>>24);
            temp[12] = (unsigned char)(ctx->len.text>>32);
            temp[13] = (unsigned char)(ctx->len.text>>40);
            temp[14] = (unsigned char)(ctx->len.text>>48);
            temp[15] = (unsigned char)(ctx->len.text>>56);
            Poly1305_Update(poly, temp, POLY1305_BLOCK_SIZE);
        }
        Poly1305_Final(poly, bctx->enc ? ctx->tag : temp);
        ctx->mac_inited = 0;

        if (in != NULL && inl != plen) {
            if (bctx->enc) {
                memcpy(out, ctx->tag, POLY1305_BLOCK_SIZE);
            } else {
                if (CRYPTO_memcmp(temp, in, POLY1305_BLOCK_SIZE)) {
                    memset(out - plen, 0, plen);
                    goto err;
                }
                /* Strip the tag */
                inl -= POLY1305_BLOCK_SIZE;
            }
        }
        else if (!bctx->enc) {
            if (CRYPTO_memcmp(temp, ctx->tag, ctx->tag_len))
                goto err;
        }
    }
finish:
    olen = inl;
    rv = 1;
err:
    *outl = olen;
    return rv;
}

static const PROV_CIPHER_HW_CHACHA20_POLY1305 chacha20poly1305_hw = {
    { chacha20_poly1305_initkey, NULL },
    chacha20_poly1305_aead_cipher,
    chacha20_poly1305_initiv,
    chacha_poly1305_tls_init,
    chacha_poly1305_tls_iv_set_fixed
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_chacha20_poly1305(size_t keybits)
{
    return (PROV_CIPHER_HW *)&chacha20poly1305_hw;
}

/*EVERYTHING NEEDED FOR ENTROPIC ENCRYPTION*/

void random_bytes_(uint64_t * p, uint64_t n){
    srand(time(NULL));
    for(unsigned i=0;i<n;i++){ 
        p[i] = rand(); 
        //printf("in Helper|random_bytes()|                      p[%d]:%0lx \n",i, p[i]);
        p[i]<<=32; 
        //printf("in Helper|random_bytes()| After shifting:      p[%d]:%0lx \n",i, p[i]);
        p[i] |= rand(); 
        //printf("in Helper|random_bytes()| After the last step: p[%d]:%0lx\n",i, p[i]);

        
    }
}

void xor_bytes( uint64_t * p1 , const uint64_t * p2 , unsigned n ) { 
    for(unsigned i=0;i<n;i++) p1[i]^= p2[i]; 
}

/**
 * extract_bits (example with uint16_t, each value written in BIG ENDIAN):
 *   array: 1010101010101010, 1010101010101010 // a0, a1
 *                      ^
 *                      |
 *                    off=4
 * ret=     [    LO    ]                  [HI]
 *   array: 1010101010101010, 1010101010101010
 */
 uint64_t extract_bits_scalars(int off, uint64_t a0, uint64_t a1) {
  assert(off >= 0 && off < 64);
  uint64_t lo = a0 >> off;
  uint64_t hi;
  if(off == 0) {
    hi = 0; // avoid bitshifting by 64;
    // UB: https://stackoverflow.com/questions/9429156/by-left-shifting-can-a-number-be-set-to-zero
  }
  else {
    hi = a1 << (64 - off); // high bits are implicitly lost; low bits are set to zero.
  }
  return lo | hi;
}

 uint64_t extract_bits(uint64_t off, const uint64_t *bits) {
  return extract_bits_scalars((int)(off % 64), bits[off / 64], bits[off / 64 + 1]);
}

 uint64_t ceil_div(uint64_t num, uint64_t den) {
  return (num + den - 1ULL) / den;
}

/// @return greatest value less or equal to `x` multiple of `align`.
 int64_t prev_align(int64_t x, int64_t align) {
  return (x / align) * align;
}

 bool get_bit_scalar(uint64_t bits, int i) {
  return bits & (1ULL << i);
}

 bool get_bit(const uint64_t* bits, uint64_t i) {
  return get_bit_scalar(bits[i / 64], (int)(i % 64ULL));
}

 uint64_t set_bit_scalar(uint64_t bits, int i, bool flag) {
  if(flag) {
    return bits | (1ULL << i);
  }
  else {
    return bits & ~(1ULL << i);
  }
}

 void set_bit(uint64_t* bits, uint64_t i, bool flag) {
  bits[i / 64] = set_bit_scalar(bits[i / 64], (int)(i % 64ULL), flag);
}

/**
 * Pseudo-code if indexing is bit-based:
 * ```
 * out[i] = in_a[a] ^ in_b[b]
 * ```
 */
 void xor_single(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b,
			 int64_t i, int64_t a, int64_t b)
{
    bool op1 = get_bit(in_a, a);
    bool op2 = get_bit(in_b, b);
    set_bit(out, i, op1 ^ op2);
}

/**
 * 3-operands version.
 * Pseudo-code if indexing is bit-based:
 * ```
 * out[i] = in_a[a] ^ in_b[b] ^ inc_c[c]
 * ```
 */
 void xor3_single(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b, const uint64_t *in_c,
			 int64_t i, int64_t a, int64_t b, int64_t c)
{
    bool op1 = get_bit(in_a, a);
    bool op2 = get_bit(in_b, b);
    bool op3 = get_bit(in_c, c);
    set_bit(out, i, op1 ^ op2 ^ op3);
}

/**
 * Pseudo-code if indexing is bit-based:
 * ```
 * for(i = i_begin; i < i_end; i++)
 *   out[i] = in_a[a+i] ^ in_b[b+i]
 * ```
 */
 void xor_range_v1(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b,
			 int64_t i_begin, int64_t i_end, int64_t a, int64_t b) {

  for(int64_t i = i_begin; i < i_end; i++) {
    bool op1 = get_bit(in_a, i + a);
    bool op2 = get_bit(in_b, i + b);
    set_bit(out, i, op1 ^ op2);
  }
}

/**
 * 3-operands version.
 * Pseudo-code if indexing is bit-based:
 * ```
 * for(i = i_begin; i < i_end; i++)
 *   out[i] = in_a[a+i] ^ in_b[b+i] ^ in_c[c+i]
 * ```
 */
 void xor3_range_v1(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b, const uint64_t* in_c,
			 int64_t i_begin, int64_t i_end, int64_t a, int64_t b, int64_t c) {

  for(int64_t i = i_begin; i < i_end; i++) {
    bool op1 = get_bit(in_a, i + a);
    bool op2 = get_bit(in_b, i + b);
    bool op3 = get_bit(in_c, i + c);
    set_bit(out, i, op1 ^ op2 ^ op3);
  }
}

/**
 * @param out The array of bits where to store the result `a ^ b`.
 * @param in_a Array of bits for first operand.
 * @param in_b Array of bits for second operand.
 * @param i_begin Index of first bit to set in `out`.
 * @param i_end Index after the last bit to set in `out`.
 * @param a Index of first bit in `in_a`.
 * @param b Index of first bit in `in_b`.
 * 
 * Pseudo-code if indexing is bit-based:
 * ```
 * for(i = i_begin; i < i_end; i++)
 *   out[i] = in_a[a+i] ^ in_b[b+i]
 * ```
 */
 void xor_range_v2(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b,
			 int64_t i_begin, int64_t i_end, int64_t a, int64_t b) {
  // Since we process first and last item separately if non-aligned,
  // tha data should span across 2 uint64_t minimum (or a single aligned uint64_t).
  assert(i_end - i_begin >= 64);
  // process first output separately, not aligned
  if(i_begin % 64 != 0) {
    int64_t i = i_begin;
    uint64_t sz = (i_begin % 64ULL);
    uint64_t sz_mask = ((1ULL << sz) - 1ULL);
    uint64_t sz_antimask = ((1ULL << (64ULL - sz)) - 1ULL);
    uint64_t op1 = extract_bits(i + a, in_a) & sz_antimask; // First output is smaller
    uint64_t op2 = extract_bits(i + b, in_b) & sz_antimask;
    uint64_t lo = out[i / 64] & sz_mask;
    out[i / 64] = lo | ((op1 ^ op2) << sz); // Keep only the highest bits: don't modify before `i_begin`
    i_begin = prev_align(i, 64) + 64;
  }
omp_set_num_threads(12);
#pragma omp parallel
{
    #pragma omp for //private() schedule()
  for(int64_t i = i_begin; i < prev_align(i_end, 64); i += 64) {
    uint64_t op1 = extract_bits(i + a, in_a);
    uint64_t op2 = extract_bits(i + b, in_b);
    out[i / 64] = op1 ^ op2;
  }
}
  
  // process last output separately, not aligned
  if(i_end % 64 != 0) {
    int64_t i = prev_align(i_end, 64);
    uint64_t sz = (i_end % 64ULL);
    uint64_t sz_mask = ((1ULL << sz) - 1ULL);
    uint64_t sz_antimask = ~sz_mask;
    uint64_t op1 = extract_bits(i + a, in_a) & sz_mask; // First output is smaller
    uint64_t op2 = extract_bits(i + b, in_b) & sz_mask;
    uint64_t hi = out[i / 64] & sz_antimask;
    out[i / 64] = hi | (op1 ^ op2); // Keep only the lowest bits: don't modify after `i_end`
  }
}

/**
 * 3-operands version.
 * Pseudo-code if indexing is bit-based:
 * ```
 * for(i = i_begin; i < i_end; i++)
 *   out[i] = in_a[a+i] ^ in_b[b+i] ^ in_c[c+i]
 * ```
 */
 void xor3_range_v2(uint64_t *out, const uint64_t *in_a, const uint64_t *in_b, const uint64_t *in_c,
			 int64_t i_begin, int64_t i_end, int64_t a, int64_t b, int64_t c) {
  assert(i_end - i_begin >= 64);
  // process first output separately, not aligned
  if(i_begin % 64 != 0) {
    int64_t i = i_begin;
    uint64_t sz = (i_begin % 64ULL);
    uint64_t sz_mask = ((1ULL << sz) - 1ULL);
    uint64_t sz_antimask = ((1ULL << (64ULL - sz)) - 1ULL);
    uint64_t op1 = extract_bits(i + a, in_a) & sz_antimask; // First output is smaller
    uint64_t op2 = extract_bits(i + b, in_b) & sz_antimask;
    uint64_t op3 = extract_bits(i + c, in_c) & sz_antimask;
    uint64_t lo = out[i / 64] & sz_mask;
    out[i / 64] = lo | ((op1 ^ op2 ^ op3) << sz); // Keep only the highest bits: don't modify before `i_begin`
    i_begin = prev_align(i, 64) + 64;
  }
omp_set_num_threads(12);
#pragma omp parallel
{
    #pragma omp for
  for(int64_t i = i_begin; i < prev_align(i_end, 64); i += 64) {
    uint64_t op1 = extract_bits(i + a, in_a);
    uint64_t op2 = extract_bits(i + b, in_b);
    uint64_t op3 = extract_bits(i + c, in_c);
    out[i / 64] = op1 ^ op2 ^ op3;
  }
}
  
  // process last output separately, not aligned
  if(i_end % 64 != 0) {
    int64_t i = prev_align(i_end, 64);
    uint64_t sz = (i_end % 64ULL);
    uint64_t sz_mask = ((1ULL << sz) - 1ULL);
    uint64_t sz_antimask = ~sz_mask;
    uint64_t op1 = extract_bits(i + a, in_a) & sz_mask; // First output is smaller
    uint64_t op2 = extract_bits(i + b, in_b) & sz_mask;
    uint64_t op3 = extract_bits(i + c, in_c) & sz_mask;
    uint64_t hi = out[i / 64] & sz_antimask;
    out[i / 64] = hi | (op1 ^ op2 ^ op3); // Keep only the lowest bits: don't modify after `i_end`
  }
}

#define xor3_range_select(version, ...) do { \
  if(version == 1) { \
    xor3_range_v1(__VA_ARGS__); \
  } \
  else if(version == 2) { \
    xor3_range_v2(__VA_ARGS__); \
  } \
} while(0)


#define xor_range_select(version, ...) do { \
  if(version == 1) { \
    xor_range_v1(__VA_ARGS__); \
  } \
  else if(version == 2) { \
    xor_range_v2(__VA_ARGS__); \
  } \
} while(0)




void reduction_c1_seq(uint64_t *d, uint64_t *Dred, uint64_t lenR_64, uint64_t lenR, uint64_t lenDred_64, uint64_t b) {

    unsigned lenT1_64 = (b - 1 + 63)/64;
    unsigned lenT4_64 = (b + 63)/64;
    //printf("lenT1_64: %u, lenT4_64: %u \n", lenT1_64, lenT4_64);

    uint64_t * T1 = (uint64_t*)aligned_alloc( 32, sizeof(uint64_t)*lenT1_64);
	if( NULL == T1 ) { printf("reduction_c1 |alloc T1 fail.\n"); exit(-1); }
	uint64_t * T4 = (uint64_t*)aligned_alloc( 32, sizeof(uint64_t)*lenT4_64);
	if( NULL == T4 ) { printf("Main |alloc T4 fail.\n"); exit(-1); }

    memset(T1, 0, sizeof(uint64_t) * lenT1_64);
    memset(T4, 0, sizeof(uint64_t) * lenT4_64);
	

    uint64_t XOR = 0; 
    uint64_t XOR_Result = 0;


    // Calculate T1 and T4
    for (uint64_t i= 0; i < b - 1; i++) {
        //printf("i + 2 * b + 1:%d \n", i + 2 * b + 1);
        //printf("INDEX_64(i + 2 * b + 1, lenR_64):%d \n", INDEX_64(i + 2 * b + 1, lenR_64));

        //printf("i + 3 * b + 2:%d \n", i + 3 * b + 2);
        //printf("INDEX_64(i + 3 * b + 2, lenR_64):%d \n", INDEX_64(i + 3 * b + 2, lenR_64));

        if(i + 2 * b + 1 >= lenR || i + 3 * b + 2 >= lenR) break;
        
        //T1[i] = d[i + 2 * b + 1] ^ d[i + 3 * b + 2];
        XOR_Result =    SHIFT_BACK((d[INDEX_64(i + 2 * b + 1, lenR_64)]     & MASK_ONE(INDEX_I(i + 2 * b + 1))), INDEX_I(i + 2 * b + 1)) ^ 
                        SHIFT_BACK((d[INDEX_64(i + 3 * b + 2, lenR_64)] & MASK_ONE(INDEX_I(i + 3 * b + 2 ))),INDEX_I(i + 3 * b + 2)) ;

        //printf("T1[INDEX_64(i, lenT1_64)]:%lu \n", T1[INDEX_64(i, lenT1_64)]);

        if (XOR_Result == 1) {
            T1[INDEX_64(i, lenT1_64)] |= MASK_ONE(INDEX_I(i));
        }
        else {
            T1[INDEX_64(i, lenT1_64)] &= ~(MASK_ONE(INDEX_I(i)));
            ////printf("~(1<<INDEX_I(i)):%lu \n", ~(MASK_ONE(INDEX_I(i))));
        }
    }
    for (uint64_t i = 0; i < b; i++) {
        //printf("\n 2nd Loop\n");
        //printf("i + 2 * b + 1:%d \n", i + 2 * b + 1);
        //printf("INDEX_64(i + 2 * b + 1, lenR_64):%d \n", INDEX_64(i + 2 * b + 1, lenR_64));

        //printf("i + 3 * b + 1:%d \n", i + 3 * b + 1);
        //printf("INDEX_64(i + 3 * b + 1, lenR_64):%d \n", INDEX_64(i + 3 * b + 1, lenR_64));

        if(i + 2 * b + 1 >= lenR || i + 3 * b + 1 >= lenR) break;

        //T4[i] = d[i + 2 * b + 1] ^ d[i + 3 * b + 1];
        XOR_Result =    SHIFT_BACK((d[INDEX_64(i + 2 * b + 1, lenR_64)]     & MASK_ONE(INDEX_I(i + 2 * b + 1))), INDEX_I(i + 2 * b + 1)) ^ 
                        SHIFT_BACK((d[INDEX_64(i + 3 * b + 1, lenR_64)] & MASK_ONE(INDEX_I(i + 3 * b + 1))),INDEX_I(i + 3 * b + 1)) ;

        //printf("T4[INDEX_64(i, lenT4_64)]:%lu \n", T1[INDEX_64(i, lenT4_64)]);

        if (XOR_Result == 1) {
            T4[INDEX_64(i, lenT4_64)] |= MASK_ONE(INDEX_I(i));
        }
        else {
            T4[INDEX_64(i, lenT4_64)] &= ~(MASK_ONE(INDEX_I(i)));
            ////printf("~(1<<INDEX_I(i)):%lu \n", ~(MASK_ONE(INDEX_I(i))));
        }
    }
    
    if(3 * b + 1 < lenR){
        //printf("\n1st Outer assignment\n");
        // Calculate Dred
        //Dred[0] = d[0] ^ T1[0] ^ d[3 * b + 1];
        XOR =   SHIFT_BACK((d[INDEX_64(0, lenR_64)]         & MASK_ONE(INDEX_I(0))), INDEX_I(0)) ^
                SHIFT_BACK((T1[INDEX_64(0, lenT1_64)]      & MASK_ONE(INDEX_I(0))),INDEX_I(0)) ^
                SHIFT_BACK((d[INDEX_64(3 * b + 1, lenR_64)]     & MASK_ONE(INDEX_I(3 * b + 1))), INDEX_I(3 * b + 1 ));
        if (XOR == 1) {
            Dred[INDEX_64(0, lenDred_64)] |= MASK_ONE(INDEX_I(0));
        }
        else {
            Dred[INDEX_64(0, lenDred_64)] &= ~(MASK_ONE(INDEX_I(0)));
        }
    }
    
    for (uint64_t i = 1; i < b - 1; i++) {
        //printf("\n 3rd Loop\n");
        //printf("i :%d \n", i );
        //printf("INDEX_64(i, lenR_64):%d \n", INDEX_64(i, lenR_64));

        //printf("i -1:%d \n", i-1);
        //printf("INDEX_64(i -1, lenT4_64):%d \n", INDEX_64(i -1, lenT4_64));

    
        //Dred[i] = d[i] ^ T1[i] ^ T4[i - 1];
        XOR_Result =    SHIFT_BACK((d[INDEX_64(i, lenR_64)]      & MASK_ONE(INDEX_I(i))), INDEX_I(i)) ^
                        SHIFT_BACK((T1[INDEX_64(i, lenT1_64)]     & MASK_ONE(INDEX_I(i))),INDEX_I(i)) ^
                        SHIFT_BACK((T4[INDEX_64(i - 1, lenT4_64)] & MASK_ONE(INDEX_I(i - 1))),INDEX_I(i - 1));
        if (XOR_Result == 1) {
            Dred[INDEX_64(i, lenDred_64)] |= MASK_ONE(INDEX_I(i));
        }
        else {
            Dred[INDEX_64(i, lenDred_64)] &= ~(MASK_ONE(INDEX_I(i)));
        }
    }

    if(3 * b < lenR){
        //printf("\n2nd Outer assignment\n");
        //Dred[b - 1] = d[b - 1] ^ d[3 * b] ^ T4[b - 2];
        XOR =   SHIFT_BACK((d[INDEX_64(b - 1, lenR_64)]   & MASK_ONE(INDEX_I(b - 1))), INDEX_I(b - 1)) ^
                SHIFT_BACK((d[INDEX_64(3 * b, lenR_64)]   & MASK_ONE(INDEX_I(3 * b))), INDEX_I(3 * b))^
                SHIFT_BACK((T4[INDEX_64(b - 2, lenT4_64)]  & MASK_ONE(INDEX_I(b - 2))),INDEX_I(b - 2)) ;
        if (XOR == 1) {
            Dred[INDEX_64(b - 1, lenDred_64)] |= MASK_ONE(INDEX_I(b - 1));
        }
        else {
            Dred[INDEX_64(b - 1, lenDred_64)] &= ~(MASK_ONE(INDEX_I(b - 1)));
        }
    }

    //printf("\n3rd Outer assignment\n");
    //Dred[b] = d[b] ^ T1[0] ^ T4[b - 1];
    XOR =   SHIFT_BACK((d[INDEX_64(b, lenR_64)]       & MASK_ONE(INDEX_I(b))), INDEX_I(b)) ^
            SHIFT_BACK((T1[INDEX_64(0, lenT1_64)]      & MASK_ONE(INDEX_I(0))), INDEX_I(0))^
            SHIFT_BACK((T4[INDEX_64(b - 1, lenT4_64)]  & MASK_ONE(INDEX_I(b - 1))),INDEX_I(b - 1)) ;
    if (XOR == 1) {
        Dred[INDEX_64(b, lenDred_64)] |= MASK_ONE(INDEX_I(b));
    }
    else {
        Dred[INDEX_64(b, lenDred_64)] &= ~(MASK_ONE(INDEX_I(b)));
    }

    for (uint64_t i = b + 1; i < 2 * b - 1; i++) {
        //printf("\n 4th Loop\n");
        //printf("i - b:%d \n", i );
        //printf("INDEX_64(i - b, lenR_64):%d \n", INDEX_64(i - b, lenT1_64));

        //printf("i - b - 1:%d \n", i-1);
        //printf("INDEX_64(i - b - 1, lenT4_64):%d \n", INDEX_64(i - b - 1, lenT4_64));


        //Dred[i] = d[i] ^ T1[i - b] ^ T1[i - b - 1];
        XOR_Result =    SHIFT_BACK((d[INDEX_64(i, lenR_64)]      & MASK_ONE(INDEX_I(i))), INDEX_I(i)) ^
                        SHIFT_BACK((T1[INDEX_64(i - b, lenT1_64)] & MASK_ONE(INDEX_I(i - b))),INDEX_I(i - b)) ^
                        SHIFT_BACK((T1[INDEX_64(i - b - 1, lenT1_64)] & MASK_ONE(INDEX_I(i - b - 1))),INDEX_I(i - b - 1));
        if (XOR_Result == 1) {
            Dred[INDEX_64(i, lenDred_64)] |= MASK_ONE(INDEX_I(i));
        }
        else {
            Dred[INDEX_64(i, lenDred_64)] &= ~(MASK_ONE(INDEX_I(i)));
        }
    }
    if(3 * b < lenR){
        //printf("\n4th Outer assignment\n");
        //Dred[2 * b - 1] = d[2 * b - 1] ^ d[3 * b] ^ T1[b - 2];
        XOR =   SHIFT_BACK((d[INDEX_64(2 * b - 1, lenR_64)]   & MASK_ONE(INDEX_I(2 * b - 1))), INDEX_I(2 * b - 1)) ^
                SHIFT_BACK((d[INDEX_64(3 * b, lenR_64)]   & MASK_ONE(INDEX_I(3 * b))), INDEX_I(3 * b))^
                SHIFT_BACK((T1[INDEX_64(b - 2, lenT1_64)]  & MASK_ONE(INDEX_I(b - 2))),INDEX_I(b - 2)) ;
        if (XOR == 1) {
            //printf("2 * b-1:%d Dred[INDEX_64(2 * b-1, lenDred_64)]:%lu\n",2 * b-1, Dred[INDEX_64(2 * b-1, lenDred_64)]);
            Dred[INDEX_64(2 * b - 1, lenDred_64)] |= MASK_ONE(INDEX_I(2 * b - 1));
            //printf("2 * b-1:%d Dred[INDEX_64(2 * b-1, lenDred_64)]:%lu\n",2 * b-1, Dred[INDEX_64(2 * b-1, lenDred_64)]);
        }
        else {
            Dred[INDEX_64(2 * b - 1, lenDred_64)] &= ~(MASK_ONE(INDEX_I(2 * b - 1)));
        }
    }
    if((3 * b + 1 < lenR) &  (3 * b < lenR)){
        //printf("\n5th Outer assignment\n");
        //Dred[2 * b] = d[2 * b] ^ d[3 * b + 1] ^ d[3 * b];
        XOR =   SHIFT_BACK((d[INDEX_64(2 * b, lenR_64)]   & MASK_ONE(INDEX_I(2 * b))), INDEX_I(2 * b)) ^
                SHIFT_BACK((d[INDEX_64(3 * b + 1, lenR_64)]   & MASK_ONE(INDEX_I(3 * b + 1))), INDEX_I(3 * b + 1))^
                SHIFT_BACK((d[INDEX_64(3 * b, lenR_64)]   & MASK_ONE(INDEX_I(3 * b))), INDEX_I(3 * b));
        if (XOR == 1) {
            Dred[INDEX_64(2 * b, lenDred_64)] |= MASK_ONE(INDEX_I(2 * b));
            
        }
        else {
            //printf("2 * b:%d Dred[INDEX_64(2 * b, lenDred_64)]:%lu\n",2 * b, Dred[INDEX_64(2 * b, lenDred_64)]);
            Dred[INDEX_64(2 * b, lenDred_64)] &= ~(MASK_ONE(INDEX_I(2 * b)));
            //printf("5th Outer assignment\n");
            //printf("2 * b:%d Dred[INDEX_64(2 * b, lenDred_64)]:%lu\n",2 * b, Dred[INDEX_64(2 * b, lenDred_64)]);
        }
    }
    /*
    for (unsigned i = 0; i < lenDred_64; i++) {
        printf("Dred[%d]: %lu \n", i, Dred[i]);
        ////printf("T[%d]: %lu \n", i, T[i]);
    }
    */
    free(T1);
    free(T4);

}

// Reduction when c =1
void reduction_c1_par(uint64_t *d, uint64_t *Dred, uint64_t lenR_64, uint64_t lenR, uint64_t lenDred_64, uint64_t b) {

    unsigned lenT1_64 = (b - 1 + 63)/64;
    unsigned lenT4_64 = (b + 63)/64;
    //printf("lenT1_64: %u, lenT4_64: %u \n", lenT1_64, lenT4_64);

    uint64_t * T1 = (uint64_t*)aligned_alloc( 32, sizeof(uint64_t)*lenT1_64);
	if( NULL == T1 ) { printf("reduction_c1 |alloc T1 fail.\n"); exit(-1); }
	uint64_t * T4 = (uint64_t*)aligned_alloc( 32, sizeof(uint64_t)*lenT4_64);
	if( NULL == T4 ) { printf("Main |alloc T4 fail.\n"); exit(-1); }
    
    memset(T1, 0, sizeof(uint64_t) * lenT1_64);
    memset(T4, 0, sizeof(uint64_t) * lenT4_64);


    omp_set_num_threads(12);

    uint64_t XOR = 0; 
    uint64_t XOR_Result = 0;

    
#pragma omp parallel
{
    #pragma omp for private(XOR_Result) schedule(static, 64)
    for (uint64_t i = 0; i < b - 1; i++) {
        //printf("\n 1st Loop\n");
        //printf("i + 2 * b + 1:%d \n", i + 2 * b + 1);
        //printf("INDEX_64(i + 2 * b + 1, lenR_64):%d \n", INDEX_64(i + 2 * b + 1, lenR_64));

        //printf("i + 3 * b + 2:%d \n", i + 3 * b + 2);
        //printf("INDEX_64(i + 3 * b + 2, lenR_64):%d \n", INDEX_64(i + 3 * b + 2, lenR_64));
        
        if(i + 2 * b + 1 >= lenR || i + 3 * b + 2 >= lenR) continue;
        
        //T1[i] = d[i + 2 * b + 1] ^ d[i + 3 * b + 2];
        XOR_Result =    SHIFT_BACK((d[INDEX_64(i + 2 * b + 1, lenR_64)]     & MASK_ONE(INDEX_I(i + 2 * b + 1))), INDEX_I(i + 2 * b + 1)) ^ 
                        SHIFT_BACK((d[INDEX_64(i + 3 * b + 2, lenR_64)] & MASK_ONE(INDEX_I(i + 3 * b + 2 ))),INDEX_I(i + 3 * b + 2)) ;

        //printf("T1[INDEX_64(i, lenT1_64)]:%lu \n", T1[INDEX_64(i, lenT1_64)]);

        if (XOR_Result == 1) {
            T1[INDEX_64(i, lenT1_64)] |= MASK_ONE(INDEX_I(i));
        }
        else {
            T1[INDEX_64(i, lenT1_64)] &= ~(MASK_ONE(INDEX_I(i)));
            ////printf("~(1<<INDEX_I(i)):%lu \n", ~(MASK_ONE(INDEX_I(i))));
        }
        
    }
    #pragma omp for private(XOR_Result) schedule(static, 64)
    for (uint64_t i = 0; i < b; i++) {
        //printf("\n 2nd Loop\n");
        //printf("i + 2 * b + 1:%d \n", i + 2 * b + 1);
        //printf("INDEX_64(i + 2 * b + 1, lenR_64):%d \n", INDEX_64(i + 2 * b + 1, lenR_64));

        //printf("i + 3 * b + 1:%d \n", i + 3 * b + 1);
        //printf("INDEX_64(i + 3 * b + 1, lenR_64):%d \n", INDEX_64(i + 3 * b + 1, lenR_64));

        if(i + 2 * b + 1 >= lenR || i + 3 * b + 1 >= lenR) continue;

        //T4[i] = d[i + 2 * b + 1] ^ d[i + 3 * b + 1];
        XOR_Result =    SHIFT_BACK((d[INDEX_64(i + 2 * b + 1, lenR_64)]     & MASK_ONE(INDEX_I(i + 2 * b + 1))), INDEX_I(i + 2 * b + 1)) ^ 
                        SHIFT_BACK((d[INDEX_64(i + 3 * b + 1, lenR_64)] & MASK_ONE(INDEX_I(i + 3 * b + 1))),INDEX_I(i + 3 * b + 1)) ;

        //printf("T4[INDEX_64(i, lenT4_64)]:%lu \n", T1[INDEX_64(i, lenT4_64)]);

        if (XOR_Result == 1) {
            T4[INDEX_64(i, lenT4_64)] |= MASK_ONE(INDEX_I(i));
        }
        else {
            T4[INDEX_64(i, lenT4_64)] &= ~(MASK_ONE(INDEX_I(i)));
            ////printf("~(1<<INDEX_I(i)):%lu \n", ~(MASK_ONE(INDEX_I(i))));
        }
    }
}

    if(3 * b + 1 < lenR){
        //printf("\n1st Outer assignment\n");
        // Calculate Dred
        //Dred[0] = d[0] ^ T1[0] ^ d[3 * b + 1];
        XOR =   SHIFT_BACK((d[INDEX_64(0, lenR_64)]         & MASK_ONE(INDEX_I(0))), INDEX_I(0)) ^
                SHIFT_BACK((T1[INDEX_64(0, lenT1_64)]      & MASK_ONE(INDEX_I(0))),INDEX_I(0)) ^
                SHIFT_BACK((d[INDEX_64(3 * b + 1, lenR_64)]     & MASK_ONE(INDEX_I(3 * b + 1))), INDEX_I(3 * b + 1 ));
        if (XOR == 1) {
            Dred[INDEX_64(0, lenDred_64)] |= MASK_ONE(INDEX_I(0));
        }
        else {
            Dred[INDEX_64(0, lenDred_64)] &= ~(MASK_ONE(INDEX_I(0)));
        }
    }
#pragma omp parallel
{
    #pragma omp for private(XOR_Result) schedule(static, 64)
    for (uint64_t i = 0; i < b - 1; i++) {
        //printf("\n 3rd Loop\n");
        //printf("i :%d \n", i );
        //printf("INDEX_64(i, lenR_64):%d \n", INDEX_64(i, lenR_64));

        //printf("i -1:%d \n", i-1);
        //printf("INDEX_64(i -1, lenT4_64):%d \n", INDEX_64(i -1, lenT4_64));

        if(i == 0) continue;
        //Dred[i] = d[i] ^ T1[i] ^ T4[i - 1];
        XOR_Result =    SHIFT_BACK((d[INDEX_64(i, lenR_64)]      & MASK_ONE(INDEX_I(i))), INDEX_I(i)) ^
                        SHIFT_BACK((T1[INDEX_64(i, lenT1_64)]     & MASK_ONE(INDEX_I(i))),INDEX_I(i)) ^
                        SHIFT_BACK((T4[INDEX_64(i - 1, lenT4_64)] & MASK_ONE(INDEX_I(i - 1))),INDEX_I(i - 1));
        if (XOR_Result == 1) {
            Dred[INDEX_64(i, lenDred_64)] |= MASK_ONE(INDEX_I(i));
        }
        else {
            Dred[INDEX_64(i, lenDred_64)] &= ~(MASK_ONE(INDEX_I(i)));
        }
    }
}

    if(3 * b < lenR){
        //printf("\n2nd Outer assignment\n");
        //Dred[b - 1] = d[b - 1] ^ d[3 * b] ^ T4[b - 2];
        XOR =   SHIFT_BACK((d[INDEX_64(b - 1, lenR_64)]   & MASK_ONE(INDEX_I(b - 1))), INDEX_I(b - 1)) ^
                SHIFT_BACK((d[INDEX_64(3 * b, lenR_64)]   & MASK_ONE(INDEX_I(3 * b))), INDEX_I(3 * b))^
                SHIFT_BACK((T4[INDEX_64(b - 2, lenT4_64)]  & MASK_ONE(INDEX_I(b - 2))),INDEX_I(b - 2)) ;
        if (XOR == 1) {
            Dred[INDEX_64(b - 1, lenDred_64)] |= MASK_ONE(INDEX_I(b - 1));
        }
        else {
            Dred[INDEX_64(b - 1, lenDred_64)] &= ~(MASK_ONE(INDEX_I(b - 1)));
        }
    }

    //printf("\n3rd Outer assignment\n");
    //Dred[b] = d[b] ^ T1[0] ^ T4[b - 1];
    XOR =   SHIFT_BACK((d[INDEX_64(b, lenR_64)]       & MASK_ONE(INDEX_I(b))), INDEX_I(b)) ^
            SHIFT_BACK((T1[INDEX_64(0, lenT1_64)]      & MASK_ONE(INDEX_I(0))), INDEX_I(0))^
            SHIFT_BACK((T4[INDEX_64(b - 1, lenT4_64)]  & MASK_ONE(INDEX_I(b - 1))),INDEX_I(b - 1)) ;
    if (XOR == 1) {
        Dred[INDEX_64(b, lenDred_64)] |= MASK_ONE(INDEX_I(b));
    }
    else {
        Dred[INDEX_64(b, lenDred_64)] &= ~(MASK_ONE(INDEX_I(b)));
    }
#pragma omp parallel
{
    #pragma omp for firstprivate(XOR_Result) schedule(static, 64)
    for (uint64_t i = 0; i < 2 * b - 1; i++) {
        //printf("\n 4th Loop\n");
        //printf("i - b:%d \n", i );
        //printf("INDEX_64(i - b, lenR_64):%d \n", INDEX_64(i - b, lenT1_64));

        //printf("i - b - 1:%d \n", i-1);
        //printf("INDEX_64(i - b - 1, lenT4_64):%d \n", INDEX_64(i - b - 1, lenT4_64));

        if(i < b + 1) continue;
        //Dred[i] = d[i] ^ T1[i - b] ^ T1[i - b - 1];
        XOR_Result =    SHIFT_BACK((d[INDEX_64(i, lenR_64)]      & MASK_ONE(INDEX_I(i))), INDEX_I(i)) ^
                        SHIFT_BACK((T1[INDEX_64(i - b, lenT1_64)] & MASK_ONE(INDEX_I(i - b))),INDEX_I(i - b)) ^
                        SHIFT_BACK((T1[INDEX_64(i - b - 1, lenT1_64)] & MASK_ONE(INDEX_I(i - b - 1))),INDEX_I(i - b - 1));
        if (XOR_Result == 1) {
            Dred[INDEX_64(i, lenDred_64)] |= MASK_ONE(INDEX_I(i));
        }
        else {
            Dred[INDEX_64(i, lenDred_64)] &= ~(MASK_ONE(INDEX_I(i)));
        }
    }
}
    if(3 * b < lenR){
        //printf("\n4th Outer assignment\n");
        //Dred[2 * b - 1] = d[2 * b - 1] ^ d[3 * b] ^ T1[b - 2];
        XOR =   SHIFT_BACK((d[INDEX_64(2 * b - 1, lenR_64)]   & MASK_ONE(INDEX_I(2 * b - 1))), INDEX_I(2 * b - 1)) ^
                SHIFT_BACK((d[INDEX_64(3 * b, lenR_64)]   & MASK_ONE(INDEX_I(3 * b))), INDEX_I(3 * b))^
                SHIFT_BACK((T1[INDEX_64(b - 2, lenT1_64)]  & MASK_ONE(INDEX_I(b - 2))),INDEX_I(b - 2)) ;
        if (XOR == 1) {
            //printf("2 * b-1:%d Dred[INDEX_64(2 * b-1, lenDred_64)]:%lu\n",2 * b-1, Dred[INDEX_64(2 * b-1, lenDred_64)]);
            Dred[INDEX_64(2 * b - 1, lenDred_64)] |= MASK_ONE(INDEX_I(2 * b - 1));
            //printf("2 * b-1:%d Dred[INDEX_64(2 * b-1, lenDred_64)]:%lu\n",2 * b-1, Dred[INDEX_64(2 * b-1, lenDred_64)]);
        }
        else {
            Dred[INDEX_64(2 * b - 1, lenDred_64)] &= ~(MASK_ONE(INDEX_I(2 * b - 1)));
        }
    }
    if((3 * b + 1 < lenR) &&  (3 * b < lenR)){
        //printf("\n5th Outer assignment\n");
        //Dred[2 * b] = d[2 * b] ^ d[3 * b + 1] ^ d[3 * b];
        XOR =   SHIFT_BACK((d[INDEX_64(2 * b, lenR_64)]   & MASK_ONE(INDEX_I(2 * b))), INDEX_I(2 * b)) ^
                SHIFT_BACK((d[INDEX_64(3 * b + 1, lenR_64)]   & MASK_ONE(INDEX_I(3 * b + 1))), INDEX_I(3 * b + 1))^
                SHIFT_BACK((d[INDEX_64(3 * b, lenR_64)]   & MASK_ONE(INDEX_I(3 * b))), INDEX_I(3 * b));
        if (XOR == 1) {
            Dred[INDEX_64(2 * b, lenDred_64)] |= MASK_ONE(INDEX_I(2 * b));
            
        }
        else {
            //printf("2 * b:%d Dred[INDEX_64(2 * b, lenDred_64)]:%lu\n",2 * b, Dred[INDEX_64(2 * b, lenDred_64)]);
            Dred[INDEX_64(2 * b, lenDred_64)] &= ~(MASK_ONE(INDEX_I(2 * b)));
            //printf("5th Outer assignment\n");
            //printf("2 * b:%d Dred[INDEX_64(2 * b, lenDred_64)]:%lu\n",2 * b, Dred[INDEX_64(2 * b, lenDred_64)]);
        }
    }
    
    free(T1);
    free(T4);

}

void reduction_c1_batched_seq(uint64_t *d, uint64_t *Dred, uint64_t lenR_64, uint64_t lenR, uint64_t lenDred_64, uint64_t b) {
    
    unsigned lenT1_64 = (b - 1 + 63)/64;
    unsigned lenT4_64 = (b + 63)/64;
    //printf("lenT1_64: %u, lenT4_64: %u \n", lenT1_64, lenT4_64);

    uint64_t * T1 = (uint64_t*)aligned_alloc( 32, sizeof(uint64_t)*lenT1_64);
	if( NULL == T1 ) { printf("reduction_c1 |alloc T1 fail.\n"); exit(-1); }
	uint64_t * T4 = (uint64_t*)aligned_alloc( 32, sizeof(uint64_t)*lenT4_64);
	if( NULL == T4 ) { printf("Main |alloc T4 fail.\n"); exit(-1); }

    memset(T1, 0, sizeof(uint64_t) * lenT1_64);
    memset(T4, 0, sizeof(uint64_t) * lenT4_64);

    int version = 2;
    
    int64_t a_lastIndex  = ((b - 1 + 2 * b + 1) < lenR) ? (2 * b + 1) : (lenR - (b - 1));
    int64_t b_lastIndex  = ((b - 1 + 3 * b + 2) < lenR) ? (3 * b + 2) : (lenR - (b - 1));
    xor_range_select(version, T1, d, d, 0, b - 1, a_lastIndex, b_lastIndex); // Compute T1

    a_lastIndex  = ((b + 2 * b + 1) < lenR) ? (2 * b + 1) :  (lenR - (b));
    b_lastIndex  = ((b + 3 * b + 1) < lenR) ? (3 * b + 1) :  (lenR - (b));    
    xor_range_select(version, T4, d, d, 0, b, a_lastIndex, b_lastIndex); // Compute T4

    if(3 * b + 1 < lenR){
        xor3_single(Dred, d, T1, d, 0, 0, 0, 3 * b + 1); // Column 0
    }

    xor3_range_select(version, Dred, d, T1, T4, 1, b - 1, 0, 0, -1); // Columns 1 to b - 2
    if(3 * b < lenR){
        xor3_single(Dred, d, d, T4, b - 1, b - 1, 3 * b, b - 2);
    }

    xor3_single(Dred, d, T1, T4, b, b, 0, b - 1);
    xor3_range_select(version, Dred, d, T1, T1, b + 1, 2 * b - 1, 0, -b, -b - 1); // Columns b + 1 to 2b - 2
    if(3 * b < lenR){
        xor3_single(Dred, d, d, T1, 2 * b - 1, 2 * b - 1, 3 * b, b - 2);
    }
     if((3 * b + 1 < lenR) &&  (3 * b < lenR)){
        xor3_single(Dred, d, d, d, 2 * b, 2 * b, 3 * b + 1, 3 * b);
    }
    free(T1);
    free(T4); 

}


void reduction(int algorithm, uint64_t *poly_R, uint64_t *fin_key, uint64_t lenR_64, uint64_t lenR, uint64_t lenX, uint64_t lenDred_64){
    //uint64_t c = 1;
    uint64_t b = (lenX-1)/2;
    //printf("Irreducible polynomial:x^%ld + x^%ld + x^%ld + x^1 + 1 \n", 2*b+1, b + 1, b);
    //printf("b:%ld, c:1 \n", b);
    switch (algorithm)
    {
    case 1:
        reduction_c1_seq(poly_R, fin_key, lenR_64, lenR, lenDred_64, b);
        break;
    case 2:
        reduction_c1_par(poly_R, fin_key, lenR_64, lenR, lenDred_64, b);
        break;
    case 3:
        reduction_c1_batched_seq(poly_R, fin_key, lenR_64, lenR, lenDred_64, b);
        break;
    default:
        exit(1);
        break;
    }
}

void simplemult_gf2x(uint64_t * c, uint64_t * a, unsigned terms_a, uint64_t * b, unsigned terms_b,  uint64_t * d,  unsigned chunkSize){
	unsigned chunkNum  = terms_a / terms_b;
	//unsigned chunkNum  =  terms_a % terms_b ==0 ? terms_a / terms_b : (terms_a / terms_b) +1 ;
	//printf("chunkNum :%u \n", chunkNum);
	unsigned chunkIndex;
	for (unsigned i = 0; i < chunkNum; i++){
		chunkIndex = i*chunkSize;
		//printf("chunkIndex :%u \n", chunkIndex);

		//memset(d, 0, chunkSize * 2 * sizeof(uint64_t));
		
		gf2x_mul(d + chunkIndex*2, a + chunkIndex, chunkSize, b, chunkSize);
		//printf("d :" ); byte_dump( d , chunkSize *2 ); puts("");

		//printf("Before XOR: c:" ); byte_dump( c , terms_a + terms_b ); puts("");
		xor_bytes( c + chunkIndex, d + chunkIndex*2, chunkSize*2);
		//printf("After XOR: c:" ); byte_dump( c , terms_a + terms_b ); puts("");
	}
	//printf("End of the function ");
}

void simplemult_gf2x_par(uint64_t * c, uint64_t * a, unsigned terms_a, uint64_t * b, unsigned terms_b,  uint64_t * d,  unsigned chunkSize, omp_lock_t * locks){
	unsigned chunkNum  = terms_a / terms_b;
	//printf("chunkNum :%u \n", chunkNum);
	unsigned chunkIndex;
	omp_set_num_threads(12);
	
#pragma omp parallel
{
	
#pragma omp for private(chunkIndex)
	for (unsigned i = 0; i < chunkNum; i++){
		chunkIndex = i*chunkSize;
		//printf("chunkIndex :%u\n ", chunkIndex);
		//printf("Thread Number: %d\n", omp_get_thread_num());
		//memset(d, 0, chunkSize * 2 * sizeof(uint64_t));
		
		gf2x_mul(d + chunkIndex*2, a + chunkIndex, chunkSize, b, chunkSize);
		//printf("d :" ); byte_dump( d , chunkSize *2 ); puts("");


		//printf("Before XOR: c:" ); byte_dump( c , terms_a + terms_b ); puts("");
		omp_set_lock(&locks[i]);
		omp_set_lock(&locks[i+1]);
		//printf("THREAD_NUM :%u \n", omp_get_thread_num());
		xor_bytes( c + chunkIndex, d + chunkIndex*2, chunkSize*2);
		//printf("THREAD_NUM :%u \n", omp_get_thread_num());
		omp_unset_lock(&locks[i]);
		omp_unset_lock(&locks[i+1]);
		

		//printf("After XOR: c:" ); //byte_fdump( stdout, c , terms_a + terms_b ); puts("");
	}
	//printf("End of the function ");
}
}

void entropic_encryption(const unsigned char *in, unsigned char *out, size_t lenM, const void *key, size_t len_key)
{
    unsigned int chunkSize = 0, chunkNum = 0;

    // Lengths in 64-bit chunks
    uint64_t lenM_64 = (lenM + 63) / 64; // Ensure lenM_64 accounts for alignment (round up to the next multiple of 64 bits)
    uint64_t lenk_64 = (len_key + 63) / 64;

    // Allocate memory with error handling and proper cleanup using goto
    uint64_t *public_string = NULL;
    uint64_t *mult_result = NULL;
    uint64_t *chunks = NULL;
    uint64_t *final_key = NULL;

    printf("\nInisde entropic encryption 1\n");
    public_string = (uint64_t *)aligned_alloc(32, sizeof(uint64_t) * lenM_64);
    if (NULL == public_string) {
        fprintf(stderr, "entropic_encryption | alloc public_string fail.\n");
        exit(-1);
    }
    random_bytes_(public_string, lenM_64);
    printf("\nInisde entropic encryption 2\n");
    // Memory allocation for the multiplication result
    uint64_t lenR = lenM + len_key;
    uint64_t lenR_64 = lenk_64 + lenM_64;
    mult_result = (uint64_t *)aligned_alloc(32, sizeof(uint64_t) * lenR_64);
    if (NULL == mult_result) {
        fprintf(stderr, "entropic_encryption | alloc mult_result fail.\n");
        exit(-1);
    }

    chunkSize = lenk_64;
    chunkNum = lenM_64 / chunkSize;

    chunks = (uint64_t *)aligned_alloc(32, sizeof(uint64_t) * (chunkSize * 2 * chunkNum));
    if (NULL == chunks) {
        fprintf(stderr, "entropic_encryption | alloc chunks fail.\n");
        exit(-1);
    }
        printf("\nInisde entropic encryption 3\n");

    // Perform binary polynomial multiplication of the key and public string
    simplemult_gf2x(mult_result, public_string, lenM_64, (uint64_t *)key, lenk_64, chunks, chunkSize);
    free(public_string);
    public_string = NULL;

    free(chunks);
    chunks = NULL;

    final_key = (uint64_t *)aligned_alloc(32, sizeof(uint64_t) * lenM_64);
    if (NULL == final_key) {
        fprintf(stderr, "entropic_encryption | alloc final_key fail.\n");
        exit(-1);
    }

    // Reduce the multiplication result
    reduction(3, mult_result, final_key, lenR_64, lenR, lenM, lenM_64);
    free(mult_result);
    mult_result = NULL;

    // XOR input (`in`) and `final_key` and write to `out`
    size_t remaining_bytes = lenM % sizeof(uint64_t);
    for (unsigned i = 0; i < lenM_64 - 1; ++i) {
        ((uint64_t *)out)[i] = ((uint64_t *)in)[i] ^ final_key[i];
    }

    // Handle remaining bytes
    if (remaining_bytes > 0) {
        unsigned char *in_bytes = (unsigned char *)in;
        unsigned char *out_bytes = (unsigned char *)out;
        unsigned char *final_key_bytes = (unsigned char *)final_key;
        for (size_t i = 0; i < remaining_bytes; ++i) {
            out_bytes[lenM - remaining_bytes + i] = in_bytes[lenM - remaining_bytes + i] ^ final_key_bytes[lenM - remaining_bytes + i];
        }
    }


    free(final_key);
    final_key = NULL;
    
}