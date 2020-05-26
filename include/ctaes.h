/*********************************************************************
 * Copyright (c) 2016 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _CTAES_H_
#define _CTAES_H_ 1

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint16_t slice[8];
} AES_state, aes_gcm_state;

typedef struct {
    AES_state rk[11];
} AES128_ctx, aes128_gcm_ctx_t;

typedef struct {
    AES_state rk[13];
} AES192_ctx, aes192_gcm_ctx_t;

typedef struct {
    AES_state rk[15];
} AES256_ctx, aes256_gcm_ctx_t;

void AES128_init(AES128_ctx* ctx, const unsigned char* key16);
void AES128_encrypt(const AES128_ctx* ctx, size_t blocks, unsigned char* cipher16, const unsigned char* plain16);
void AES128_decrypt(const AES128_ctx* ctx, size_t blocks, unsigned char* plain16, const unsigned char* cipher16);

void AES192_init(AES192_ctx* ctx, const unsigned char* key24);
void AES192_encrypt(const AES192_ctx* ctx, size_t blocks, unsigned char* cipher16, const unsigned char* plain16);
void AES192_decrypt(const AES192_ctx* ctx, size_t blocks, unsigned char* plain16, const unsigned char* cipher16);

void AES256_init(AES256_ctx* ctx, const unsigned char* key32);
void AES256_encrypt(const AES256_ctx* ctx, size_t blocks, unsigned char* cipher16, const unsigned char* plain16);
void AES256_decrypt(const AES256_ctx* ctx, size_t blocks, unsigned char* plain16, const unsigned char* cipher16);

#define aes256_gcm_init(ctx, key32) AES256_init(ctx, key32)
#define aes256_gcm_encrypt(ctx, blocks, cipher16, plain16)	AES256_encrypt(ctx, blocks, cipher16, plain16)
#define aes256_gcm_decrypt(ctx, blocks, plain16, cipher)	AES256_decrypt(ctx, blocks, plain16, cipher)

#endif
