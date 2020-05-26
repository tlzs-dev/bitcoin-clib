#ifndef _HMAC_H_
#define _HMAC_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include "sha.h"

typedef struct hmac_sha256
{
	sha256_ctx_t outer;
	sha256_ctx_t inner;
}hmac_sha256_t;

void hmac_sha256_init(hmac_sha256_t * hmac, const unsigned char * key, size_t keylen);
void hmac_sha256_update(hmac_sha256_t * hmac, const unsigned char * data, size_t len);
void hmac_sha256_final(hmac_sha256_t * hmac, unsigned char hash[32]);


typedef struct hmac_sha512
{
	sha512_ctx_t outer;
	sha512_ctx_t inner;	
}hmac_sha512_t;

void hmac_sha512_init(hmac_sha512_t * hmac, const unsigned char * key, size_t keylen);
void hmac_sha512_update(hmac_sha512_t * hmac, const unsigned char * data, size_t len);
void hmac_sha512_final(hmac_sha512_t * hmac, unsigned char hash[64]);


#define hmac256(key, keylen, data, size, hash) do { \
		hmac_sha256_t hmac[1]; \
		hmac_sha256_init(hmac, (unsigned char *)key, keylen); \
		hmac_sha256_update(hmac, data, size); \
		hmac_sha256_final(hmac, hash); \
	} while(0)
	
#define hmac512(key, keylen, data, size, hash) do { \
		hmac_sha512_t hmac[1]; \
		hmac_sha512_init(hmac, (unsigned char *)key, keylen); \
		hmac_sha512_update(hmac, data, size); \
		hmac_sha512_final(hmac, hash); \
	} while(0)


#ifdef __cplusplus
}
#endif
#endif
