#ifndef _SHA_H_
#define _SHA_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct sha256_ctx
{
	uint32_t s[8];
	unsigned char buf[64];
	size_t bytes;
}sha256_ctx_t;

void sha256_init(sha256_ctx_t * sha);
void sha256_update(sha256_ctx_t * sha, const unsigned char * data, size_t len);
void sha256_final(sha256_ctx_t * sha, unsigned char hash[static 32]);



typedef struct sha512_ctx
{
	uint64_t s[8];
	unsigned char buf[128];
	size_t bytes;
}sha512_ctx_t;

void sha512_init(sha512_ctx_t * sha);
void sha512_update(sha512_ctx_t * sha, const void * data, size_t len);
void sha512_final(sha512_ctx_t * sha, unsigned char hash[static 64]);




#ifdef __cplusplus
}
#endif
#endif
