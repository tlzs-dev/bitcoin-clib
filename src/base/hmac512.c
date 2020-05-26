/*
 * hmac512.c
 * 
 * Copyright 2019 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hmac.h"

void hmac_sha512_init(hmac_sha512_t * hmac, const unsigned char * key, size_t keylen)
{
#define HMAC_KEY_SIZE 128
	int i;
	unsigned char rkey[HMAC_KEY_SIZE];
	sha512_init(&hmac->outer);
	sha512_init(&hmac->inner);
	
	if(keylen <= HMAC_KEY_SIZE)
	{
		memcpy(rkey, key, keylen);
		memset(rkey + keylen, 0, HMAC_KEY_SIZE - keylen);
	}else
	{
		sha512_ctx_t sha[1];
		sha512_init(sha);
		sha512_update(sha, key, keylen);
		sha512_final(sha, rkey);
		memset(rkey + 64, 0, 64);
	}
	
	for(i = 0; i < HMAC_KEY_SIZE; ++i)
	{
		rkey[i] ^= 0x5c;
	}
	sha512_update(&hmac->outer, rkey, HMAC_KEY_SIZE);
	
	for(i = 0; i < HMAC_KEY_SIZE; ++i)
	{
		rkey[i] ^= 0x5c ^ 0x36;
	}
	sha512_update(&hmac->inner, rkey, HMAC_KEY_SIZE);	
#undef HMAC_KEY_SIZE
}

void hmac_sha512_update(hmac_sha512_t * hmac, const unsigned char * data, size_t len)
{
	sha512_update(&hmac->inner, data, len);
}

void hmac_sha512_final(hmac_sha512_t * hmac, unsigned char hash[32])
{
	unsigned char in_hash[64];
	sha512_final(&hmac->inner, in_hash);
	sha512_update(&hmac->outer, in_hash, 64);
	sha512_final(&hmac->outer, hash);
}
