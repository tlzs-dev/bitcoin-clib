/*
 * crypto.c
 * 
 * Copyright 2020 Che Hongwei <htc.chehw@gmail.com>
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
#include <assert.h>

#include "crypto.h"

#if defined(_TEST_CRYPTO) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	unsigned char hmac_key[16] = { 0x01, };
	unsigned char hash[64] = { 0 };
	hmac256(hmac_key, 16, (unsigned char *)"hello world", 11, hash);
	
	for(int i = 0; i < 32; ++i)
	{
		printf("%.2x", hash[i]);
	}
	printf("\n");
	
	aes256_gcm_ctx_t aes[1];
	
	unsigned char message[1024];
	unsigned char cipher[1024] = { 0 };
	unsigned char plain[1024] = { 0 };
	for(int i = 0; i < (int)(sizeof(message) / sizeof(message[0])); ++i)
	{
		message[i] = i * 2;
	}
	aes256_gcm_init(aes, hash);
	aes256_gcm_encrypt(aes, 1024 / 16, cipher, message);
	
	aes256_gcm_decrypt(aes, 1024 / 16, plain, cipher);
	
	for(int i = 0; i < (int)(sizeof(plain) / sizeof(plain[0])); ++i)
	{
		printf(" %.2x <-- %.2x | ", plain[i], cipher[i]);
		if((i & 0x0f) == 0x0F) printf("\n");
	}
	return 0;
}
#endif
