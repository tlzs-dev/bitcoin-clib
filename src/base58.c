/*
 * base58.c
 * 
 * Copyright 2020 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include <endian.h>

#include "base58.h"

static const char* s_b58_digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const unsigned char s_b58_table[256] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF,    0,    1,    2,    3,    4,    5,    6,    7,    8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF,    9,    10,  11,   12,   13,   14,   15,   16, 0xFF,   17,   18,   19,   20,   21, 0xFF, 
	  22,   23,   24,   25,   26,   27,   28,   29,   30,   31,   32, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,   43, 0xFF,   44,   45,   46,
	  47,   48,   49,   50,   51,   52,   53,   54,   55,   56,   57, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

ssize_t base58_encode(const void * data, ssize_t length, char ** p_b58)
{
	if(length <= 0) return 0;
	
	size_t dst_size = length * 138 / 100 + 1;
	const unsigned char * src = data;
	size_t cb_leading_zeros = 0;
	while((cb_leading_zeros < length) && (0 == src[cb_leading_zeros])) ++cb_leading_zeros;
	
	src += cb_leading_zeros;
	length -= cb_leading_zeros;
	
	unsigned char * dst = calloc(dst_size, 1);
	assert(dst);
	
	size_t cb_dst = 1;
	for(size_t i = 0; i < length; ++i) {
		int carry = src[i];
		
		/**
		 * src = 58*(58*(58*(... (58*(dst[n] + dst[n-1]) + dst[n-2]) ...))) + dst[0] 
		*/
		int dst_index = 0;
		do {
			carry += ((int)dst[dst_index]) << 8;
			dst[dst_index] = carry % 58;
			carry /= 58;
		}while(++dst_index < cb_dst);
		
		while(carry) {
			carry += ((int)dst[cb_dst]) << 8;
			dst[cb_dst] = carry % 58;
			carry /= 58;
			++cb_dst;
		}
	}
	
	char * b58 = *p_b58;
	if(NULL == b58) {
		b58 = calloc(cb_dst + cb_leading_zeros + 1, 1);
		assert(b58);
		*p_b58 = b58;
	}
	
	for(size_t i = 0; i < cb_leading_zeros; ++i) *b58++ = '1';
	
	for(size_t i = 0; i < cb_dst; ++i) {
		b58[i] = s_b58_digits[(int)dst[cb_dst - i - 1]];
	}
	b58[cb_dst] = '\0';
	free(dst);
	return (cb_dst + cb_leading_zeros);
}

ssize_t base58_decode(const char * b58, ssize_t cb_b58, unsigned char ** p_dst)
{
	if(cb_b58 <= 0) cb_b58 = strlen(b58);
	if(cb_b58 == 0) return 0;
	
	unsigned char * dst_buf = calloc(cb_b58 + 1, 1);	// dst size <= b58.length
	assert(dst_buf);
	unsigned char * dst = dst_buf;
	
	// insert leading zeros
	ssize_t offset = 0;
	while(b58[offset] == '1') ++offset; 
	dst += offset;
	b58 += offset;
	cb_b58 -= offset;
	
	ssize_t cb_dst = 1;
	for(int i = 0; i < cb_b58; ++i)
	{
		int carry = s_b58_table[(int)b58[i]];
		if(carry == 0xFF) {
			free(dst_buf);
			return -1;
		}
		
		int dst_index = 0;
		do {
			carry += ((int)dst[dst_index]) * 58;
			dst[dst_index] = carry & 0xFF;
			carry >>= 8;
		}while(++dst_index < cb_dst);
		
		while(carry) {
			assert(cb_dst <= cb_b58);
			carry += ((int)dst[cb_dst]) * 58;
			dst[cb_dst] = carry & 0xFF;
			carry >>= 8;
			++cb_dst;
		}
	}
	
	// reverse bytes
	for(ssize_t i = 0; i < cb_dst / 2; ++i) {
		unsigned char c = dst[i];
		dst[i] = dst[cb_dst - i - 1];
		dst[cb_dst - i - 1] = c;
	}
	
	cb_dst += offset;
	if(NULL == *p_dst) *p_dst = dst_buf;
	else {
		memcpy(*p_dst, dst_buf, cb_dst);
		free(dst_buf);
	}
	return cb_dst;
}


#if defined(_TEST_BASE58) && defined(_STAND_ALONE)
size_t base58_encode_legacy(const unsigned char * src, size_t cb_src, char * to, size_t buffer_size)
{
	size_t cb_dst = cb_src * 138 / 100 + 1;
	if(NULL == to) // query buffer size
		return cb_dst; 
		
	if(cb_dst > buffer_size) return 0;
	int i;
	int zeros = 0;
	int carry;
	
	const unsigned char * p_end = src + cb_src;
	
	unsigned char * dst = (unsigned char *)calloc(1, cb_dst);
	assert(NULL != dst);
	
	// skip leading zeros
	while((src < p_end) && (*src == 0))
	{
		++src;
		++zeros;
	}
	
	while(src < p_end)
	{
		carry = *src;
		for(i = cb_dst - 1; i >= 0; --i)
		{
			carry += 256 * dst[i];
			dst[i] = carry % 58;
			carry /= 58;			
		}
		assert(carry == 0);
		++src;
	}
	
	// skip leading zeros in b58 result
	unsigned char * p_begin = dst;
	p_end = dst + cb_dst;
	while((p_begin < p_end) && (p_begin[0] == 0)) ++p_begin;
	
	cb_dst = (p_end - p_begin);
	
	
	char * iter = to;
	for(i = 0; i < zeros; ++i) 
		iter[i] = '1';	
	iter += zeros;
	for(i = 0; i < cb_dst; ++i) 
		iter[i] = s_b58_digits[p_begin[i]];
	
	iter[i] = '\0';
	
	free(dst);
	return (cb_dst + zeros);
}

#include <ctype.h>
static size_t base58_decode_legacy(const char * src, size_t cb_src, unsigned char * to, size_t buffer_size)
{
	assert(NULL != src);
	if(-1 == cb_src) cb_src = strlen(src);
	if(0 == cb_src) return 0;
	
	size_t cb_dst = cb_src * 733 / 1000 + 1;
	if(NULL == to) // query buffer size
		return cb_dst;
		
	if(cb_dst > buffer_size) return 0;
	
	unsigned char * b256 = (unsigned char *)calloc(1, cb_dst);
	assert(NULL != b256);
	
	// skip leading b58 zeros ('1')
	int zeros;
	int i;
	for(zeros = 0; zeros < cb_src; ++zeros)
	{
		if(src[zeros] != '1') break;
	}
	src += zeros;
	cb_src -= zeros;
	int carry;
	//~ fprintf(stderr, "src = [%s]\n", src);
	//~ unsigned char ch;
	for(i = 0; i < cb_src; ++i)
	{
		carry = (int)s_b58_table[(unsigned char)src[i]];
		
		if(carry == 0xff) 
		{
			
			fprintf(stderr, "Error: ['%s' - '%s'] @ line %d: invalid b58 string format. (zeros = %d, char[%d] = %.2x)\n",
				__FILE__, __func__, __LINE__,
				zeros,
				i, src[i]);
			free(b256);
			return 0;
		}
		
		for(int j = cb_dst - 1; j >= 0; --j)
		{
			carry += 58 * b256[j];
			b256[j] = carry % 256;
			carry >>= 8;
		}
		assert(carry == 0);
		//~ ++src;
	}
	
	// skip trailing spaces
	for(; i < cb_src; ++i)
	{
		if(!isspace(src[i])) break;
	}
	if(i != cb_src)
	{
		free(b256);
		return 0;
	}
	
	unsigned char * p_begin = b256;
	for(i = 0; i < cb_dst; ++i)
		if(b256[i] != 0) break;
		
	p_begin += i;
	cb_dst -= i;
	
	for(i = 0; i < zeros; ++i)
		to[i] = 0;
	
	unsigned char * iter = to + i;
	
	for(i = 0; i < cb_dst; ++i)
	{
		iter[i] = p_begin[i];
	}
	free(b256);
	return (cb_dst + zeros);
}


#define ROUNDS (100000)
static int test_encode(void);
static int test_decode(void);
int main(int argc, char **argv)
{
	test_encode();
	test_decode();
	return 0;
}

static int test_encode()
{
	printf("\n====== %s() ======\n", __FUNCTION__);
	unsigned char data[32] = {0, 0, 0, 'h', 'e', 'l', 'l', 'o', 0, 1, 2, 3, 4, 5 };
	size_t cb_data = sizeof(data);
	printf("data(cb=%d): [%s]\n", (int)cb_data, (char *)data);
	
	char b58_buf[200] = "";
	char b58_verify[200] = "";
	
	char * b58 = b58_buf;
	ssize_t cb = base58_encode(data, cb_data, &b58);
	assert(cb > 0);
	
	ssize_t cb_verify = base58_encode_legacy(data, cb_data, b58_verify, sizeof(b58_verify));
	assert(cb_verify > 0);
	
	printf("b58       : %s\n", b58);
	printf("b58_verify: %s\n", b58_verify);
	
	assert(0 == strcmp(b58, b58_verify));
	
	// benchmark
	double time_elapsed;
	app_timer_start(NULL);
	for(int i = 0; i < ROUNDS; ++i)
	{
		base58_encode(data, cb_data, &b58);
	}
	time_elapsed = app_timer_stop(NULL);
	printf("base58_encode(): time_elapsed = %.6f (s)\n", time_elapsed);
	
	
	app_timer_start(NULL);
	for(int i = 0; i < ROUNDS; ++i)
	{
		base58_encode_legacy(data, cb_data, b58_verify, sizeof(b58_verify));
	}
	time_elapsed = app_timer_stop(NULL);
	printf("base58_encode_legacy(): time_elapsed = %.6f (s)\n", time_elapsed);
	
	return 0;
}

static int test_decode()
{
	printf("\n====== %s() ======\n", __FUNCTION__);
	static const char b58_list[2][100] = {
		"38bxLNKsRnCTXcfQggeDYJ6vMjKnQZa9Dy",
		"1115jsvRizAw5GteUxFyvuqAqgQKz5E3ywJxbruudgT",
	};
	
	unsigned char ext_pubkey[100] = { 0 };
	unsigned char * p_data = ext_pubkey;
	
	unsigned char verify_data[100] = { 0 };
	
	for(size_t i = 0; i < (sizeof(b58_list) / sizeof(b58_list[0])); ++i)
	{
		const char * b58 = b58_list[i];
		ssize_t cb_b58 = strlen(b58);
		
		ssize_t cb = base58_decode(b58, cb_b58, &p_data); 
		assert(cb > 0);
		printf("decode: cb=%d, data=", (int)cb); dump(p_data, cb); printf("\n");
	
		ssize_t cb_verify = base58_decode_legacy(b58, cb_b58, verify_data, sizeof(verify_data)); 
		assert(cb_verify > 0);
		printf("legacy: cb=%d, data=", (int)cb_verify); dump(verify_data, cb_verify); printf("\n");
		
		assert(cb == cb_verify);
		assert(0 == memcmp(p_data, verify_data, cb));
		
	}
	
	// benchmark
	const char * b58 = b58_list[0];
	ssize_t cb_b58 = strlen(b58);
	double time_elapsed;
	app_timer_start(NULL);
	for(int i = 0; i < ROUNDS; ++i)
	{
		
		 base58_decode(b58, cb_b58, &p_data); 
	}
	time_elapsed = app_timer_stop(NULL);
	printf("base58_decode(): time_elapsed = %.6f (s)\n", time_elapsed);
	
	
	app_timer_start(NULL);
	for(int i = 0; i < ROUNDS; ++i)
	{
		 base58_decode_legacy(b58, cb_b58, verify_data, sizeof(verify_data)); 
	}
	time_elapsed = app_timer_stop(NULL);
	printf("base58_decode_legacy(): time_elapsed = %.6f (s)\n", time_elapsed);
	
	return 0;
}

#undef ROUNDS
#endif
