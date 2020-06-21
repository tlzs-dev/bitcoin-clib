/*
 * compact_int.c
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

#include "satoshi-types.h"

compact_int_t uint256_to_compact_int(const uint256_t * target)
{
	compact_int_t cint = { .bits = 0 };
	
	int num_zeros = 0;
	const unsigned char * p_end = (const unsigned char *)target + 32;
	
	// count the number of 0s at the end
	while(num_zeros < 32 && (p_end[-1] == 0)) { --p_end; ++num_zeros;}

	cint.exp = 32 - num_zeros;
	
	int num_bytes = 3;	// 24 bits
	if((num_zeros + num_bytes) > 32) num_bytes = 32 - num_zeros; 
	
	// unsigned char[] to little-endian int
	if(num_bytes > 0) cint.mantissa[2] = *--p_end;
	if(num_bytes > 1) cint.mantissa[1] = *--p_end;
	if(num_bytes > 2) cint.mantissa[0] = *--p_end;
	
	return cint;
}
uint256_t compact_int_to_uint256(compact_int_t * cint)
{
	uint256_t target = *uint256_zero;
	if(cint->exp >= 32) return target;
	
	int num_bytes = 3;
	if((cint->exp + num_bytes) > 32) num_bytes = 32 - cint->exp; 
	unsigned char * p_end = (unsigned char *)&target + cint->exp;
	
	// little-endian int to unsigned char[]
	if(num_bytes > 0) *--p_end = cint->mantissa[2];
	if(num_bytes > 1) *--p_end = cint->mantissa[1];
	if(num_bytes > 2) *--p_end = cint->mantissa[0];
	
	return target;
}

/**
 * helpler functions to calculate difficulty.
 * 
 * 	compact_int_div(): use to calc bdiff
 * 	uint256_div():     use to calc pdiff
 * 
 * For the explanation of 'bdiff' and 'pdiff', please refer to 'https://en.bitcoin.it/wiki/Difficulty'
 */
compact_int_t compact_int_div(const compact_int_t * n, const compact_int_t * d);
compact_int_t uint256_div(const uint256_t * n, const uint256_t * d);

#if defined(_TEST_COMPACT_INT) && defined(_STAND_ALONE)

#ifndef dump_line
#define dump_line(prefix, data, size) do { 	\
		fprintf(stderr, "%s", prefix);		\
		for(ssize_t i = 0; i < size; ++i) fprintf(stderr, "%.2x", ((unsigned char*)data)[i]);	\
		fprintf(stderr, "\n");				\
	} while(0)
#endif

#include <stdint.h>
int main(int argc, char **argv)
{
	// (000000000000000000000000000000000000000000000000) CB0404 0000000000
	static const uint256_t TARGET = {
		.val = {
			[24] = 0xcb,
			[25] = 0x04,
			[26] = 0x04,	
		},
	};
	static const uint32_t BITS = 0x1b0404cb;
	
	compact_int_t cint = {.bits = 0x1b0404cb };
	
	printf("test1: compact_int_to_uint256() ...\n");
	printf("\tcint    : 0x%.8x\n", cint.bits); 
	dump_line("\tcintdata:   ", &cint, sizeof(cint));
	
	uint256_t target = compact_int_to_uint256(&cint);
	dump_line("\ttarget: ", &target, 32);
	dump_line("\tTARGET: ", &TARGET, 32);
	
	assert(0 == memcmp(&target, &TARGET, 32));
	
	printf("test1: uint256_to_compact_int() ...\n");
	cint = uint256_to_compact_int(&TARGET);
	
	dump_line("\tTARGET: ", &TARGET, 32);
	printf("\tcint    : 0x%.8x\n", cint.bits); 
	dump_line("\tcintdata:   ", &cint, sizeof(cint));
	
	assert(cint.bits == BITS);
	
	return 0;
}
#endif

