/*
 * satoshi-datatypes.c
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

#include <stdint.h>

#include "crypto.h"
#include "utils.h"

#include "common.h"
#include "satoshi-types.h"
#include "bitcoin-consensus.h"

/**
 * @ref https://en.bitcoin.it/wiki/Protocol_documentation
 */

/*********************************************************
 * varint
*********************************************************/
size_t varint_calc_size(uint64_t value)
{
	if(value < 0XFD) return 1;
	if(value <= 0xFFFF) return 3;
	if(value <= 0xFFFFFFFF) return 5;
	return 9;
}

static inline void varint_set_data(unsigned char * vch, uint64_t value)
{
	if(value < 0XFD) {
		vch[0] = (unsigned char)value;
	}
	else if(value <= 0xFFFF) {
		vch[0] = 0xFD;
		uint16_t u16 = htole16((uint16_t)value);
		memcpy(&vch[1], &u16, 2);
	}else if (value <= 0xFFFFFFFF)
	{
		uint32_t u32 = htole32((uint32_t)value);
		vch[0] = 0xFE;
		memcpy(&vch[1], &u32, 4);
	}
	else
	{
		uint64_t u64 = htole64(value);
		vch[0] = 0xFF;
		memcpy(&vch[1], &u64, 8);
	}
	return;
}

varint_t * varint_new(uint64_t value)
{
	size_t size = varint_calc_size(value);
	assert(size > 0 && size <= 9);
	
	unsigned char * vch = calloc(1, size);
	varint_set_data(vch, value);
	
	return (varint_t *)vch;
}

void varint_free(varint_t * vint)
{
	free(vint);
}

size_t varint_size(const varint_t * vint)
{
	uint8_t * vch = (uint8_t *)vint;
	if(vch[0] < 0xFD) return 1;
	switch(vch[0]) {
	case 0xFD: return 3;
	case 0xFE: return 5;
	case 0xFF: return 9;
	default: break;
	}
	return -1;
}

varint_t * varint_set(varint_t * vint, uint64_t value)
{
	if(NULL == vint) return varint_new(value);
	
	size_t new_size = varint_calc_size(value);
	assert(new_size > 0 && new_size <= 9);
	
	//~ size_t old_size = varint_size(vint);
	//~ if(old_size != new_size) {
		//~ varint_free(vint);
		//~ return varint_new(value);
	//~ }
	
	varint_set_data(vint->vch, value);
	return vint;
}

uint64_t varint_get(const varint_t * vint)
{
	assert(vint);
	
	uint64_t value = 0;
	const uint8_t * vch = vint->vch;
	
	if(vch[0] < 0xFD) return vch[0];
	
	if(vch[0] == 0xFD) {
		uint16_t u16;
		memcpy(&u16, &vch[1], 2);
		value = le16toh(u16);		
	}else if(vch[0] == 0xFE)
	{
		uint32_t u32;
		memcpy(&u32, &vch[1], 4);
		value = le32toh(u32);
	}else {
		uint64_t u64;
		memcpy(&u64, &vch[1], 8);
		value = le64toh(u64);
	}
	return value;
}



/*********************************************************
 * varstr
*********************************************************/
const varstr_t varstr_empty[1];	// {{ .vch = {0} }

varstr_t * varstr_new(const unsigned char * data, size_t length)
{
	size_t vint_size = varint_calc_size(length);
	assert(vint_size > 0 && vint_size <= 9 && ((vint_size + length) > length));
	
	
	uint8_t * vch = calloc(1, vint_size + length);
	assert(vch);
	varint_set_data(vch, length);
	
	if(data && (length > 0) )
	{
		memcpy(vch + vint_size, data, length);
	}
	return (varstr_t *)vch;
}
void varstr_free(varstr_t * vstr)
{
	if(vstr != varstr_empty) free(vstr);
}

varstr_t * varstr_clone(const varstr_t * vstr)
{
	if(NULL == vstr) return NULL;
	if(vstr == varstr_empty) return (varstr_t *)varstr_empty;
	
	ssize_t size = varstr_size(vstr);
	assert(size > 0);
	
	varstr_t * dst = malloc(size);
	assert(dst);
	memcpy(dst, vstr, size);
	return dst;
}

varstr_t * varstr_resize(varstr_t * vstr, size_t new_len)
{
	if(NULL == vstr || vstr == varstr_empty) return varstr_new(NULL, new_len);
	
	size_t old_len = varstr_length(vstr);
	if(old_len == new_len) return vstr;
	
	varstr_t * new_str = varstr_new(NULL, new_len);
	assert(new_str);
	
	size_t len = (old_len < new_len)?old_len:new_len;
	if(len > 0)
	{
		unsigned char * old_data = vstr->vch + varint_size((varint_t *)vstr);
		unsigned char * new_data = new_str->vch + varint_size((varint_t *)new_str);
		assert(old_data && new_data);
		memcpy(new_data, old_data, len);
	}
	
	varstr_free(vstr);
	return new_str;
}

size_t varstr_size(const varstr_t * vstr)
{
	size_t vint_size = varint_size((varint_t *)vstr);
	size_t data_len = varint_get((varint_t *)vstr);
	
	return  (vint_size + data_len);
}

varstr_t * varstr_set(varstr_t * vstr, const unsigned char * data, size_t length)
{
	if(NULL == vstr || vstr == varstr_empty) return varstr_new(data, length);
	
	unsigned char * p = (unsigned char *)vstr;
	varint_set((varint_t *)p, length);
	p += varint_size((varint_t *)p);
	
	if(data) memcpy(p, data, length);
	return vstr;
}

//~ size_t varstr_length(const varstr_t * vstr)
//~ {
	//~ return varint_get((varint_t *)vstr);
//~ }

size_t varstr_get(const varstr_t * vstr, unsigned char ** p_data, size_t buf_size)
{
	assert(vstr);
	ssize_t data_len = varint_get((varint_t *)vstr);
	if(data_len <= 0) return 0;

	if(NULL == p_data) return data_len;	// return buffer size
	
	unsigned char * dst = *p_data;
	if(dst) {
		if(buf_size == 0 || buf_size > data_len) buf_size = data_len;
		
	}else
	{
		dst = malloc(data_len + 1);
		assert(dst);
		*p_data = dst;
		
		buf_size = data_len;
		dst[data_len] = '\0';
	}
	
	const unsigned char * src = vstr->vch + varint_size((varint_t *)vstr);
	assert(src);
	
	memcpy(dst, src, buf_size);		// truncate to buf_size
	return buf_size;
}


/******************************
 * uint256
*****************************/
void uint256_reverse(uint256_t * u256)
{
	uint64_t * u64 = (uint64_t *)u256->val;
	uint64_t tmp;
	
	tmp = bswap_64(u64[0]);
	u64[0] = bswap_64(u64[3]);
	u64[3] = tmp;
	
	tmp = bswap_64(u64[1]);
	u64[1] = bswap_64(u64[2]);
	u64[2] = tmp;
	return;
}

char * uint256_to_string(const uint256_t * u256, int to_little_endian, char ** p_hex)
{
	assert(u256);
	char * hex = p_hex?*p_hex:NULL;
	if(NULL == hex) hex = calloc(1, 33);
	
	uint256_t val = *u256;
	if(to_little_endian) uint256_reverse(&val);
	
	bin2hex(&val, sizeof(val), &hex);
	return hex;
}

ssize_t uint256_from_string(uint256_t * u256, int from_little_endian, const char * hex, ssize_t length)
{
	// big-endian
	assert(hex);
	ssize_t cb = length;
	if(cb <= 0) cb = strlen(hex);
	assert(cb <= 64 && !(cb & 0x01));
	
	unsigned char data[32] = { 0 };
	void * p_data = data;
	cb = hex2bin(hex, cb, &p_data);
	assert(cb >= 0 && cb <= 32);
	
	memset(u256->val, 0, 32);
	if(cb > 0)
	{
		if(from_little_endian)
		{
			memcpy(&u256->val[0], data, cb);
			uint256_reverse(u256);
		}else
		{
			memcpy(&u256->val[32 - cb], data, cb);
		}
	}
	return cb;
}

/************************************************************
 * @ingroup satoshi_tx
 * 
 */
#ifdef _DEBUG
#define message_parser_error_handler(fmt, ...) do { \
		fprintf(stderr, "\e31m[ERROR]::%s@%d::%s(): " fmt "\e[39m" "\n", \
			__FILE__, __LINE__, __FUNCTION__,	\
			##__VA_ARGS__);						\
		abort();								\
		goto label_error;						\
	} while(0)
#else
#define message_parser_error_handler(fmt, ...) do { \
		fprintf(stderr, "\e31m[ERROR]::%s@%d::%s(): " fmt "\e[39m" "\n", \
			__FILE__, __LINE__, __FUNCTION__,	\
			##__VA_ARGS__);						\
		goto label_error;						\
	} while(0)
#endif

static const satoshi_outpoint_t s_coinbase_outpoint[1] = {{
	.prev_hash = {0},
	.index = 0xffffffff
}};


/** 
 * parse_varint:
 * 	@return 
 * 		next offset on success, 
 * 		NULL on error.
 */
static inline const unsigned char * parse_varint(
	const unsigned char * p, 
	const unsigned char * p_end,
	ssize_t * value)
{
	assert(value);
	
	if(p >= p_end) return NULL;
	
	size_t vint_size = varint_size((varint_t *)p);
	if((p + vint_size) > p_end) return NULL;
	
	*value = varint_get((varint_t *)p);
	return (p + vint_size);
}


/** 
 * parse_varstr:
 * 	@return 
 * 		next offset on success, 
 * 		NULL on error.
 */
static inline const unsigned char * parse_varstr(
	const unsigned char * p, 
	const unsigned char * p_end,
	varstr_t ** p_dst)
{
	assert(p_dst);
	if(p >= p_end) return NULL;
	
	size_t vstr_size = varstr_size((varstr_t *)p);
	if((p + vstr_size) > p_end) return NULL;
	
	*p_dst = varstr_clone((varstr_t *)p);
	return (p + vstr_size);
}


varstr_t * satoshi_txin_get_redeem_scripts(const satoshi_txin_t * txin)
{
	if(NULL == txin || NULL == txin->redeem_scripts) return NULL;
	
	const unsigned char * scripts_data = varstr_getdata_ptr(txin->redeem_scripts);
	const unsigned char * p_end = scripts_data + varstr_length(txin->redeem_scripts);
	
	scripts_data += txin->redeem_scripts_start_pos;
	if(scripts_data >= p_end) return NULL;
	
	return varstr_new(scripts_data, (p_end - scripts_data));
}

ssize_t satoshi_txin_query_redeem_scripts_data(const satoshi_txin_t * txin, const unsigned char ** p_data)
{
	if(NULL == txin || NULL == txin->redeem_scripts) return -1;
	varstr_t * redeem_scripts = txin->redeem_scripts;
	
	const unsigned char * p = varstr_getdata_ptr(redeem_scripts);
	const unsigned char * p_end = p + varstr_length(redeem_scripts);
	
	p += txin->redeem_scripts_start_pos;
	if(p > p_end) return -1;
	
	*p_data = p;
	return p_end - p;
}

varstr_t * satoshi_txin_set_redeem_scripts(satoshi_txin_t * txin, const unsigned char * data, size_t length)
{
	if(NULL == txin) return NULL;
	
	varstr_t * redeem_scripts = varstr_new(data, length);
	varstr_free(txin->redeem_scripts);
	txin->redeem_scripts = redeem_scripts;
	txin->redeem_scripts_start_pos = 0;
	return redeem_scripts;
}


ssize_t satoshi_txin_parse(satoshi_txin_t * txin, ssize_t length, const void * payload)
{
	assert(txin && (length > 0) && payload);

	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	// step 1. parse outpoint
	if((p + sizeof(struct satoshi_outpoint)) > p_end) {
		message_parser_error_handler("%s", "parse outpoint failed.");
	}
	memcpy(&txin->outpoint, p, sizeof(struct satoshi_outpoint));
	p += sizeof(struct satoshi_outpoint);
	
	txin->is_coinbase = (0 == memcmp(&txin->outpoint, s_coinbase_outpoint, sizeof(txin->outpoint)));
	
	// step2. parse scripts
	ssize_t vstr_size = varstr_size((varstr_t *)p);
	if((p + vstr_size) > p_end) message_parser_error_handler("parse sig_scripts failed: %s", "invalid payload length.");
	
	txin->scripts = varstr_clone((varstr_t *)p);
	assert(txin->scripts && varstr_size(txin->scripts) == vstr_size);
	
	txin->cb_scripts = varstr_length(txin->scripts);
	p += vstr_size;

	// step 3. parse sequence
	if((p + sizeof(uint32_t)) > p_end) {
		message_parser_error_handler("parse sequence failed: %s.", "invalid payload length");
	}
	txin->sequence = *(uint32_t *)p;
	p += sizeof(uint32_t);
	
	return (p - (unsigned char *)payload);
label_error:
	satoshi_txin_cleanup(txin);
	return -1;
}

ssize_t satoshi_txin_serialize(const satoshi_txin_t * txin, unsigned char ** p_data)
{
	assert(txin->scripts);
	ssize_t vstr_size = varstr_size(txin->scripts);
	assert(vstr_size > 0);
	
	ssize_t cb_payload 							// payload length
		= sizeof(struct satoshi_outpoint) 
		+ vstr_size
		+ sizeof(uint32_t);				// sizeof(sequence)

	if(NULL == p_data) return cb_payload;
	
	assert(cb_payload > 0);
	unsigned char * payload = *p_data;
	if(NULL == payload) {
		payload = malloc(cb_payload);
		assert(payload);
		*p_data = payload;
	}

	unsigned char * p = payload;
	unsigned char * p_end = p + cb_payload;
	
	// step 1. write outpoint
	memcpy(p, &txin->outpoint, sizeof(struct satoshi_outpoint));
	p += sizeof(struct satoshi_outpoint);
	
	// step 2. write sig_scripts
	memcpy(p, txin->scripts, vstr_size);
	p += vstr_size;
		
	// step 3. write sequence
	assert((p + sizeof(uint32_t)) <= p_end);
	*(uint32_t *)p = txin->sequence;
	p += sizeof(uint32_t);
	
	assert(p == p_end);
	return cb_payload;
}

void satoshi_txin_cleanup(satoshi_txin_t * txin)
{
	if(txin) {
		if(txin->scripts)
		{
			varstr_free(txin->scripts);
			txin->scripts = NULL;
		}
		
		if(txin->signatures)
		{
			for(ssize_t i = 0; i < txin->num_signatures; ++i)
			{
				varstr_free(txin->signatures[i]);
			}
			free(txin->signatures);
		}
		
		if(txin->redeem_scripts)
		{
			varstr_free(txin->redeem_scripts);
			txin->redeem_scripts = NULL;
		}
	}
	return;
}

//~ typedef struct satoshi_txout
//~ {
	//~ int64_t value;
	//~ ssize_t cb_script;
	//~ unsigned char * scripts;
//~ }satoshi_txout_t;
ssize_t satoshi_txout_parse(satoshi_txout_t * txout, ssize_t length, const void * payload)
{
	assert(txout && (length > 0) && payload);
	const unsigned char * p = (unsigned char *) payload;
	const unsigned char * p_end = p + length;
	
	// parse value
	if(length < sizeof(int64_t)) message_parser_error_handler("parse value failed: %s", "invalid payload length.");
	txout->value = *(int64_t *)p;
	p += sizeof(int64_t); 
	
	if((p + 1) > p_end) message_parser_error_handler("parse pk_script failed: %s", "no varint data.");
	
	// parse pk_scripts
	ssize_t vstr_size = varstr_size((varstr_t *)p);
	if((p + vstr_size) > p_end) message_parser_error_handler("%s", "invalid varstr size or payload length.");
	
	txout->scripts = varstr_clone((varstr_t *)p);
	assert(txout->scripts && varstr_size(txout->scripts) == vstr_size);
	p += vstr_size;
	
	/**
	 * check Witness flags: 
	 * A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that 
	 * consists of a 1-byte push opcode (for 0 to 16) 
	 * followed by a data push between 2 and 40 bytes gets a new special meaning. 
	 * The value of the first push is called the "version byte". 
	 * The following byte vector pushed is called the "witness program".
	*/
	unsigned char * scripts_data = varstr_getdata_ptr(txout->scripts);
	txout->flags = (scripts_data[0] <= 16)?satoshi_txout_type_segwit:satoshi_txout_type_legacy;
	
	return (p - (unsigned char *)payload);
label_error:
	satoshi_txout_cleanup(txout);
	return -1;
}

ssize_t satoshi_txout_serialize(const satoshi_txout_t * txout, unsigned char ** p_data)
{
	ssize_t	scripts_size = varstr_size(txout->scripts);
	ssize_t cb_payload = sizeof(int64_t) + scripts_size;
	
	if(NULL == p_data) return cb_payload;
	
	unsigned char * payload = *p_data;
	if(NULL == payload)
	{
		malloc(cb_payload);
		assert(payload);
		*p_data = payload;
	}
	
	unsigned char * p_end = payload + cb_payload;
	// write value
	assert((payload + sizeof(int64_t)) < p_end);
	*(int64_t *)payload = txout->value;
	payload += sizeof(int64_t);
	
	// write pk_scripts 
	memcpy(payload, txout->scripts, scripts_size);
	payload += scripts_size;
	
	assert(payload == p_end);
	return cb_payload;
}
void satoshi_txout_cleanup(satoshi_txout_t * txout)
{
	if(txout && txout->scripts)
	{
		varstr_free(txout->scripts);
		txout->scripts = NULL;
	}
}

//~ typedef struct satoshi_tx
//~ {
	//~ int32_t version;
	//~ int has_flag;	// has witness-flag
	//~ uint8_t flag[2]; // If present, always 0001, and indicates the presence of witness data
	//~ ssize_t txin_count;
	//~ satoshi_txin_t * txins;
	
	//~ ssize_t txout_count;
	//~ satoshi_txout_t * txouts;
	
	//~ ssize_t cb_witness;
	//~ bitcoin_tx_witness_t * witnesses;
	//~ uint32_t lock_time;
	
//~ }satoshi_tx_t;

#define parse_data(p, p_end, data_type, dst) ({	\
		const unsigned char * ret = NULL;		\
		if((p + sizeof(data_type)) <= p_end) {	\
			dst = *(data_type *)p;				\
			p += sizeof(data_type);				\
			ret = p;							\
		}										\
		ret;									\
	})


ssize_t satoshi_tx_parse(satoshi_tx_t * tx, ssize_t length, const void * payload)
{
	assert(tx);
	assert(length > 0 && length <= MAX_BLOCK_SERIALIZED_SIZE);
	
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	// parse version
	p = parse_data(p, p_end, int32_t, tx->version);
	if(NULL == p) {
		message_parser_error_handler("parse version failed: %s", "invalid payload length");
	}
	
	// parse witness flag, If present, always 0001, and indicates the presence of witness data
	if((p + 2) > p_end){
		message_parser_error_handler("parse flags failed: %s", "invalid payload length");
	}
	if(p[0] == 0) {	// has witness flag
		if(p[1] != 1) {	// According to current protocol (2020/05/26), witness-flag MUST BE {0x00, 0x01}.
			message_parser_error_handler("invalid witness flag: '%.2x %.2x'", p[0], p[1]);
		}
		
		tx->has_flag = 1;
		tx->flag[0] = p[0];
		tx->flag[1] = p[1];
		p += 2;
	}
	
	// parse txins
	if(p >= p_end) message_parser_error_handler("parse txins failed: %s", "invalid payload length");
	
	p = parse_varint(p, p_end, &tx->txin_count);
	if(NULL == p)
	{
		message_parser_error_handler("parse txin_count failed: %s", "invalid payload length");
	}
	if(tx->txin_count <= 0) message_parser_error_handler("invalid txins count: %d", (int)tx->txin_count);
	
	satoshi_txin_t * txins = calloc(tx->txin_count, sizeof(*txins));
	assert(txins);
	tx->txins = txins;
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		if(p >= p_end) message_parser_error_handler("no txins[%d] data.", (int)i);
		ssize_t cb_payload = satoshi_txin_parse(&txins[i], (p_end - p), p);
		if(cb_payload <= 0) message_parser_error_handler("parse txins[%d] failed.", (int)i);
		p += cb_payload;
	}
	
	// parse txouts
	p = parse_varint(p, p_end, &tx->txout_count);
	if(NULL == p) message_parser_error_handler("parse txout failed: %s", "invalid payload length");
	
	if(tx->txout_count <= 0) message_parser_error_handler("invalid txouts count: %d", (int)tx->txout_count);
	
	satoshi_txout_t * txouts = calloc(tx->txout_count, sizeof(*txouts));
	assert(txouts);
	tx->txouts = txouts;
	for(ssize_t i = 0; i < tx->txout_count; ++i)
	{
		if(p >= p_end) message_parser_error_handler("no txout[%d] data.", (int)i);
		ssize_t cb_payload = satoshi_txout_parse(&txouts[i], (p_end - p), p);
		if(cb_payload <= 0) message_parser_error_handler("parse txout[%d] failed.", (int)i);
		p += cb_payload;
	}
	
	// parse witnesses_data if has
	tx->cb_witnesses = 0;
	
	if( tx->has_flag 
		&& ((p + sizeof(uint32_t)) < p_end)	// has witness data
	  ) 
	{
		/*
		 * parse payload to witnesses[(tx->txins_count)] array
		 * each txin is associated with a witness field
		 * if a txin is non-witness, set witness to 0x00.
		 */
		
		assert(tx->txin_count > 0);
		bitcoin_tx_witness_t * witnesses = calloc(tx->txin_count, sizeof(*tx->witnesses));
		assert(witnesses);
		
		tx->witnesses = witnesses;
		const unsigned char * p_witnesses = p;
		for(ssize_t i = 0; i < tx->txin_count; ++i)
		{
			if(p >= p_end) message_parser_error_handler("parse witness data failed: %s.", "invalid payload length");
			
			ssize_t num_items = 0;
			p = parse_varint(p, p_end, &num_items);
			if(NULL == p) {
				message_parser_error_handler("parse witness data failed: %s.", 
					"invalid payload length");
			}
			
			witnesses[i].num_items = num_items;
			
			if(num_items > 0)
			{
				varstr_t ** items = calloc(num_items, sizeof(*items));
				assert(items);
				witnesses[i].items = items;
				
				for(ssize_t item_index = 0; item_index < num_items; ++item_index)
				{
					if(p >= p_end) {
						message_parser_error_handler("parse witness data failed: %s.", 
							"invalid payload length");
					}
					
					p = parse_varstr(p, p_end, &items[item_index]);
					if(NULL == p) {
						message_parser_error_handler("parse witness data failed: %s.", 
							"invalid payload length");
					}
				}
				
			}
		}
		tx->cb_witnesses = p - p_witnesses;
	}
	
	// parse lock_time
	if((p + sizeof(uint32_t)) > p_end)
		message_parser_error_handler("parse locktime failed: %s", "invalid payload length");
		
	tx->lock_time = *(uint32_t *)p;
	p += sizeof(uint32_t);
	
	return (p - (unsigned char *)payload);
label_error:
	satoshi_tx_cleanup(tx);
	return -1;
}

void bitcoin_tx_witness_cleanup(bitcoin_tx_witness_t * witness)
{
	if(NULL == witness) return;
	for(ssize_t ii = 0; ii < witness->num_items; ++ii)
	{
		free(witness->items[ii]);
	}
	free(witness->items);
	witness->items = NULL;
	witness->num_items = 0;
	return;
}

void satoshi_tx_cleanup(satoshi_tx_t * tx)
{
	if(NULL == tx) return;
	
	if(tx->has_flag && tx->witnesses)
	{
		for(ssize_t i = 0; i < tx->txin_count; ++i)
		{
			bitcoin_tx_witness_cleanup(&tx->witnesses[i]);
		}
		free(tx->witnesses);
		tx->witnesses = NULL;
	}
	
	if(tx->txins)
	{
		for(ssize_t i = 0; i < tx->txin_count; ++i)
		{
			satoshi_txin_cleanup(&tx->txins[i]);
		}
		free(tx->txins);
		tx->txins = NULL;
		tx->txin_count = 0;
	}
	if(tx->txouts)
	{
		for(ssize_t i = 0; i < tx->txout_count; ++i)
		{
			satoshi_txout_cleanup(&tx->txouts[i]);
		}
		free(tx->txouts);
		tx->txouts = NULL;
		tx->txout_count = 0;
	}
	
	
	return;
}

ssize_t satoshi_tx_serialize(const satoshi_tx_t * tx, unsigned char ** p_data)
{
	ssize_t txin_vint_size = varint_calc_size(tx->txin_count);
	ssize_t txout_vint_size = varint_calc_size(tx->txout_count);
	
	ssize_t txins_size = 0;
	ssize_t txouts_size = 0;
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		ssize_t cb = satoshi_txin_serialize(&tx->txins[i], NULL);
		assert(cb > 0);
		txins_size += cb;
	}
	for(ssize_t i = 0; i < tx->txout_count; ++i)
	{
		ssize_t cb = satoshi_txout_serialize(&tx->txouts[i], NULL);
		assert(cb > 0);
		txouts_size += cb;
	}
	
	ssize_t tx_size = sizeof(int32_t)	// version
		+ (tx->has_flag?2:0)			// witness data flags
		+ txin_vint_size
		+ txins_size
		+ txout_vint_size
		+ txouts_size
		+ (tx->has_flag?tx->cb_witnesses:0)
		+ sizeof(uint32_t)	// lock_time
		;
	if(NULL == p_data) return tx_size;
	
	unsigned char * payload = *p_data;
	if(NULL == payload)
	{
		payload = malloc(tx_size);
		assert(payload);
		*p_data = payload;
	}
	
	unsigned char * p = payload;
	unsigned char * p_end = p + tx_size;
	
	// version
	assert((p + sizeof(int32_t)) < p_end); 
	*(int32_t *)p = tx->version;
	p += sizeof(int32_t);
	
	// witness flags
	if(tx->has_flag)
	{
		assert((p + 2) < p_end);
		p[0] = 0;
		p[1] = 1;
		p += 2;
	}
	
	// txins
	assert((p + txin_vint_size) < p_end);
	varint_set((varint_t *)p, tx->txin_count);
	p += txin_vint_size;
	
	for(ssize_t i = 0; i < tx->txin_count; ++i)
	{
		assert(p < p_end);
		ssize_t cb = satoshi_txin_serialize(&tx->txins[i], &p);
		assert(cb > 0);
		p += cb;
	}
	
	// txouts
	assert((p + txout_vint_size) < p_end);
	varint_set((varint_t *)p, tx->txout_count);
	p += txout_vint_size;
	
	for(ssize_t i = 0; i < tx->txout_count; ++i)
	{
		assert(p < p_end);
		ssize_t cb = satoshi_txout_serialize(&tx->txouts[i], &p);
		assert(cb > 0);
		p += cb;
	}
	
	// witnesses data
	if(tx->has_flag)
	{
		assert(tx->cb_witnesses > 0 && tx->witnesses);
		unsigned char * p_witnesses = p;
		assert((p + tx->cb_witnesses) < p_end);
		
		bitcoin_tx_witness_t * witnesses = tx->witnesses;
		for(ssize_t i = 0; i < tx->txin_count; ++i)
		{
			// write items count
			ssize_t num_items = witnesses[i].num_items;
			varint_set((varint_t *)p, num_items);
			p += varint_size((varint_t *)p);
			
			if(num_items)
			{
				varstr_t ** items = witnesses[i].items;
				assert(items);
				
				for(ssize_t ii = 0; ii < num_items; ++ii)
				{
					varstr_t * item = items[ii];
					assert(item);
					ssize_t item_size = varstr_size(item);
					memcpy(p, item, item_size);
					p += item_size;
				}
			}
			
			assert((p_witnesses + tx->cb_witnesses) == p); 
		}
	}
	
	// lock_time
	assert((p + sizeof(uint32_t)) == p_end);
	*(uint32_t *)p = tx->lock_time;
	p += sizeof(uint32_t);
	
	assert((p - payload) == tx_size);
	return tx_size;
}

ssize_t satoshi_block_parse(satoshi_block_t * block, ssize_t length, const void * payload)
{
	assert(block && (length > 0) && payload);
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	satoshi_block_cleanup(block);	// clear old data
		
	// parse block header
	if((p + sizeof(struct satoshi_block_header)) > p_end) {
		message_parser_error_handler("parse block header failed: %s", "invalid payload length");
	}
	memcpy(&block->hdr, p, sizeof(struct satoshi_block_header));
	p += sizeof(struct satoshi_block_header);
	
	// calc block_hash
	hash256(payload, sizeof(struct satoshi_block_header), (uint8_t *)&block->hash);
	
	if(length == sizeof(struct satoshi_block_header)) // parse block header only
	{
		return sizeof(struct satoshi_block_header);
	}
	
	// parse txn_count
	ssize_t vint_size = varint_size((varint_t *)p);
	if((p + vint_size) > p_end) {
		message_parser_error_handler("parse txn_count failed: %s", "invalid payload length");
	}
	
	block->txn_count = varint_get((varint_t *)p);
	p += vint_size;
	
	if(block->txn_count <= 0) {
		message_parser_error_handler("invalid txn_count: %ld", (long)block->txn_count);
	}
	
	satoshi_tx_t * txns = calloc(block->txn_count, sizeof(*txns));
	assert(txns);
	block->txns = txns;
	
	for(ssize_t i = 0; i < block->txn_count; ++i)
	{
		if(p >= p_end) {
			message_parser_error_handler("parse tx[%d] failed: invalid payload length", (int)i);
		}
		ssize_t tx_size = satoshi_tx_parse(&block->txns[i], (p_end - p), p);
		if(tx_size <= 0) {
			message_parser_error_handler("parse tx[%d] failed: invalid payload data", (int)i);
		}
		p += tx_size;
	}
	
	assert(p <= p_end);
	ssize_t block_size = (p - (unsigned char *)payload);
	assert(block_size <= MAX_BLOCK_SERIALIZED_SIZE);
	
	return block_size;
	
label_error:
	satoshi_block_cleanup(block);
	return -1;
}
void satoshi_block_cleanup(satoshi_block_t * block)
{
	if(NULL == block) return;
	if(block->txns)
	{
		for(ssize_t i = 0; i < block->txn_count; ++i)
		{
			satoshi_tx_cleanup(&block->txns[i]);
		}
		free(block->txns);
		block->txns = NULL;
		block->txn_count = 0;
	}
	return;
}

ssize_t satoshi_block_serialize(const satoshi_block_t * block, unsigned char ** p_data)
{
	ssize_t vint_size = 0;
	ssize_t tx_size = 0;
	
	if(block->txn_count > 0) // full block
	{
		vint_size = varint_calc_size(block->txn_count);
		for(ssize_t i = 0; i < block->txn_count; ++i)
		{
			ssize_t cb = satoshi_tx_serialize(&block->txns[i], NULL);
			assert(cb > 0);
			tx_size += cb;
		}
	}

	ssize_t block_size = sizeof(struct satoshi_block_header)
		+ vint_size
		+ tx_size;
	assert(block_size <= MAX_BLOCK_SERIALIZED_SIZE);
	if(NULL == p_data) return block_size;
	
	unsigned char * payload = *p_data;
	if(NULL == payload)
	{
		payload = malloc(block_size);
		assert(payload);
		*p_data = payload;
	}
	
	unsigned char * p = payload;
	unsigned char * p_end = p + block_size;
	
	// block header
	assert((p + sizeof(struct satoshi_block_header)) <= p_end);
	memcpy(p, &block->hdr, sizeof(struct satoshi_block_header));
	p += sizeof(struct satoshi_block_header);
	if(p == p_end) return sizeof(struct satoshi_block_header);	// block header only
	
	// txns
	assert((p + vint_size) <= p_end);
	if(block->txn_count > 0)
	{
		varint_set((varint_t *)p, block->txn_count);
		p += vint_size;
		
		for(ssize_t i = 0; i < block->txn_count; ++i)
		{
			assert(p < p_end);
			ssize_t cb = satoshi_tx_serialize(&block->txns[i], &p);
			assert(cb > 0);
			p += cb;
		}
	}
	assert(p <= p_end);
	assert((p - payload) == block_size);
	return block_size;
}


#if defined(_TEST_SATOSHI_TYPES) && defined(_STAND_ALONE)
int main(int argc, char ** argv)
{
	
	return 0;
}
#endif
