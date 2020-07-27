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



#include <ctype.h>		// for ptrdiff_t
#include <secp256k1.h>	// use https://github.com/bitcoin/bitcoin/tree/master/src/secp256k1

#include "utils.h"
#include "crypto.h"

/**
 * utils
 */
void hash256(const void * data, size_t length, uint8_t hash[32])
{
	sha256_ctx_t sha[1];
	uint8_t hash32[32];
	sha256_init(sha);
	sha256_update(sha, data, length);
	sha256_final(sha, hash32);
	
	sha256_init(sha);
	sha256_update(sha, hash32, 32);
	sha256_final(sha, hash);
}

void hash160(const void * data, size_t length, uint8_t hash[20])
{
	sha256_ctx_t sha[1];
	ripemd160_ctx_t ripemd[1];
	uint8_t hash32[32];
	
	sha256_init(sha);
	sha256_update(sha, data, length);
	sha256_final(sha, hash32);
	
	ripemd160_init(ripemd);
	ripemd160_update(ripemd, hash32, 32);
	ripemd160_final(ripemd, hash);
}



typedef struct crypto_context_private
{
	crypto_context_t * crypto;
	secp256k1_context * sign_ctx;		
	secp256k1_context * verify_ctx;
}crypto_context_private_t;


#define MAX_PUBKEY_DATA_LENGTH (65)

struct crypto_pubkey
{
	secp256k1_pubkey key[1];
	unsigned char data[MAX_PUBKEY_DATA_LENGTH];
	size_t cb_data;
	int compressed_flag;
};

struct crypto_signature
{
	secp256k1_ecdsa_signature ecsig[1];
	unsigned char sig_der[100];
	ssize_t cb_sig_der;
};

crypto_signature_t * crypto_signature_import(crypto_context_t * crypto, const unsigned char * sig_der, size_t length)
{
	assert(crypto && crypto->priv);
	assert(sig_der && length > 0);
	
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->verify_ctx;
	assert(secp);
	
	crypto_signature_t * sig = calloc(1, sizeof(*sig));
	assert(sig);
	
	int ok = secp256k1_ecdsa_signature_parse_der(secp, sig->ecsig, sig_der, length);
	if(ok <= 0)
	{
		free(sig);
		return NULL;
	}
	return sig;
}

crypto_signature_t * crypto_signature_import_from_string(crypto_context_t * crypto, const char * sig_der_hex)
{
	assert(sig_der_hex);
	ssize_t cb = strlen(sig_der_hex);
	assert(cb > 0 && 0 == (cb % 2) && cb < 200);
	
	unsigned char data[100] = { 0 };
	void * p_data = data;
	ssize_t cb_data = hex2bin(sig_der_hex, cb, &p_data);
	assert(cb_data == (cb / 2));
	
	crypto_signature_t * sig = crypto_signature_import(crypto, data, cb_data);
	return sig;
}


ssize_t crypto_signature_export(crypto_context_t * crypto, const crypto_signature_t * sig, unsigned char ** p_sig_der)
{
	assert(crypto && crypto->priv);
	assert(sig);
	
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->verify_ctx;
	assert(secp);
	
	if(sig->cb_sig_der <= 0)
	{
		size_t buf_size = sizeof(sig->sig_der);
		int ok = secp256k1_ecdsa_signature_serialize_der(secp, (unsigned char *)sig->sig_der, &buf_size, sig->ecsig);
		if(ok <= 0) return -1;
		
		*(ssize_t *)&sig->cb_sig_der = buf_size;	// ignore const modifier
	}
	
	assert(sig->cb_sig_der > 0);
	if(NULL == p_sig_der) return sig->cb_sig_der;
	
	unsigned char * sig_der = *p_sig_der;
	if(NULL == sig_der) 
	{
		sig_der = malloc(sig->cb_sig_der);
		assert(sig_der);
		* p_sig_der = sig_der;
	}
	
	memcpy(sig_der, sig->sig_der, sig->cb_sig_der);
	return sig->cb_sig_der;
}

void crypto_signature_free(crypto_signature_t * sig)
{
	free(sig);
}

#define PRIVKEY_SIZE (32)
struct crypto_privkey
{
	unsigned char key[PRIVKEY_SIZE];
	size_t length;
	struct crypto_pubkey pubkey[1];
};

const crypto_pubkey_t * crypto_privkey_get_pubkey(crypto_privkey_t * privkey)
{
	if(NULL == privkey || privkey->length != 32) return NULL;
	return privkey->pubkey;
}

crypto_privkey_t * crypto_privkey_import(crypto_context_t * crypto, const unsigned char * secdata, ssize_t length)
{
	assert(crypto && crypto->priv);
	assert(secdata && length <= 32);
	
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->sign_ctx;
	assert(secp);
	
	crypto_privkey_t * privkey = calloc(1, sizeof(*privkey));
	assert(privkey);
	
	memcpy(privkey->key, secdata, length);
	int ok = secp256k1_ec_seckey_verify(secp, privkey->key);
	if(!ok)
	{
		fprintf(stderr, "[ERROR]: invalid privkey data.");
		memset(privkey->key, 0, sizeof(privkey->key)); // clear sensitive data
		free(privkey);
		return NULL;
	}
	
	ok = secp256k1_ec_pubkey_create(secp, privkey->pubkey->key, privkey->key);
	if(!ok)
	{
		fprintf(stderr, "[ERROR]: calc pubkey failed.");
		memset(privkey->key, 0, sizeof(privkey->key)); // clear sensitive data
		free(privkey);
		return NULL;
	}
	
	privkey->length = PRIVKEY_SIZE;	// to confirm this is a valid key
	
	return privkey;
}
ssize_t crypto_privkey_export(crypto_context_t * crypto, const crypto_privkey_t * privkey, unsigned char ** p_secdata)
{
	assert(crypto && crypto->priv);
	assert(privkey);

	if(privkey->length != PRIVKEY_SIZE) return -1;	// invalid key
	if(NULL == p_secdata) return PRIVKEY_SIZE;		// return key length

	unsigned char * secdata = *p_secdata;
	if(NULL == secdata)
	{
		secdata = malloc(PRIVKEY_SIZE);
		assert(secdata);
		*p_secdata = secdata;
	}
	
	memcpy(secdata, privkey->key, PRIVKEY_SIZE);
	return PRIVKEY_SIZE;
}
void crypto_privkey_free(crypto_privkey_t * privkey)
{
	if(privkey)
	{
		memset(privkey->key, 0, sizeof(privkey->key));	// clear sensitive data
	}
	free(privkey);
}

crypto_privkey_t * crypto_privkey_import_from_string(crypto_context_t * crypto, const char * secdata_hex)
{
	assert(secdata_hex);
	ssize_t cb = strlen(secdata_hex);
	assert(cb > 0 && cb <= 64);
	
	unsigned char data[32] = { 0 };
	void * p_data = data;
	ssize_t cb_data = hex2bin(secdata_hex, cb, &p_data);
	assert(cb_data == (cb / 2));
	
	crypto_privkey_t * privkey = crypto_privkey_import(crypto, data, cb_data);
	memset(data, 0, sizeof(data));
	return privkey;
}

crypto_pubkey_t * crypto_pubkey_import(crypto_context_t * crypto, const unsigned char * pubkey_data, size_t length)
{
	assert(crypto && crypto->priv);
	assert(pubkey_data && length <= MAX_PUBKEY_DATA_LENGTH);
	
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->verify_ctx;
	assert(secp);
	
	crypto_pubkey_t * pubkey = calloc(1, sizeof(*pubkey));
	assert(pubkey);
	
	int ok = secp256k1_ec_pubkey_parse(secp, pubkey->key, pubkey_data, length);
	if(!ok)
	{
		fprintf(stderr, "[ERROR]: parse pubkey failed.");
		free(pubkey);
		return NULL;
	}
	return pubkey;
}
ssize_t crypto_pubkey_export(crypto_context_t * crypto, crypto_pubkey_t * pubkey, 
	int compressed_flag, unsigned char ** p_pubkey_data)
{
	assert(crypto && crypto->priv);
	assert(pubkey);
	
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->verify_ctx;
	
	int ok = 0;
	if(0 == pubkey->cb_data || compressed_flag != pubkey->compressed_flag)
	{
		pubkey->cb_data = sizeof(pubkey->data);
		ok = secp256k1_ec_pubkey_serialize(secp, 
			pubkey->data, &pubkey->cb_data, 
			pubkey->key, 
			compressed_flag?SECP256K1_EC_COMPRESSED:SECP256K1_EC_UNCOMPRESSED);
		if(!ok)
		{
			fprintf(stderr, "[ERROR]: serialize pubkey failed.");
			pubkey->cb_data = 0;
			return -1;
		}
		pubkey->compressed_flag = compressed_flag;
	}
	
	if(NULL == p_pubkey_data) return pubkey->cb_data;	// return data length
	
	assert(pubkey->cb_data > 0 && pubkey->cb_data < MAX_PUBKEY_DATA_LENGTH);
	unsigned char * pubkey_data = *p_pubkey_data;
	if(NULL == pubkey_data)
	{
		pubkey_data = malloc(pubkey->cb_data);
		assert(pubkey_data);
		
		*p_pubkey_data = pubkey_data;
	}
	memcpy(pubkey_data, pubkey->data, pubkey->cb_data);
	return pubkey->cb_data;
}
void crypto_pubkey_free(crypto_pubkey_t * pubkey)
{
	free(pubkey);
}

crypto_pubkey_t * crypto_pubkey_import_from_string(crypto_context_t * crypto, const char * pubkey_hex)
{
	assert(crypto && pubkey_hex);
	int cb_hex = strlen(pubkey_hex);
	assert(cb_hex == 66 || cb_hex == 130);
	
	unsigned char pubkey_data[65] = {0};
	void * p_data = pubkey_data;
	ssize_t cb_pubkey = hex2bin(pubkey_hex, cb_hex, (void **)&p_data);
	assert(cb_pubkey == 33 || cb_pubkey == 65);
	
	return crypto_pubkey_import(crypto, pubkey_data, cb_pubkey);
}


crypto_context_private_t * crypto_context_private_new(crypto_context_t * crypto)
{
	assert(crypto);
	crypto_context_private_t * priv = calloc(1, sizeof(*priv));
	assert(priv);
	
	priv->crypto = crypto;
	crypto->priv = priv;
	
	priv->sign_ctx = secp256k1_context_create(SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN);
	priv->verify_ctx = secp256k1_context_create(SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY);
	
	assert(priv->sign_ctx && priv->verify_ctx);
	
	return priv;
}

void crypto_context_private_free(crypto_context_private_t * priv)
{
	if(NULL == priv) return;
	if(priv->sign_ctx)
	{
		secp256k1_context_destroy(priv->sign_ctx);
		priv->sign_ctx = NULL;
	}
	if(priv->verify_ctx)
	{
		secp256k1_context_destroy(priv->verify_ctx);
		priv->verify_ctx = NULL;
	}
	free(priv);
	return;
}

static int crypto_sign(struct crypto_context * crypto, 
	const unsigned char * msg, size_t msg_len,
	const crypto_privkey_t * privkey, 
	unsigned char ** p_sig_der, ssize_t * p_cb_sig_der)
{
	assert(crypto && crypto->priv);
	assert(privkey && msg);
	assert(p_sig_der && p_cb_sig_der);
		
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->sign_ctx;
	assert(secp);
	
	secp256k1_ecdsa_signature sig[1];
	memset(sig, 0, sizeof(sig));
	
	int ok = secp256k1_ecdsa_sign(secp, sig, 
		(unsigned char *)msg, 
		privkey->key, 
		secp256k1_nonce_function_default, NULL);
	if(ok > 0) {
		unsigned char sig_buffer[100] = { 0 };
		size_t cb_buffer = sizeof(sig_buffer);
		
		ok = secp256k1_ecdsa_signature_serialize_der(secp, sig_buffer, &cb_buffer, sig);
		if(ok)
		{
			assert(cb_buffer > 0);
			*p_cb_sig_der = cb_buffer;
			unsigned char * sig_der = *p_sig_der;
			if(NULL == sig_der) {
				sig_der = malloc(cb_buffer);
				assert(sig_der);
				*p_sig_der = sig_der;
			}
			memcpy(sig_der, sig_buffer, cb_buffer);
			return 0;
		} 
	}
	return -1;
}
static int crypto_verify(struct crypto_context * crypto, 
	const unsigned char * msg, size_t msg_len,
	const crypto_pubkey_t * pubkey, 
	const unsigned char * sig_der, size_t cb_sig_der)
{
	assert(crypto && crypto->priv);
	assert(pubkey && msg && sig_der && cb_sig_der > 0);
		
	crypto_context_private_t * priv = crypto->priv;
	secp256k1_context * secp = priv->verify_ctx;
	assert(secp);
	
	secp256k1_ecdsa_signature sig[1];
	memset(sig, 0, sizeof(sig));
	
	int ok = 0;
	ok = secp256k1_ecdsa_signature_parse_der(secp, sig, sig_der, cb_sig_der);
	if(!ok)
	{
		fprintf(stderr, "[ERROR]: parse signature failed.\n");
		return -1;
	}
	
	ok = secp256k1_ecdsa_verify(secp, sig, 
		msg,
		pubkey->key);
	if(ok > 0) return 0;
	return -1;
}

crypto_context_t * crypto_context_init(crypto_context_t * crypto, enum crypto_backend_type * backend, void * user_data)
{
	assert(backend == crypto_backend_libsecp256);
	if(NULL == crypto) crypto = calloc(1, sizeof(* crypto));
	assert(crypto);
	
	crypto->user_data = user_data;
	crypto->sign = crypto_sign;
	crypto->verify = crypto_verify;
	
	crypto_context_private_t * priv = crypto_context_private_new(crypto);
	assert(priv && crypto->priv == priv);
	
	
	return crypto;
}
void crypto_context_cleanup(crypto_context_t * crypto)
{
	if(crypto)
	{
		crypto_context_private_free(crypto->priv);
		crypto->priv = NULL;
	}
	return;
}



#undef PRIVKEY_SIZE

#if defined(_TEST_CRYPTO) && defined(_STAND_ALONE)

void test_encrypt();
void test_sign_and_verify();

int main(int argc, char **argv)
{
//	test_encrypt(argc, argv);
	test_sign_and_verify(argc, argv);
	return 0;
}

/**************************************************************************
 * test_encrypt
 *************************************************************************/
void test_encrypt(int argc, char ** argv)
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
}


/**************************************************************************
 * test_sign_and_verify
 *************************************************************************/
#define AUTO_FREE_PTR __attribute__((cleanup(auto_free_ptr))) 
void auto_free_ptr(void * ptr)
{
	void * p = *(void **)ptr;
	if(p)
	{
		free(p);
		*(void **)ptr = NULL;
	}
}

#define AUTO_FREE_PRIVKEY __attribute__((cleanup(auto_free_crypto_privkey)))
void auto_free_crypto_privkey(void * ptr)
{
	crypto_privkey_t * privkey = *(void **)ptr;
	if(privkey)
	{
		crypto_privkey_free(privkey);
		*(void **)ptr = NULL;
	}
}

#define AUTO_FREE_PUBKEY __attribute__((cleanup(auto_free_crypto_pubkey)))
void auto_free_crypto_pubkey(void * ptr)
{
	crypto_pubkey_t * pubkey = *(void **)ptr;
	if(pubkey)
	{
		crypto_pubkey_free(pubkey);
		*(void **)ptr = NULL;
	}
}

static void prepare_data(
	unsigned char rawtx_hash[/* 32 */],
	unsigned char ** p_pubkey_data, ssize_t * p_cb_pubkey_data,
	unsigned char ** p_sig_der, ssize_t * p_cb_sig_der)
{
	// use tx_data from satoshi-script.c::TEST::txns[1]
	// calculated by tests/test_satoshi-script
	static const char * rawtx_hash_hex = "e6d9603313a33b0b0e34f19247c9cc3d56052c6f4e9184fb4cc7cf73e7f8cd6a";
	
	static const char * pubkey_hex 	// satoshi-script.c::TEST::txns[1].txins[0].pubkey
			= "031a455dab5e1f614e574a2f4f12f22990717e93899695fb0d81e4ac2dcfd25d00";	
	
	static const char * sig_der_hex // satoshi-script.c::TEST::txns[1].txins[0].signatures
		= "3044"
			"022048d1468895910edafe53d4ec4209192cc3a8f0f21e7b9811f83b5e419bfb57e0"
			"02203fef249b56682dbbb1528d4338969abb14583858488a3a766f609185efe68bca";
			
	ssize_t cb_hash = hex2bin(rawtx_hash_hex, -1, (void **)&rawtx_hash);
	assert(cb_hash == 32);
	
	*p_cb_pubkey_data = hex2bin(pubkey_hex, -1, (void **)p_pubkey_data);
	*p_cb_sig_der = hex2bin(sig_der_hex, -1, (void **)p_sig_der);
	
	assert(*p_pubkey_data && *p_sig_der);
	return;
}

void test_sign_and_verify(int argc, char ** argv)
{
	int rc = 0;
// test1.  verify():
	unsigned char rawtx_hash[32] = { 0 };
	unsigned char * pubkey_data = NULL;
	unsigned char * sig_der = NULL;
	ssize_t cb_pubkey = 0;
	ssize_t cb_sig_der = 0;
	
	prepare_data(rawtx_hash, 
		&pubkey_data, &cb_pubkey,
		&sig_der, &cb_sig_der);
	
	// test verify():
	crypto_context_t * crypto = crypto_context_init(NULL, crypto_backend_libsecp256, NULL);
	assert(crypto);
	
	crypto_pubkey_t * pubkey = crypto_pubkey_import(crypto, pubkey_data, cb_pubkey);
	assert(pubkey);
	
	rc = crypto->verify(crypto, rawtx_hash, 32, 
		pubkey, 
		sig_der, cb_sig_der);
	assert(0 == rc);
	printf("verify txns[1]: [OK]\n");
	
	// cleanup
	crypto_pubkey_free(pubkey); pubkey = NULL;

	free(pubkey_data); pubkey_data = NULL;
	free(sig_der); sig_der = NULL;
	
	
// test2. sign and verify
	unsigned char sec_data[32] = {	// Pseudo-privkey
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
	};
	
	AUTO_FREE_PRIVKEY crypto_privkey_t * privkey = crypto_privkey_import(crypto, sec_data, 32);
	assert(privkey);
	
	pubkey = (crypto_pubkey_t *)crypto_privkey_get_pubkey(privkey);
	assert(pubkey);
	
	rc = crypto->sign(crypto, rawtx_hash, 32,
		privkey, &sig_der, &cb_sig_der);
	assert(0 == rc);
	printf("sign: [OK]\n");
	
	rc = crypto->verify(crypto, rawtx_hash, 32,
		pubkey, sig_der, cb_sig_der);
	assert(0 == rc);
	printf("verify: [OK]\n");
	
	free(sig_der); sig_der = NULL;
	
	crypto_context_cleanup(crypto);
	free(crypto);
	return;
}
#endif
