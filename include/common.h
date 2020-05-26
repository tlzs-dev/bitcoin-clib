// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <endian.h>
#include <byteswap.h>

#ifndef bswap_16
#define bswap_16(x) (uint16_t)(((uint16_t)(x) >> 8) | (((uint16_t)(x) & 0x00ff) << 8))
#endif

#ifndef bswap_32
#define bswap_32(x) (uint32_t)(						\
		    (((uint32_t)(x) & 0xff000000U) >> 24) 		\
		  | (((uint32_t)(x) & 0x00ff0000U) >>  8) 		\
		  | (((uint32_t)(x) & 0x0000ff00U) <<  8) 		\
		  | (((uint32_t)(x) & 0x000000ffU) << 24)		\
		)
#endif

#ifndef bswap_64
#define bswap_64(x) (uint64_t)(									\
		    (((uint64_t)(x) & 0xff00000000000000ull) >> 56)		\
		  | (((uint64_t)(x) & 0x00ff000000000000ull) >> 40)		\
		  | (((uint64_t)(x) & 0x0000ff0000000000ull) >> 24)		\
		  | (((uint64_t)(x) & 0x000000ff00000000ull) >> 8)			\
		  | (((uint64_t)(x) & 0x00000000ff000000ull) << 8)			\
		  | (((uint64_t)(x) & 0x0000000000ff0000ull) << 24)		\
		  | (((uint64_t)(x) & 0x000000000000ff00ull) << 40)		\
		  | (((uint64_t)(x) & 0x00000000000000ffull) << 56)		\
		)
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	#ifndef htobe16
	#define htobe16(x)	bswap_16(x)
	#endif 

	#ifndef htole16 
	#define htole16(x) (uint16_t)(x)
	#endif

	#ifndef be16toh
	#define be16toh(x)	bswap_16(x)
	#endif

	#ifndef le16toh
	#define le16toh(x)	(uint16_t)(x)
	#endif

	#ifndef htobe32
	#define htobe32(x) 	bswap_32(x)
	#endif

	#ifndef htole32
	#define htole32(x)	(uint32_t)(x)
	#endif

	#ifndef be32toh
	#define be32toh(x)	bswap_32(x)
	#endif

	#ifndef le32toh
	#define le32toh(x)	(uint32_t)(x)
	#endif

	#ifndef htobe64
	#define htobe64(x)	bswap_64(x)
	#endif

	#ifndef htole64
	#define htole64(x)	(uint64_t)(x)
	#endif

	#ifndef be64toh
	#define be64toh(x)	bswap_64(x)
	#endif

	#ifndef le64toh
	#define le64toh(x)	(uint64_t)(x)
	#endif
#else 	// else if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	#ifndef htole16
	#define htole16(x)	bswap_16(x)
	#endif 

	#ifndef htobe16 
	#define htobe16(x) (uint16_t)(x)
	#endif

	#ifndef le16toh
	#define le16toh(x)	bswap_16(x)
	#endif

	#ifndef be16toh
	#define be16toh(x)	(uint16_t)(x)
	#endif

	#ifndef htole32
	#define htole32(x) 	bswap_32(x)
	#endif

	#ifndef htobe32
	#define htobe32(x)	(uint32_t)(x)
	#endif

	#ifndef le32toh
	#define le32toh(x)	bswap_32(x)
	#endif

	#ifndef be32toh
	#define be32toh(x)	(uint32_t)(x)
	#endif

	#ifndef htole64
	#define htole64(x)	bswap_64(x)
	#endif

	#ifndef htobe64
	#define htobe64(x)	(uint64_t)(x)
	#endif

	#ifndef le64toh
	#define le64toh(x)	bswap_64(x)
	#endif

	#ifndef be64toh
	#define be64toh(x)	(uint64_t)(x)
	#endif
#endif	// __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

uint16_t static inline ReadLE16(const unsigned char* ptr)
{
    return le16toh(*((uint16_t*)ptr));
}

uint32_t static inline ReadLE32(const unsigned char* ptr)
{
    return le32toh(*((uint32_t*)ptr));
}

uint64_t static inline ReadLE64(const unsigned char* ptr)
{
    return le64toh(*((uint64_t*)ptr));
}

void static inline WriteLE16(unsigned char* ptr, uint16_t x)
{
    *((uint16_t*)ptr) = htole16(x);
}

void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
    *((uint32_t*)ptr) = htole32(x);
}

void static inline WriteLE64(unsigned char* ptr, uint64_t x)
{
    *((uint64_t*)ptr) = htole64(x);
}

uint32_t static inline ReadBE32(const unsigned char* ptr)
{
    return be32toh(*((uint32_t*)ptr));
}

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
    return be64toh(*((uint64_t*)ptr));
}

void static inline WriteBE32(unsigned char* ptr, uint32_t x)
{
    *((uint32_t*)ptr) = htobe32(x);
}

void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    *((uint64_t*)ptr) = htobe64(x);
}


#ifdef __cplusplus
}
#endif

#endif // BITCOIN_CRYPTO_COMMON_H
