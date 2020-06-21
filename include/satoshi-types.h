#ifndef _SATOSHI_TYPES_H_
#define _SATOSHI_TYPES_H_

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/**
 * varint
 * @defgroup varint
 * Integer can be encoded depending on the represented value to save space. 
 * Variable length integers always precede an array/vector of a type of data that may vary in length. 
 * Longer numbers are encoded in little endian.
 * 
 *    Value	Storage length	Format
 *    (< 0xFD)	1	uint8_t
 *    (<= 0xFFFF)	3	0xFD followed by the length as uint16_t
 *    (<= 0xFFFF FFFF)	5	0xFE followed by the length as uint32_t
 *    else	9	0xFF followed by the length as uint64_t
 * 
 * @{
 * @}
 * 
 */
 
 /**
  * @ingroup varint
  */
typedef struct varint
{
	unsigned char vch[1];
}varint_t;
size_t varint_calc_size(uint64_t value);

/**
  * @ingroup varint
  * @{
  */
varint_t * varint_new(uint64_t value);
void varint_free(varint_t * vint);

size_t varint_size(const varint_t * vint);
varint_t * varint_set(varint_t * vint, uint64_t value);
uint64_t varint_get(const varint_t * vint);

/**
 * @}
 */


/**
 * varstr
 * @defgroup varstr
 * 
 * @{
 * @}
 */
 
 
/**
 * @ingroup varstr
 */
typedef struct varstr
{
	unsigned char vch[1];
}varstr_t;
extern const varstr_t varstr_empty[1];

/**
 * @ingroup varstr
 */
varstr_t * varstr_new(const unsigned char * data, size_t length);
void varstr_free(varstr_t * vstr);
varstr_t * varstr_resize(varstr_t * vstr, size_t new_size);
varstr_t * varstr_clone(const varstr_t * vstr);

size_t varstr_size(const varstr_t * vstr);
varstr_t * varstr_set(varstr_t * vstr, const unsigned char * data, size_t length);
//~ size_t varstr_length(const varstr_t * vstr);
size_t varstr_get(const varstr_t * vstr, unsigned char ** p_data, size_t buf_size);

#define varstr_length(vstr)			varint_get((varint_t *)vstr)
#define varstr_getdata_ptr(vstr) 	((unsigned char *)vstr + varint_size((varint_t *)vstr))
/**
 * @}
 */


#ifndef HAS_UINT256
#define HAS_UINT256
typedef struct uint256
{
	uint8_t val[32];
}uint256, uint256_t;
#endif
//~ extern const uint256_t uint256_zero[1];
#define uint256_zero (&(uint256_t){{0}})

void uint256_reverse(uint256_t * u256);
ssize_t uint256_from_string(uint256_t * u256, int from_little_endian, const char * hex_string, ssize_t length);
char * uint256_to_string(const uint256_t * u256, int to_little_endian, char ** p_hex);


/**
 * @defgroup compact_int
 *  Use a 32-bit integer(little-endian) to approximate a 256-bit integer.
 * 
 * @details 
 *  The Bitcoin network has a global block difficulty. 
 *  Valid blocks must have a hash below this target. 
 *  The target is a 256-bit number (extremely large) that all Bitcoin clients share. 
 *  The dSHA256 hash of a block's header must be lower than or equal to the current target 
 *  for the block to be accepted by the network. 
 *  The lower the target, the more difficult it is to generate a block.
 * 
 *  It should be noted here that, the dSHA256 hash value SHOULD be regarded as little-endian.
 * 	(Perhaps to avoid confusion, the designer specified all integers as little-endian.)
 * 	 
 *  The target value was stored in a compact format(uint32_t) int the 'bit' field of block header. 
 *  --> the lower 24 bits represent an signed integer value, and must be positive (the highest bit cannot be 1).
 *      When converting from an 'uint256_t', if the lower24 bits value is negative, 
 *      then need to add an extra 0 to the hightest byte (need to borrow a 0 from the tailing-zeros of the uint256)
 *  --> the upper 8 bits indicate that how many bytes remained 
 * 		after removing the tailing-0s(if regarded as big-endian) or leading-0s(if regarded as little-endian)
 * 
 *  for example:
 * 	    bits: 0x 1b 0404cb
 * 	    target= (0x0404cb << ((0x1b - 3) * 8))
 * 		TARGET= 0x0000000000 0404CB (000000000000000000000000000000000000000000000000)
 * 		dSHA256=  (000000000000000000000000000000000000000000000000) CB0404 0000000000
 *	 PS. The parts enclosed in parentheses are ignored. (not used when calculating the target)
 * @{
 * @}
 */
union compact_uint256
{
	uint32_t bits;		// 
	struct
	{
		uint8_t mantissa[3]; 
		uint8_t exp;
	}__attribute__((packed));
}__attribute__((packed));

typedef union compact_uint256 compact_uint256_t;
compact_uint256_t uint256_to_compact(const uint256_t * target);
uint256_t compact_to_uint256(const compact_uint256_t * cint);

#define compact_uint256_zero 	((compact_uint256_t){.exp = 0, })
#define compact_uint256_NaN 	((compact_uint256_t){.exp = 0xff, })	// Not a Number

#define uint256_NaN	((uint256_t){.val = {						\
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 		\
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,			\
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,			\
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }})

// The highest possible target (difficulty 1) is defined as 0x1d00ffff
#define compact_uint256_difficulty_one  ((compact_uint256_t){.bits = 0x1d00ffff, })
#define uint256_difficulty_one ((uint256_t){.val = {			\
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 		\
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,			\
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,			\
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }})
/**
 * helpler functions to calculate difficulty.
 * 
 * 	compact_int_div(): use to calc bdiff
 * 	uint256_div():     use to calc pdiff
 * 
 * For the explanation of 'bdiff' and 'pdiff', please refer to 'https://en.bitcoin.it/wiki/Difficulty'
 */
double compact_uint256_div(const compact_uint256_t * restrict n, const compact_uint256_t * restrict d);
double uint256_div(const uint256_t * restrict n, const uint256_t * restrict d);

/**
 * compare functions:
 * @return 
 *   <0 if (a  < b);
 *   =0 if (a == b);
 *   >0 if (a  > b);
 * 
 * @{
 */
int compact_uint256_compare(const compact_uint256_t * restrict a, const compact_uint256_t * restrict b);
int uint256_compare(const uint256_t * restrict a, const uint256_t * restrict b);
int uint256_compare_with_compact(const uint256_t * restrict hash, const compact_uint256_t * restrict target);
/**
 * @}
 */

/**
 * @defgroup merkle_tree
 * @{
 * @}
 */
typedef struct uint256_merkle_tree
{
	void * user_data;
	void * priv;
	
	ssize_t max_size;
	ssize_t count;
	uint256 merkle_root;
	uint256 * items;
	int levels;
	
	void (* hash_func)(const void *data, size_t size, uint8_t hash[]);
	int (* add)(struct uint256_merkle_tree * mtree, int count, const uint256 * items);
	int (* remove)(struct uint256_merkle_tree * mtree, int index);
	int (* set)(struct uint256_merkle_tree * mtree, int index, const uint256 item);
	
	int (* recalc)(struct uint256_merkle_tree * mtree, int start_index, int count);
}uint256_merkle_tree_t;
uint256_merkle_tree_t * uint256_merkle_tree_new(ssize_t max_size, void * user_data);
void uint256_merkle_tree_free(uint256_merkle_tree_t * mtree);


/**
 * @ingroup satoshi_tx
 * 
 */
typedef struct satoshi_outpoint
{
	uint8_t prev_hash[32];
	uint32_t index;
}satoshi_outpoint_t;

typedef struct satoshi_txin
{
	satoshi_outpoint_t outpoint;
	int is_coinbase;	// coinbase flag
	int is_p2sh;		// p2sh flag
	
	varstr_t * scripts;
	ssize_t cb_scripts;	// hold scripts length
	uint32_t sequence;
	
	// The following fields will be set during satoshi_script->parse()
	ssize_t num_signatures;	
	varstr_t ** signatures;

	varstr_t * redeem_scripts; 	// { (varint_length) , (pubkey or redeem script) }
	
	/**
	 * redeem_scripts_start_pos: The position after the most recently-executed op_codeseparator.
	 * 
	 * According to 'https://en.bitcoin.it/wiki/Script': 
	 * "All of the signature checking words will only match signatures 
	 * to the data after the most recently-executed OP_CODESEPARATOR."
	 * 
	 * This means if any op_codeseparator exists in the redeem_scripts,  
	 * the data required by the next checksig-ops will start 
	 * from the most recently-executed op_codeseparator.
	 */
	ptrdiff_t redeem_scripts_start_pos;
	
}satoshi_txin_t;

ssize_t satoshi_txin_parse(satoshi_txin_t * txin, ssize_t length, const void * payload);
ssize_t satoshi_txin_serialize(const satoshi_txin_t * txin, unsigned char ** p_data);
void satoshi_txin_cleanup(satoshi_txin_t * txin);
varstr_t * satoshi_txin_get_redeem_scripts(const satoshi_txin_t * txin);
ssize_t satoshi_txin_query_redeem_scripts_data(const satoshi_txin_t * txin, const unsigned char ** p_data);
varstr_t * satoshi_txin_set_redeem_scripts(satoshi_txin_t * txin, const unsigned char * data, size_t length);

enum satoshi_txout_type
{
	satoshi_txout_type_unknown = 0,
	satoshi_txout_type_legacy = 1,
	satoshi_txout_type_segwit = 2,	// native p2wphk or p2wsh
	
	satoshi_txout_type_masks = 0x7FFF,
	satoshi_txout_type_p2sh_segwit_flags = 0x8000,	// (p2sh --> p2wphk or p2wsh)
};

typedef struct satoshi_txout
{
	int64_t value;
	varstr_t * scripts;
	enum satoshi_txout_type flags;			// 0: a legacy-utxo, 1: a segwit-utxo
}satoshi_txout_t;
ssize_t satoshi_txout_parse(satoshi_txout_t * txout, ssize_t length, const void * payload);
ssize_t satoshi_txout_serialize(const satoshi_txout_t * txout, unsigned char ** p_data);
void satoshi_txout_cleanup(satoshi_txout_t * txout);


/*
 * A witness field starts with a var_int to indicate the number of stack items for the txin. 
 * It is followed by stack items, with each item starts with a var_int to indicate the length. 
 * Witness data is NOT script.
 */
typedef struct bitcoin_tx_witness
{
	ssize_t num_items;	//
	varstr_t ** items; 
}bitcoin_tx_witness_t;

typedef struct satoshi_tx
{
	int32_t version;
	int has_flag;	// with witness 
	uint8_t flag[2]; // If present, always 0001, and indicates the presence of witness data
	ssize_t txin_count;
	satoshi_txin_t * txins;
	
	ssize_t txout_count;
	satoshi_txout_t * txouts;
	
	ssize_t cb_witnesses;		// witnesses data serialized length (in bytes)
	bitcoin_tx_witness_t * witnesses;
	uint32_t lock_time;
	
}satoshi_tx_t;
ssize_t satoshi_tx_parse(satoshi_tx_t * tx, ssize_t length, const void * payload);
void satoshi_tx_cleanup(satoshi_tx_t * tx);
ssize_t satoshi_tx_serialize(const satoshi_tx_t * tx, unsigned char ** p_data);

struct satoshi_block_header
{
	int32_t version;
	uint8_t prev_hash[32];
	uint8_t merkle_root[32];
	uint32_t timestamp;
	uint32_t bits;
	uint32_t nounce;
	uint8_t txn_count[0];	// place-holder
}__attribute__((packed));

typedef struct satoshi_block
{
	struct satoshi_block_header hdr;
	ssize_t txn_count;
	satoshi_tx_t * txns;
	
	uint256_t hash;
}satoshi_block_t;
ssize_t satoshi_block_parse(satoshi_block_t * block, ssize_t length, const void * payload);
void satoshi_block_cleanup(satoshi_block_t * block);
ssize_t satoshi_block_serialize(const satoshi_block_t * block, unsigned char ** p_data);


#define BITCOIN_MESSAGE_MAGIC_MAINNET 	0xD9B4BEF9
#define BITCOIN_MESSAGE_MAGIC_TESTNET 	0xDAB5BFFA
#define BITCOIN_MESSAGE_MAGIC_TESTNET3 	0x0709110B
#define BITCOIN_MESSAGE_MAGIC_NAMECOIN	0xFEB4BEF9

enum bitcoin_message_type	// command
{
	bitcoin_message_type_unknown = 0,
	bitcoin_message_type_version = 1,
	bitcoin_message_type_verack,
	bitcoin_message_type_addr,
	bitcoin_message_type_inv,
	bitcoin_message_type_getdata,
	bitcoin_message_type_notefound,
	bitcoin_message_type_getblocks,
	bitcoin_message_type_getheaders,
	bitcoin_message_type_tx,
	bitcoin_message_type_block,
	bitcoin_message_type_headers,
	bitcoin_message_type_getaddr,
	bitcoin_message_type_mempool,
	bitcoin_message_type_checkorder,
	bitcoin_message_type_submitorder,
	bitcoin_message_type_reply,
	bitcoin_message_type_ping, 
	bitcoin_message_type_pong,
	bitcoin_message_type_reject,
	bitcoin_message_type_filterload,
	bitcoin_message_type_filteradd,
	bitcoin_message_type_filterclear,
	bitcoin_message_type_merkle_block,
	bitcoin_message_type_alert,
	bitcoin_message_type_sendheaders,
	bitcoin_message_type_feefilter,
	bitcoin_message_type_sendcmpct,
	bitcoin_message_type_cmpctblock,
	bitcoin_message_type_getblocktxn,
	bitcoin_message_type_blocktxn,
	//
};

struct bitcoin_message_header
{
	uint32_t magic;
	char command[12];
	uint32_t length;
	uint32_t checksum;
	uint8_t payload[0];
}__attribute__((packed));

typedef struct bitcoin_message
{
	struct bitcoin_message_header hdr;
	
	enum bitcoin_message_type msg_type;
	void * msg;
	
	void * user_data;
	void * priv;
	// public function
	enum bitcoin_message_type (* parse)(struct bitcoin_message * msg, uint32_t length, const void * payload);
	ssize_t (* serialize)(const struct bitcoin_message * msg, unsigned char ** p_data);
	void (* cleanup)(struct bitcoin_message * msg);
	
}bitcoin_message_t;

bitcoin_message_t * bitcoin_message_new(void * user_data);
void bitcoin_message_free(bitcoin_message_t * msg);

enum bitcoin_message_type bitcoin_message_parse(struct bitcoin_message * msg, uint32_t length, const void * payload);
void bitcoin_message_serialize(const struct bitcoin_message * msg);
void bitcoin_message_cleanup(struct bitcoin_message * msg);

struct bitcoin_network_address_legacy
{
	uint64_t services;
	char ip[16];
	uint16_t port;
};

struct bitcoin_network_address
{
	uint32_t time; 		// if protocol.version >= 31402
	uint64_t services;	// same service(s) listed in version
	char ip[16];	// IPv6 or IPv4-mapped IPv6 address
	uint16_t port;	// network byte order
}__attribute__((packed));

enum bitcoin_inventory_type
{
	bitcoin_inventory_type_error = 0,
	bitcoin_inventory_type_msg_tx = 1,
	bitcoin_inventory_type_msg_filter_block = 2,
	bitcoin_inventory_type_cmpct_block = 3,
	
	bitcoin_inventory_type_size = UINT32_MAX
};

struct bitcoin_inventory
{
	uint32_t type;
	uint8_t hash[32];
};


/** @todo: BIP: 152
 * https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
  Layer: Peer Services
  Title: Compact Block Relay
*/
enum bitcoin_message_service_type
{
	bitcoin_message_service_type_node_network = 1,	// full node
	bitcoin_message_service_type_node_getutxo = 2,	// bip 0064
	bitcoin_message_service_type_node_bloom = 4,	// bip 0111
	bitcoin_message_service_type_node_witness = 8, 	// bip 0144
	bitcoin_message_service_type_node_network_limited = 1024, // bip 0159
	
	bitcoin_message_service_type_size = UINT64_MAX,	// place holder
};
struct bitcoin_message_version
{
	int32_t version;
	uint64_t services;	// enum bitcoin_message_service_type
	int64_t timestamp;
	struct bitcoin_network_address_legacy addr_recv;
// Fields below require version ≥ 106
	struct bitcoin_network_address_legacy addr_from;
	uint64_t nounce;

// variable length data
	varstr_t * user_agent; // (0x00 if string is 0 bytes long)
	int32_t start_height;	// The last block received by the emitting node
// Fields below require version ≥ 70001
	uint8_t relay;	// bool
};
struct bitcoin_message_version * bitcoin_message_version_parse(struct bitcoin_message_version * msg, uint32_t length, const uint8_t * payload);
void bitcoin_message_version_cleanup(struct bitcoin_message_version * msg);
ssize_t bitcoin_message_version_serialize(const struct bitcoin_message_version *msg, unsigned char ** p_data);

struct bitcoin_message_addr
{
	// varint_t * count;
	ssize_t count;	// <-- varint 
	struct bitcoin_network_address * addrs;
};
struct bitcoin_message_addr * bitcoin_message_addr_parse(struct bitcoin_message_addr * msg, uint32_t length, const uint8_t * payload);
void bitcoin_message_addr_cleanup(struct bitcoin_message_addr * msg);
ssize_t bitcoin_message_addr_serialize(const struct bitcoin_message_addr * msg, unsigned char ** p_data);

// https://en.bitcoin.it/wiki/Protocol_documentation
#define BITCOIN_MESSAGE_MAX_PAYLOAD_ENTRIES (50000)

struct bitcoin_message_inv
{
	ssize_t count;
	struct bitcoin_inventory * inventories;
};
struct bitcoin_message_inv * bitcoin_message_inv_parse(struct bitcoin_message_inv * msg, uint32_t length, const uint8_t * payload);
void bitcoin_message_inv_cleanup(struct bitcoin_message_inv * msg);
ssize_t bitcoin_message_inv_serialize(const struct bitcoin_message_inv * msg, unsigned char ** p_data);

struct bitcoin_message_getdata
{
	ssize_t count;
	struct bitcoin_inventory * inventories;
};
struct bitcoin_message_getdata * bitcoin_message_getdata_parse(struct bitcoin_message_getdata * msg, uint32_t length, const uint8_t payload);
void bitcoin_message_getdata_cleanup(struct bitcoin_message_getdata * msg);
ssize_t bitcoin_message_getdata_serialize(const struct bitcoin_message_getdata * msg, unsigned char ** p_data);

struct bitcoin_message_notfound
{
	ssize_t count;
	struct bitcoin_inventory * inventories;
};

struct bitcoin_message_notfound * bitcoin_message_notfound_parse(struct bitcoin_message_notfound * msg, uint32_t length, const uint8_t payload);
void bitcoin_message_notfound_cleanup(struct bitcoin_message_notfound * msg_notfound);


struct bitcoin_message_getblocks
{
	uint32_t version;
	ssize_t hash_count;
	uint256_t * hashes;
	uint256_t hash_stop;
};

struct bitcoin_message_getblocks * bitcoin_message_getblocks_parse(struct bitcoin_message_getblocks * msg, uint32_t length, const uint8_t payload);
void bitcoin_message_getblocks_cleanup(struct bitcoin_message_getblocks * msg);



struct bitcoin_message_getheaders
{
	uint32_t version;
	ssize_t hash_count;
	uint256_t * hashes;
	uint256_t hash_stop;
};

struct bitcoin_message_getheaders * bitcoin_message_getheaders_parse(struct bitcoin_message_getheaders * msg, uint32_t length, const uint8_t payload);
void bitcoin_message_getheaders_cleanup(struct bitcoin_message_getheaders * msg);

typedef struct satoshi_tx bitcoin_message_tx_t;
#define bitcoin_message_tx_parse 		satoshi_tx_parse
#define bitcoin_message_tx_cleanup 		satoshi_tx_cleanup



#ifdef __cplusplus
}
#endif

#endif
