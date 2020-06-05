#ifndef _SATOSHI_TYPES_H_
#define _SATOSHI_TYPES_H_

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


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
void uint256_reverse(uint256_t * u256);
ssize_t uint256_from_string(uint256_t * u256, int from_little_endian, const char * hex_string, ssize_t length);
char * uint256_to_string(const uint256_t * u256, int to_little_endian, char ** p_hex);


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
	
	ssize_t cb_scripts;
	unsigned char * scripts;

	// for coinbase txins only
	ssize_t cb_coinbase_script;
	const unsigned char * coinbase_scripts;
	
	// for standard txins
	ssize_t cb_signatures;
	const unsigned char * signatures;
	uint32_t hash_type;
	
	ssize_t cb_redeem_scripts;	// pubkey or redeem script
	const unsigned char * redeem_scripts;

	uint32_t sequence;
}satoshi_txin_t;

ssize_t satoshi_txin_parse(satoshi_txin_t * txin, ssize_t length, const void * payload);
ssize_t satoshi_txin_serialize(const satoshi_txin_t * txin, unsigned char ** p_data);
void satoshi_txin_cleanup(satoshi_txin_t * txin);

typedef struct satoshi_txout
{
	int64_t value;
	ssize_t cb_script;
	unsigned char * scripts;
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
