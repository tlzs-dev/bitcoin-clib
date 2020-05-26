#ifndef _BITCOIN_H_
#define _BITCOIN_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif


enum bitcoin_network_type
{
	bitcoin_network_default,
	bitcoin_network_mainnet,
	bitcoin_network_testnet,
	bitcoin_network_regtest,
};

enum bitcoin_address_prefix
{
	bitcoin_address_p2pkh = 0,
	bitcoin_address_p2sh = 5,
	bitcoin_address_wif = 0x80,				// 128
	bitcoin_address_xpub = 0x1EB28804,		// 0488b21e
	bitcoin_address_xprv = 0xE4AD8804,		// 0488ade4
	bitcoin_address_testnet_p2pkh = 0x6F, 	// 111
	bitcoin_address_testnet_p2sh = 0xC4, 	// 196
	bitcoin_address_testnet_wif = 0xEF, 	// 239
	bitcoin_address_tpub = 0xCF873504,		// 04358394
	bitcoin_address_tprv = 0x94833504,		// 04358394
	
	bitcoin_address_bech32 = 0x00016362, 	// "bc1\0"
	bitcoin_address_testnet_bech32 = 0x00016374,	// "tc1\0"
};

#ifdef __cplusplus
}
#endif

#endif
