#ifndef _BITCOIN_CONSENSUS_H_
#define _BITCOIN_CONSENSUS_H_

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers

/*
 * Copyright (c) 2020-2025 htc.chehw@gmail.com
 * base: 
 * 	https://github.com/bitcoin/bitcoin/blob/master/src/consensus/consensus.h 
 * 		eb7daf4 on Jul 27, 2018
 * 
 * 	https://github.com/bitcoin/bitcoin/blob/master/src/consensus/params.h
 * 		aaaaad6 on Dec 30, 2019
*/

// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>

#include "satoshi-types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BLOCK_SERIALIZED_SIZE	(4 * 1000 * 1000)
#define MAX_BLOCK_WEIGHT			(4 * 1000 * 1000)
#define MAX_BLOCK_SIGOPS_COST		((int64_t)80000)
#define COINBASE_MATURITY			100
#define WITNESS_SCALE_FACTOR		4
#define MIN_TRANSACTION_WEIGHT				((WITNESS_SCALE_FACTOR) * 60)	// 60 is the lower bound for the size of a valid serialized CTransaction
#define MIN_SERIALIZABLE_TRANSACTION_WEIGHT	((WITNESS_SCALE_FACTOR) * 10) 	// 10 is the lower bound for the size of a serialized CTransaction


/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
#define LOCKTIME_VERIFY_SEQUENCE	(1 << 0)
/** Use GetMedianTimePast() instead of nTime for end point timestamp. */
#define LOCKTIME_MEDIAN_TIME_PAST	(1 << 1)

//~ /* Params.h */
//~ #ifndef HAS_UINT256
//~ typedef uint8_t uint256[256];
//~ typedef uint256 uint256_t;
//~ #endif

enum bitcoin_deployment_pos
{
	bitcoin_deployment_pos_testdummy,
	
	// NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp or consensus/bitcoin_consensus.c
	bitcoin_deployment_pos_max_version_bits_deployments
};

typedef struct bip9_deployment
{
	/** Bit position to select the particular bit in nVersion. */
	int bit;

	/** Start MedianTime for version bits miner confirmation. Can be a date in the past */
	int64_t start_time;

	/** Timeout/expiry MedianTime for the deployment attempt. */
	int64_t timeout;

	/** Constant for nTimeout very far in the future. */
	// static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();
	// #define BIP9_DEPLOYMENT_NO_TIMEOUT	(INT64_MAX)

	/** Special value for nStartTime indicating that the deployment is always active.
	*  This is useful for testing, as it means tests don't need to deal with the activation
	*  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
	*  behaviour during activation cannot use this. */
	// static constexpr int64_t ALWAYS_ACTIVE = -1;
	// #define BIP9_DEPLOYMENT_ALWAYS_ACTIVE ((int64_t)-1)
}bip9_deployment_t;
extern const int64_t BIP9_DEPLOYMENT_NO_TIMEOUT;		// INT_MAX
extern const int64_t BIP9_DEPLOYMENT_ALWAYS_ACTIVE;		// -1

#ifndef _BITCOIN_CORE_VERSION
#define _BITCOIN_CORE_VERSION 20191230
#endif

#if _BITCOIN_CORE_VERSION <= 20191230
typedef struct bitcoin_params
{
	uint256_t genesis_block_hash;
	int subsidy_halving_interval;
	uint256_t bip16_exception;	///< Block hash that is excepted from BIP16 enforcement 
	int bip34_height;			///< Block height and hash at which BIP34 becomes active 
	uint256_t bip34_hash;
	int bip65_height;			/** Block height at which BIP65 becomes active */
	int bip66_height;			/** Block height at which BIP66 becomes active */
	int csv_height;				/** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
	
	/** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
	* Note that segwit v0 script rules are enforced on all blocks except the
	* BIP 16 exception blocks. */
	int segwit_height;

	/** Don't warn about unknown BIP 9 activations below this height.
	* This prevents us from warning about the CSV and segwit activations. */
	int min_bip9_warning_height;

	/**
	* Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
	* (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
	* Examples: 1916 for 95%, 1512 for testchains.
	*/
	uint32_t rule_change_activation_threshold;	//	nRuleChangeActivationThreshold;
	uint32_t miner_confirmation_window;			// 	nMinerConfirmationWindow;
	bip9_deployment_t * deployments[bitcoin_deployment_pos_max_version_bits_deployments];

	/** Proof of work parameters */
	uint256 pow_limit;		// powLimit;

	bool pow_allow_min_difficulty_blocks;	// fPowAllowMinDifficultyBlocks;
	bool pow_retargeting;					// fPowNoRetargeting;
	int64_t pow_target_spacing;				// nPowTargetSpacing;
	int64_t pow_target_timespan;			// nPowTargetTimespan;
	int64_t (* difficulty_adjustment_interval)(void); 	//DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
	uint256 minimium_chainwork;		//	nMinimumChainWork;
	uint256 default_assume_value;	// 	defaultAssumeValid;
}bitcoin_params_t;

const bitcoin_params_t * bitcoin_consensus_get_params(void);

#endif


#ifdef __cplusplus
}
#endif
#endif
