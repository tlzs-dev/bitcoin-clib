/*
 * blockchain.c
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

#include "bitcoin-consensus.h"
#include "satoshi-types.h"
#include "utils.h"

#include "blockchain.h"

#include <search.h>
#include <db.h>

#define BLOCKCHAIN_ALLOC_SIZE			(65536)

typedef struct utxo_db_private
{
	bitcoin_utxo_db_t * db;
	// priv
	char db_name[200];
	DB_ENV * env;
	DB * dbp;	// primary db, indexed by outpoint
	DB * sdbp;	// secondary db,  indexed by block_hash
	ssize_t count;
}utxo_db_private_t;

typedef struct block_db_private
{
	bitcoin_blocks_db_t * db;
	char db_name[200];
	DB_ENV * env;
	DB * dbp;
	ssize_t count;
}block_db_private_t;


