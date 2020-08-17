TARGET=unit-test

DEBUG ?= 1
VERBOSE ?= 7
OPTIMIZE ?= -O2

CC=gcc -std=gnu99 -Wall -D_GNU_SOURCE
LINKER=gcc -std=gnu99 -Wall -D_GNU_SOURCE

CFLAGS = -I../include
LIBS = -lm -lpthread -ljson-c -ldb 
LIBS += -lgmp

ifeq ($(DEBUG),1)
CFLAGS += -g -D_DEBUG
OPTIMIZE=-O0
endif

LINKER += $(OPTIMIZE)

SRC_DIR := ../src
OBJ_DIR := ../obj

BASE_SRC_DIR = $(SRC_DIR)/base
BASE_OBJ_DIR = $(OBJ_DIR)/base

UTILS_SRC_DIR = $(SRC_DIR)/utils
UTILS_OBJ_DIR = $(OBJ_DIR)/utils

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

BASE_SOURCES := $(wildcard $(BASE_SRC_DIR)/*.c)
BASE_OBJECTS := $(BASE_SOURCES:$(BASE_SRC_DIR)/%.c=$(BASE_OBJ_DIR)/%.o)

UTILS_SOURCES := $(wildcard $(UTILS_SRC_DIR)/*.c)
UTILS_OBJECTS := $(UTILS_SOURCES:$(UTILS_SRC_DIR)/%.c=$(UTILS_OBJ_DIR)/%.o)

all: do_init $(TARGET)

$(TARGET): $(BASE_OBJECTS) $(OBJECTS) $(UTILS_OBJECTS) unit-test.c 
	echo "objects: $(OBJECTS)"
	echo "sources: $(SOURCES)"
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) -lsecp256k1

$(OBJECTS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c 
	$(CC) -o $@ -c $< $(CFLAGS)

$(BASE_OBJECTS): $(BASE_OBJ_DIR)/%.o : $(BASE_SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(UTILS_OBJECTS): $(UTILS_OBJ_DIR)/%.o : $(UTILS_SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)


blockchain: test_blockchain

test_blockchain: $(BASE_OBJECTS) $(UTILS_OBJECTS) \
	$(OBJ_DIR)/satoshi-types.o $(OBJ_DIR)/compact_int.o $(OBJ_DIR)/merkle_tree.o \
	$(OBJ_DIR)/utxoes_db.o $(OBJ_DIR)/blocks_db.o $(OBJ_DIR)/db_engine.o \
	$(OBJ_DIR)/chains.o $(OBJ_DIR)/crypto.o\
	test_blockchain.c $(SRC_DIR)/algorithm/avl_tree.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ -D_TEST_BITCOIN_BLOCKCHAIN -D_STAND_ALONE -lsecp256k1 -D_VERBOSE=7

satoshi-script: test_satoshi-script
test_satoshi-script: $(BASE_OBJECTS) $(UTILS_OBJECTS) $(SRC_DIR)/satoshi-types.c \
		$(SRC_DIR)/satoshi-script.c $(SRC_DIR)/crypto.c \
		$(SRC_DIR)/satoshi-tx.c	$(SRC_DIR)/segwit-tx.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ \
		-D_TEST_SATOSHI_SCRIPT -D_STAND_ALONE -D_DEBUG -lsecp256k1


crypto: test_crypto
test_crypto: $(BASE_OBJECTS) $(UTILS_OBJECTS) $(SRC_DIR)/crypto.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ -D_TEST_CRYPTO -D_STAND_ALONE -lsecp256k1

satoshi-types: test_satoshi-types
test_satoshi-types: $(BASE_OBJECTS) $(UTILS_OBJECTS) \
	$(SRC_DIR)/satoshi-types.c $(SRC_DIR)/compact_int.c $(SRC_DIR)/merkle_tree.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ -D_TEST_SATOSHI_TYPES -D_STAND_ALONE

segwit-tx: test_satoshi-tx
satoshi-tx: test_satoshi-tx
test_satoshi-tx: $(BASE_OBJECTS) $(UTILS_OBJECTS) \
		$(SRC_DIR)/satoshi-tx.c $(SRC_DIR)/segwit-tx.c \
		$(SRC_DIR)/satoshi-types.c $(SRC_DIR)/crypto.c $(SRC_DIR)/satoshi-script.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ -D_TEST_SATOSHI_TX -D_STAND_ALONE -lsecp256k1 -D_VERBOSE=7


compact_int: test_compact_int
test_compact_int: $(SRC_DIR)/compact_int.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ \
	-lgmp \
	-D_TEST_COMPACT_INT -D_STAND_ALONE -D_VERBOSE=7

chains: test_chains
test_chains: $(BASE_OBJECTS) $(UTILS_OBJECTS) \
	$(OBJ_DIR)/satoshi-types.o $(SRC_DIR)/compact_int.c $(OBJ_DIR)/merkle_tree.o $(OBJ_DIR)/crypto.o \
	$(SRC_DIR)/chains.c
	echo "build $@ ..."
	$(LINKER) -o $@ $(CFLAGS) $(LIBS) $^ \
	-lgmp \
	-D_TEST_CHAINS -D_STAND_ALONE -D_VERBOSE=7  -lsecp256k1 -D_VERBOSE=7


db_engine: test_db_engine
test_db_engine: $(SRC_DIR)/db_engine.c
	echo "build $@ ..."
	echo 'rm data/*'
	[ -e data -a ! -L data ] && rm -f data/*.db data/__db.* data/log.*
	mkdir -p data
	$(LINKER) -o $@ $(CFLAGS) $^ \
		-lm -lpthread -ldb \
		-D_TEST_DB_ENGINE -D_STAND_ALONE -D_VERBOSE=7


blocks_db: test_blocks_db
test_blocks_db: $(SRC_DIR)/blocks_db.c $(SRC_DIR)/db_engine.c \
	$(BASE_OBJECTS) $(UTILS_OBJECTS) 
	echo "build $@ ..."
	$(LINKER) -o $@ $(CFLAGS) $(LIBS) $^ \
		-D_TEST_BLOCKS_DB -D_STAND_ALONE -D_VERBOSE=7


utxoes_db: test_utxoes_db
test_utxoes_db: $(SRC_DIR)/utxoes_db.c $(SRC_DIR)/db_engine.c \
	$(SRC_DIR)/satoshi-types.c $(SRC_DIR)/compact_int.c $(SRC_DIR)/merkle_tree.c \
	$(BASE_OBJECTS) $(UTILS_OBJECTS) 
	echo "build $@ ..."
	$(LINKER) -o $@ $(CFLAGS) $^ \
		$(LIBS) -lgmp \
		-D_TEST_UTXOES_DB -D_STAND_ALONE -D_VERBOSE=7
		

avl_tree: test_avl_tree
test_avl_tree: $(SRC_DIR)/algorithm/avl_tree.c
	echo "build $@ ..."
	$(LINKER) -o $@ $(CFLAGS) $^ \
		$(LIBS) \
		-D_TEST_AVL_TREE -D_STAND_ALONE -D_VERBOSE=7
		
		
bitcoin-network: test_bitcoin-network
test_bitcoin-network: $(SRC_DIR)/bitcoin-network.c $(SRC_DIR)/auto_buffer.c $(SRC_DIR)/utils/utils.c
	echo "build $@ ..."
	$(LINKER) -o $@ $(CFLAGS) $^ \
		$(LIBS) \
		-D_TEST_BITCOIN_NETWORK -D_STAND_ALONE -D_VERBOSE=7

socks5-proxy: test_socks5-proxy
test_socks5-proxy: $(SRC_DIR)/socks5-proxy.c
	echo "build $@ ..."
	$(LINKER) -o $@ $(CFLAGS) $^ \
		$(LIBS) \
		-D_TEST_SOCKS5_PROXY -D_STAND_ALONE -D_VERBOSE=7

base58: test_base58
test_base58: $(SRC_DIR)/base58.c $(SRC_DIR)/utils/utils.c
	echo "build $@ ..."
	$(LINKER) -o $@ $(CFLAGS) $^ \
		-lm -lpthread \
		-D_TEST_BASE58 -D_STAND_ALONE -D_VERBOSE=7

transactions_db: test_transactions_db
test_transactions_db: $(SRC_DIR)/transactions_db.c $(SRC_DIR)/utils/utils.c $(SRC_DIR)/db_engine.c 
	echo "build $@ ..."
	$(LINKER) -o $@ $(CFLAGS) $^ \
		-lm -lpthread -ldb \
		-D_TEST_TRANSACTIONS_DB -D_STAND_ALONE -D_VERBOSE=7



.PHONY: do_init clean
do_init:
	mkdir -p ../obj/base ../obj/utils
	
clean:
	rm -f $(OBJ_DIR)/*.o $(OBJ_DIR)/base/*.o $(OBJ_DIR)/utils/*.o $(TARGET) 

