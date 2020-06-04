TARGET=unit-test

CC=gcc -std=gnu99 -Wall
LINKER=gcc -std=gnu99 -Wall

CFLAGS = -g -I../include -D_DEBUG
LIBS = -lm -lpthread -ljson-c -ldb

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

test_blockchain: $(BASE_OBJECTS) $(UTILS_OBJECTS) $(OBJ_DIR)/satoshi-types.o $(SRC_DIR)/blockchain.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ -D_TEST_BITCOIN_BLOCKCHAIN -D_STAND_ALONE

satoshi-script: test_satoshi-script
test_satoshi-script: $(BASE_OBJECTS) $(UTILS_OBJECTS) $(OBJ_DIR)/satoshi-types.o $(SRC_DIR)/satoshi-script.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ -D_TEST_SATOSHI_SCRIPT -D_STAND_ALONE


crypto: test_crypto
test_crypto: $(BASE_OBJECTS) $(UTILS_OBJECTS) $(SRC_DIR)/crypto.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ -D_TEST_CRYPTO -D_STAND_ALONE -lsecp256k1

satoshi-types: test_satoshi-types
test_satoshi-types: $(BASE_OBJECTS) $(UTILS_OBJECTS) $(SRC_DIR)/satoshi-types.c
	echo "build $@ ..."
	$(CC) -o $@ $(CFLAGS) $(LIBS) $^ -D_TEST_SATOSHI_TYPES -D_STAND_ALONE

.PHONY: do_init clean
do_init:
	mkdir -p ../obj/base ../obj/utils
	
clean:
	rm -rf ../obj/base ../obj/utils

