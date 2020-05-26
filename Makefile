TARGET=ln-network-daemon

DEBUG=1
OPTIMIZE=-O2
VERBOSE=1

CC=gcc -std=gnu99 -D_DEFAULT_SOURCE -D_GNU_SOURCE
LINKER=gcc -std=gnu99 -D_DEFAULT_SOURCE -D_GNU_SOURCE
AR=ar crf

SRC_DIR=src
OBJ_DIR=obj
BIN_DIR=bin
LIB_DIR=lib

CFLAGS = -Wall -Iinclude -D_VERBOSE=$(VERBOSE)
LIBS = -lm -lpthread -ljson-c -lcurl -luuid

ifeq ($(DEBUG),1)
CFLAGS += -g
OPTIMIZE = -O0
endif

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

BASE_SRC_DIR := $(SRC_DIR)/base
BASE_OBJ_DIR := $(OBJ_DIR)/base

UTILS_SRC_DIR := $(SRC_DIR)/utils
UTILS_OBJ_DIR := $(OBJ_DIR)/utils

BASE_SOURCES := $(wildcard $(BASE_SRC_DIR)/*.c)
BASE_OBJECTS := $(BASE_SOURCES:$(BASE_SRC_DIR)/%.c=$(BASE_OBJ_DIR)/%.o)

UTILS_SOURCES := $(wildcard $(UTILS_SRC_DIR)/*.c)
UTILS_OBJECTS := $(UTILS_SOURCES:$(UTILS_SRC_DIR)/%.c=$(UTILS_OBJ_DIR)/%.o)

all: do_init $(OBJECTS) $(BASE_OBJECTS) $(UTILS_OBJECTS)

$(OBJECTS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(BASE_OBJECTS): $(BASE_OBJ_DIR)/%.o : $(BASE_SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
	
$(UTILS_OBJECTS): $(UTILS_OBJ_DIR)/%.o : $(UTILS_SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
	
.PHONY: do_init clean tests
do_init:
	mkdir -p obj/base obj/utils bin lib tests

clean:
	rm -rf obj/* $(TARGET)
	
tests: json-rpc

json-rpc: src/rpc/json-rpc.c $(OBJECTS)
	$(CC) -o tests/$@ src/rpc/json-rpc.c $(CFLAGS) $(LIBS) -D_TEST -D_STAND_ALONE

