TARGET=test-blockchain

DEBUG ?= 1
OPTIMIZE ?= -O2

CC = gcc -std=gnu99 -D_GNU_SOURCE
LINKER = gcc -std=gnu99 -D_GNU_SOURCE

CFLAGS = -I../include
LIBS = -lm -lpthread -lgmp -L/usr/local/lib -lsecp256k1 -ldb

CFLAGS += $(shell pkg-config --cflags gtk+-3.0)
LIBS += $(shell pkg-config --libs gtk+-3.0)

ifeq ($(DEBUG),1)
CFLAGS += -g -D_DEBUG
OPTIMIZE = -O0
endif


SRC_DIR = ../src
OBJ_DIR = ../obj


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




all: do_init $(TARGET)

$(TARGET): $(OBJECTS) $(BASE_OBJECTS) $(UTILS_OBJECTS) test-blockchain.c da_panel.c
	$(LINKER) $(OPTIMIZE) -o $@ $^ $(LIBS) $(CFLAGS)
	

$(OBJECTS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(BASE_OBJECTS): $(BASE_OBJ_DIR)/%.o : $(BASE_SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
	
$(UTILS_OBJECTS): $(UTILS_OBJ_DIR)/%.o : $(UTILS_SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
	
.PHONY: do_init clean
do_init:
	mkdir -p $(OBJ_DIR)/base $(OBJ_DIR)/utils
clean:
	rm -f $(OBJ_DIR)/*.o $(OBJ_DIR)/base/*.o $(OBJ_DIR)/utils/*.o $(TARGET)




