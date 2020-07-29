DEBUG ?= 1
PROJECT_DIR := ..

SRC_DIR = $(PROJECT_DIR)/src
OBJ_DIR = $(PROJECT_DIR)/obj

UTILS_SRC_DIR = $(PROJECT_DIR)/src/utils
UTILS_OBJ_DIR = $(PROJECT_DIR)/obj/utils

CC = gcc -std=gnu99 -D_GNU_SOURCE
LINKER = gcc -std=gnu99 -D_GNU_SOURCE
CFLAGS = -Wall -I $(PROJECT_DIR)/include
CFLAGS +=  $(shell pkg-config --cflags gtk+-3.0 vte-2.91)

LIBS = -lm -lpthread -ldb -ljson-c
LIBS += $(shell pkg-config --libs gtk+-3.0 vte-2.91)

ifeq ($(DEBUG),1)
CFLAGS += -g -D_DEBUG
endif

DB_SOURCES := $(SRC_DIR)/db_engine.c 
DB_OBJECTS := $(DB_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

UTILS_SOURCES := $(wildcard $(UTILS_SRC_DIR)/*.c)
UTILS_OBJECTS := $(UTILS_SOURCES:$(UTILS_SRC_DIR)/%.c=$(UTILS_OBJ_DIR)/%.o)

all: db_viewer

db_viewer: db_viewer.c shell.c  $(UTILS_OBJECTS)  $(DB_OBJECTS)
	$(LINKER) -o $@ $^ $(CFLAGS) $(LIBS)
	
$(UTILS_OBJECTS) : $(UTILS_OBJ_DIR)/%.o : $(UTILS_SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
	
.PHONY: clean
clean:
	rm -f db_viewer


