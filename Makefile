# This Makefile can be used with GNU Make or BSD Make

LIB=libml-dsa-44_clean.a
BUILD_DIR=build
LIB_PATH=$(BUILD_DIR)/$(LIB)

# Source directories
COMMON_SRC_DIR=src/common
MLDSA44_SRC_DIR=src/mldsa44

# Headers from both directories
COMMON_HEADERS=$(wildcard $(COMMON_SRC_DIR)/*.h)
MLDSA44_HEADERS=$(wildcard $(MLDSA44_SRC_DIR)/*.h)
HEADERS=$(COMMON_HEADERS) $(MLDSA44_HEADERS)

# Object files
COMMON_OBJECTS=$(BUILD_DIR)/fips202.o $(BUILD_DIR)/randombytes.o $(BUILD_DIR)/memory_cleanse.o
MLDSA44_OBJECTS=$(BUILD_DIR)/ntt.o $(BUILD_DIR)/packing.o $(BUILD_DIR)/poly.o $(BUILD_DIR)/polyvec.o $(BUILD_DIR)/reduce.o $(BUILD_DIR)/rounding.o $(BUILD_DIR)/sign.o $(BUILD_DIR)/symmetric-shake.o
OBJECTS=$(COMMON_OBJECTS) $(MLDSA44_OBJECTS)

CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -I$(COMMON_SRC_DIR) -I$(MLDSA44_SRC_DIR) $(EXTRAFLAGS)

all: $(BUILD_DIR) $(LIB_PATH)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Common objects
$(BUILD_DIR)/%.o: $(COMMON_SRC_DIR)/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# ML-DSA-44 objects
$(BUILD_DIR)/%.o: $(MLDSA44_SRC_DIR)/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB_PATH): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)

# Test targets
$(BUILD_DIR)/test_mldsa44: tests/test_mldsa44.c $(LIB_PATH)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lml-dsa-44_clean

test: $(BUILD_DIR)/test_mldsa44
	$(BUILD_DIR)/test_mldsa44

clean:
	$(RM) -r $(BUILD_DIR)

.PHONY: all test clean