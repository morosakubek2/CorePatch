MODULE_NAME := corepatch
SRC_DIR := src
BUILD_DIR := build

ARCH ?= arm64

ifeq ($(ARCH),arm64)
    CROSS_COMPILE ?= aarch64-linux-gnu-
    CFLAGS_ARCH := -D__aarch64__
else ifeq ($(ARCH),arm)
    CROSS_COMPILE ?= arm-linux-gnueabihf-
    CFLAGS_ARCH := -D__arm__
else ifeq ($(ARCH),x86_64)
    CROSS_COMPILE ?= x86_64-linux-gnu-
    CFLAGS_ARCH := -D__x86_64__
else
    $(error Unsupported ARCH: $(ARCH))
endif

CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

# Flags matching splfix-kpm style: freestanding, no PIC/PIE for kernel context
CFLAGS := -Wall -Wextra -O2 -ffreestanding -nostdlib -fno-pic -fno-pie
CFLAGS += $(CFLAGS_ARCH)
CFLAGS += -I$(SRC_DIR)

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
TARGET := $(BUILD_DIR)/$(MODULE_NAME).kpm

all: dirs $(TARGET)

dirs:
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS)
	$(LD) -r -o $@ $^
	@echo "Built $@"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled $<"

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean dirs
