#
# KPM CorePatch - Makefile for building the kernel patch module
# 
# Usage:
#   make ARCH=arm64       - Build for ARM64 (recommended for CI)
#   make ARCH=arm         - Build for ARM
#   make clean            - Clean build artifacts
#

MODULE_NAME := corepatch
KPM_SDK_PATH ?= $(PWD)/kpm_sdk
SRC_DIR := src
BUILD_DIR := build
INCLUDE_DIR := include

# Architecture detection
ARCH ?= arm64

# Cross compiler setup
ifeq ($(ARCH),arm64)
    CROSS_COMPILE ?= aarch64-linux-gnu-
    ARCH_DEF := -D__aarch64__ -DKPM_ARCH_ARM64
else ifeq ($(ARCH),arm)
    CROSS_COMPILE ?= arm-linux-gnueabihf-
    ARCH_DEF := -D__arm__ -DKPM_ARCH_ARM
else ifeq ($(ARCH),x86_64)
    CROSS_COMPILE ?= x86_64-linux-gnu-
    ARCH_DEF := -D__x86_64__ -DKPM_ARCH_X86_64
else
    $(error Unsupported architecture: $(ARCH))
endif

CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

# Compiler flags
CFLAGS := -Wall -Wextra -O2 -fno-pic -fno-pie -ffreestanding -nostdlib
CFLAGS += -I$(KPM_SDK_PATH)/include
CFLAGS += -I$(INCLUDE_DIR)
CFLAGS += $(ARCH_DEF)

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Output
OUTPUT := $(BUILD_DIR)/$(MODULE_NAME).kpm

all: directories $(OUTPUT)

directories:
	mkdir -p $(BUILD_DIR)

$(OUTPUT): $(OBJS)
	$(LD) -r -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | directories
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean directories
