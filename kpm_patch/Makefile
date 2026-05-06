/*
 * KPM CorePatch - Makefile for building the kernel patch module
 * 
 * Usage:
 *   make                  - Build for current architecture
 *   make ARCH=arm64       - Build for ARM64
 *   make ARCH=arm         - Build for ARM
 *   make clean            - Clean build artifacts
 */

# Module name
MODULE_NAME := corepatch

# KernelSU/Apatch KPM SDK path (adjust as needed)
KPM_SDK_PATH ?= $(PWD)/kpm_sdk

# Architecture detection
ARCH ?= $(shell uname -m | sed 's/x86_64/x86_64/; s/aarch64/arm64/')

# Cross compiler setup
ifeq ($(ARCH),arm64)
    CROSS_COMPILE ?= aarch64-linux-gnu-
    ARCH_DEF := -D__aarch64__
else ifeq ($(ARCH),arm)
    CROSS_COMPILE ?= arm-linux-gnueabi-
    ARCH_DEF := -D__arm__
else ifeq ($(ARCH),x86_64)
    CROSS_COMPILE ?= x86_64-linux-gnu-
    ARCH_DEF := -D__x86_64__
else ifeq ($(ARCH),x86)
    CROSS_COMPILE ?= i686-linux-gnu-
    ARCH_DEF := -D__i386__
endif

CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

# Compiler flags
CFLAGS := -Wall -Wextra -O2 -fPIC -ffreestanding -nostdlib
CFLAGS += -I$(KPM_SDK_PATH)/include
CFLAGS += -I$(PWD)/include
CFLAGS += $(ARCH_DEF)

# Debug build
ifdef DEBUG
    CFLAGS += -g -DDEBUG
endif

# Source files
SRC_DIR := src
OBJ_DIR := obj
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Output
OUTPUT := $(MODULE_NAME).kpm

# Default target
all: directories $(OUTPUT)

# Create output directories
directories:
	mkdir -p $(OBJ_DIR)

# Link final module
$(OUTPUT): $(OBJS)
	echo "Linking $(OUTPUT)..."
	$(LD) -r -o $@ $^
	echo "Built $(OUTPUT) successfully"

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	echo "Cleaning..."
	rm -rf $(OBJ_DIR) $(OUTPUT)
	echo "Clean complete"

# Install to KernelSU modules directory (requires root)
install: $(OUTPUT)
	echo "Installing $(OUTPUT) to /data/adb/modules/"
	su -c "cp $(OUTPUT) /data/adb/modules/"
	echo "Installation complete. Reboot to apply."

# Uninstall
uninstall:
	echo "Removing $(OUTPUT) from /data/adb/modules/"
	su -c "rm -f /data/adb/modules/$(OUTPUT)"
	echo "Uninstallation complete. Reboot to apply."

# Help
help:
	echo "KPM CorePatch Build System"
	echo ""
	echo "Targets:"
	echo "  all       - Build the module (default)"
	echo "  clean     - Remove build artifacts"
	echo "  install   - Install to KernelSU modules directory"
	echo "  uninstall - Remove from KernelSU modules directory"
	echo "  help      - Show this help message"
	echo ""
	echo "Options:"
	echo "  ARCH=<arch>        - Target architecture (arm64, arm, x86_64, x86)"
	echo "  CROSS_COMPILE=<cc> - Cross-compiler prefix"
	echo "  DEBUG=1            - Enable debug build"
	echo "  KPM_SDK_PATH=<path>- Path to KPM SDK"
	echo ""
	echo "Examples:"
	echo "  make ARCH=arm64"
	echo "  make ARCH=arm64 CROSS_COMPILE=aarch64-linux-android-"
	echo "  make DEBUG=1"

.PHONY: all clean install uninstall help directories
