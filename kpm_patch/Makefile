KPM_NAME := corepatch
SRC_DIR := src
OBJ_FILE := $(KPM_NAME).o
KPM_FILE := $(KPM_NAME).kpm

# Ścieżka do źródeł KernelPatch (przekazywana z workflow)
KP_ROOT ?= $(PWD)/kernel_patch_src
KP_TOOLS := $(KP_ROOT)/tools

ARCH ?= arm64
ifeq ($(ARCH), arm64)
    CROSS_COMPILE := aarch64-linux-gnu-
    KP_ARCH := arm64
else ifeq ($(ARCH), arm)
    CROSS_COMPILE := arm-linux-gnueabihf-
    KP_ARCH := arm
else ifeq ($(ARCH), x86_64)
    CROSS_COMPILE := x86_64-linux-gnu-
    KP_ARCH := x86_64
else
    $(error Unsupported ARCH: $(ARCH))
endif

CC := $(CROSS_COMPILE)gcc

# Flagi kompilacji zgodne z demo KernelPatch
CFLAGS := -Wall -Wextra -O2 -fno-pic -fno-pie -fno-strict-aliasing
CFLAGS += -I$(KP_ROOT)/kernel/include
CFLAGS += -I$(KP_ROOT)/kernel/arch/$(KP_ARCH)/include
CFLAGS += -D__KERNEL__ -DMODULE -DKBUILD_MODNAME=\"$(KPM_NAME)\"
CFLAGS += -Wno-unused-parameter -Wno-unused-variable

all: $(KPM_FILE)

$(OBJ_FILE): $(SRC_DIR)/corepatch.c
	@echo "Compiling $(SRC_DIR)/corepatch.c..."
	$(CC) $(CFLAGS) -c $< -o $@

$(KPM_FILE): $(OBJ_FILE)
	@echo "Packaging $(OBJ_FILE) into $(KPM_FILE)..."
	@if [ ! -f "$(KP_TOOLS)/kpbuild" ]; then \
		echo "Error: kpbuild not found in $(KP_TOOLS)!"; \
		exit 1; \
	fi
	$(KP_TOOLS)/kpbuild $(OBJ_FILE) -o $(KPM_FILE)
	@echo "Successfully built $(KPM_FILE)"

clean:
	rm -f $(OBJ_FILE) $(KPM_FILE)

.PHONY: all clean
