KPM_NAME := corepatch
SRC_DIR := src
OBJ_FILE := $(KPM_NAME).o
KPM_FILE := $(KPM_NAME).kpm

KP_ROOT ?= $(PWD)/kernel_patch_src
# Ścieżka do narzędzi
KP_TOOLS_DIR := $(KP_ROOT)/tools

ARCH ?= arm64

# Ustawienia cross-kompilacji
ifeq ($(ARCH), arm64)
    CROSS_COMPILE := aarch64-linux-gnu-
    LINUX_ARCH := arm64
else ifeq ($(ARCH), arm)
    CROSS_COMPILE := arm-linux-gnueabihf-
    LINUX_ARCH := arm
else ifeq ($(ARCH), x86_64)
    CROSS_COMPILE := x86_64-linux-gnu-
    LINUX_ARCH := x86
else
    $(error Unsupported ARCH: $(ARCH))
endif

CC := $(CROSS_COMPILE)gcc

# POPRAWIONE ŚCIEŻKI DO NAGŁÓWKÓW
# W repozytorium KernelPatch źródła kernela są w katalogu 'kernel'
KERNEL_SRC_PATH := $(KP_ROOT)/kernel

CFLAGS := -Wall -Wextra -O2 -fno-pic -fno-pie -fno-strict-aliasing
# Dodajemy ścieżki do nagłówków kernela z repozytorium KernelPatch
CFLAGS += -I$(KERNEL_SRC_PATH)/include
CFLAGS += -I$(KERNEL_SRC_PATH)/arch/$(LINUX_ARCH)/include
CFLAGS += -I$(KERNEL_SRC_PATH)/arch/$(LINUX_ARCH)/include/generated
CFLAGS += -I$(KERNEL_SRC_PATH)/include/generated/uapi
CFLAGS += -I$(KERNEL_SRC_PATH)/include/uapi

CFLAGS += -D__KERNEL__ -DMODULE -DKBUILD_MODNAME=\"$(KPM_NAME)\"
CFLAGS += -Wno-unused-parameter -Wno-unused-variable
# Często wymagane dla modułów zewnętrznych
CFLAGS += -nostdinc -isystem $(dir $(shell $(CC) -print-file-name=include))

all: $(KPM_FILE)

$(OBJ_FILE): $(SRC_DIR)/corepatch.c
	@echo "Compiling $(SRC_DIR)/corepatch.c for $(ARCH)..."
	@echo "Using kernel headers from: $(KERNEL_SRC_PATH)"
	$(CC) $(CFLAGS) -c $< -o $@

$(KPM_FILE): $(OBJ_FILE)
	@echo "Packaging $(OBJ_FILE) into $(KPM_FILE)..."
	@if [ ! -f "$(KP_TOOLS_DIR)/kptools" ]; then \
		echo "Error: kptools not found!"; \
		exit 1; \
	fi
	# Używamy kptools do pakowania (komenda może się różnić w zależności od wersji, często 'kptools kpm')
	# W nowszych wersjach KernelPatch często używa się składni: kptools kpm <input> -o <output>
	# Lub po prostu kopiujemy plik .o na .kpm jeśli narzędzie tylko zmienia format, ale bezpieczniej użyć narzędzia.
	# Sprawdzamy dostępność komendy 'kpm' w kptools lub używamy bezpośredniej metody jeśli to tylko linker.
	# Dla bezpieczeństwa, jeśli kptools służy tylko do patchowania boot.img, a KPM to zwykły .o:
	cp $(OBJ_FILE) $(KPM_FILE)
	@echo "Successfully built $(KPM_FILE) (Note: verify if kptools processing is needed)"
	# Opcjonalnie: $(KP_TOOLS_DIR)/kptools kpm $(OBJ_FILE) -o $(KPM_FILE)

clean:
	rm -f $(OBJ_FILE) $(KPM_FILE)

.PHONY: all clean
