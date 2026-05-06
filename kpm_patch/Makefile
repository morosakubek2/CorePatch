MODULE_NAME := corepatch
SRC_DIR := src
BUILD_DIR := build

# Domyślna architektura
ARCH ?= arm64

# Kompilator cross
ifeq ($(ARCH),arm64)
    CROSS_COMPILE ?= aarch64-linux-gnu-
    ARCH_DEF := -D__aarch64__
else ifeq ($(ARCH),arm)
    CROSS_COMPILE ?= arm-linux-gnueabihf-
    ARCH_DEF := -D__arm__
else ifeq ($(ARCH),x86_64)
    CROSS_COMPILE ?= x86_64-linux-gnu-
    ARCH_DEF := -D__x86_64__
else
    $(error Unsupported architecture: $(ARCH))
endif

CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

# Flagi kompilacji zgodne z demo-syscallhook
# Usunięto -ffreestanding i -nostdlib, aby允许kompilator widział definicje z linux/*.h
# Kod będzie zawierał nierozwiązane symbole, które KPM resolver załaduje w runtime
CFLAGS := -Wall -Wextra -O2 -fPIC -fno-strict-aliasing
CFLAGS += $(ARCH_DEF)
CFLAGS += -DMODULE -D__KERNEL__
# Dodajemy ścieżki do nagłówków jądra, jeśli są dostępne w systemie cross-compile
# W GitHub Actions często nie ma pełnych nagłówków, więc polegamy na tym, że 
# struktury są standardowe, a KPM rozwiąże symbole.
# Jeśli wystąpi błąd brakujących nagłówków, należy zainstalować linux-headers-arm64-cross

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
OUTPUT := $(BUILD_DIR)/$(MODULE_NAME).kpm

all: directories $(OUTPUT)

directories:
	mkdir -p $(BUILD_DIR)

$(OUTPUT): $(OBJS)
	$(LD) -r -o $@ $^
	@echo "Built $(OUTPUT) successfully for $(ARCH)"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | directories
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled $<"

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean directories
