# САФТ "Рубеж" BPF Makefile
# Compiles XDP program with proper flags

CLANG := clang
LLC := llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Compiler flags
CFLAGS := -O2 -g -Wall -Werror
CFLAGS += -D__KERNEL__ -D__BPF_TRACING__
CFLAGS += -target bpf
CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu

# Source and output
SRC := xdp_filter.c
OBJ := xdp_filter.o

# Installation path
INSTALL_DIR := /usr/lib/rubezh-saft

.PHONY: all clean install uninstall

all: $(OBJ)
	@echo "✓ XDP program compiled successfully"

$(OBJ): $(SRC)
	$(CLANG) $(CFLAGS) -c $(SRC) -o $(OBJ)

install: $(OBJ)
	@echo "Installing XDP program to $(INSTALL_DIR)..."
	@mkdir -p $(INSTALL_DIR)
	@install -m 0644 $(OBJ) $(INSTALL_DIR)/
	@echo "✓ XDP program installed to $(INSTALL_DIR)/$(OBJ)"

clean:
	@rm -f $(OBJ)
	@echo "✓ Cleaned build artifacts"

uninstall:
	@rm -f $(INSTALL_DIR)/$(OBJ)
	@echo "✓ XDP program uninstalled"

# Build and install in one step
setup: all install
	@echo "✓ Build and install complete"
