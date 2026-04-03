# САФТ "Рубеж" Makefile
# Automatic compilation of XDP/eBPF programs

CLANG := clang
LLC := llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_RELEASE := $(shell uname -r)
KERNEL_HEADERS := /usr/src/linux-headers-$(KERNEL_RELEASE)

# Compiler flags for eBPF
CFLAGS := -O2 -g -Wall -Wextra \
	-target bpf \
	-D__BPF_TRACING__ \
	-D__KERNEL__ \
	-I$(KERNEL_HEADERS)/arch/$(ARCH)/include \
	-I$(KERNEL_HEADERS)/arch/$(ARCH)/include/generated \
	-I$(KERNEL_HEADERS)/include \
	-I$(KERNEL_HEADERS)/include/generated \
	-I/usr/include/bpf

BPF_SRC := bpf/xdp_filter.c
BPF_OBJ := bpf/xdp_filter.o

.PHONY: all clean install check-deps

all: check-deps $(BPF_OBJ)
	@echo "\n✓ XDP program compiled successfully: $(BPF_OBJ)"
	@echo "To install: sudo make install"

check-deps:
	@echo "Checking dependencies..."
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "❌ Error: clang not found. Install: sudo apt install clang"; exit 1; }
	@command -v llc >/dev/null 2>&1 || { echo "❌ Error: llc not found. Install: sudo apt install llvm"; exit 1; }
	@[ -d "$(KERNEL_HEADERS)" ] || { echo "❌ Error: Kernel headers not found. Install: sudo apt install linux-headers-$(KERNEL_RELEASE)"; exit 1; }
	@echo "✓ All dependencies found"

$(BPF_OBJ): $(BPF_SRC)
	@echo "Compiling XDP program..."
	@mkdir -p $(dir $(BPF_OBJ))
	$(CLANG) $(CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "✓ Compiled: $(BPF_OBJ)"

install: $(BPF_OBJ)
	@echo "Installing XDP program..."
	@mkdir -p /usr/lib/rubezh-saft
	@cp $(BPF_OBJ) /usr/lib/rubezh-saft/xdp_filter.o
	@echo "✓ Installed to: /usr/lib/rubezh-saft/xdp_filter.o"
	@ls -lh /usr/lib/rubezh-saft/xdp_filter.o

clean:
	@echo "Cleaning..."
	@rm -f $(BPF_OBJ)
	@echo "✓ Cleaned"

help:
	@echo "САФТ \"Рубеж\" Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make           - Compile XDP program"
	@echo "  make install   - Install XDP program to /usr/lib/rubezh-saft/"
	@echo "  make clean     - Remove compiled files"
	@echo "  make check-deps - Check if dependencies are installed"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang"
	@echo "  - llvm"
	@echo "  - linux-headers-$(KERNEL_RELEASE)"
