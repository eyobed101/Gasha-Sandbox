# Makefile — compiles monitoring.bpf.c into a loadable eBPF ELF object.
#
# Requirements (Linux only):
#   clang >= 14         apt install clang
#   llvm                apt install llvm
#   linux-headers       apt install linux-headers-$(uname -r)
#   libbpf-dev          apt install libbpf-dev
#   bpftool (optional)  apt install linux-tools-$(uname -r)
#
# Usage:
#   make                    # build monitoring.bpf.o in this directory
#   make install            # copy .o next to the lemas binary (BINDIR=./bin)
#   make vmlinux            # regenerate vmlinux.h from running kernel
#   make clean

CLANG      ?= clang
ARCH       ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
LINUX_ARCH ?= $(shell uname -m | sed 's/x86_64/x86_64/' | sed 's/aarch64/aarch64/')

# Kernel headers — prefer libbpf vmlinux.h, fall back to system headers
VMLINUX_H  := vmlinux.h
KERN_HDRS  := /usr/include/$(LINUX_ARCH)-linux-gnu

CFLAGS := -O2 -Wall -Wno-unused-variable \
          -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          -I. \
          -I$(KERN_HDRS)

TARGET := monitoring.bpf.o
SOURCE := monitoring.bpf.c

BINDIR ?= ../../../.

.PHONY: all clean install vmlinux

all: $(TARGET)

$(TARGET): $(SOURCE) $(VMLINUX_H)
	$(CLANG) $(CFLAGS) -c $(SOURCE) -o $(TARGET)
	@echo "[+] Built $(TARGET)"
	@ls -lh $(TARGET)

# Generate vmlinux.h from the running kernel's BTF data.
# Requires bpftool installed.
vmlinux: vmlinux.h

vmlinux.h:
	@command -v bpftool >/dev/null 2>&1 || \
		(echo "bpftool not found — install linux-tools-$(shell uname -r)" && exit 1)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "[+] Generated vmlinux.h"

install: $(TARGET)
	cp $(TARGET) $(BINDIR)/monitoring.bpf.o
	@echo "[+] Installed to $(BINDIR)/monitoring.bpf.o"
	@echo "    Set LEMAS_BPF_OBJECT=$(BINDIR)/monitoring.bpf.o or place it"
	@echo "    next to the lemas binary for automatic detection."

clean:
	rm -f $(TARGET) vmlinux.h
