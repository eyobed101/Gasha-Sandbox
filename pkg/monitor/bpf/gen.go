//go:build ignore

// gen.go — bpf2go code generation driver.
//
// This file is excluded from normal builds (//go:build ignore).
// Run it on a Linux machine with clang and kernel headers installed:
//
//   # From the workspace root:
//   go generate ./pkg/monitor/bpf/
//
// What it produces:
//   monitoring_bpfel.go   — little-endian Go bindings + embedded ELF
//   monitoring_bpfeb.go   — big-endian  Go bindings + embedded ELF
//   monitoring_bpfel.o    — compiled BPF ELF (little-endian)
//   monitoring_bpfeb.o    — compiled BPF ELF (big-endian)
//
// The generated .go files are committed to the repo so the project builds
// on Windows/macOS without a local clang installation. The .o files are
// picked up automatically by the generated Go code via go:embed.
//
// Prerequisites:
//   apt install clang llvm libbpf-dev linux-headers-$(uname -r)
//   (or: make vmlinux  to generate vmlinux.h from the running kernel)
//
// Alternative (no bpf2go — manual compile):
//   make -C pkg/monitor/bpf
//   # Then set env var at runtime:
//   export LEMAS_BPF_OBJECT=pkg/monitor/bpf/monitoring.bpf.o

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//   -cc clang \
//   -cflags "-O2 -Wall -target bpf -D__TARGET_ARCH_x86" \
//   -type bpf_event \
//   Monitoring monitoring.bpf.c \
//   -- -I. -I/usr/include/x86_64-linux-gnu
