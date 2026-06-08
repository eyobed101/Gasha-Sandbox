//go:build ignore

// This file drives bpf2go code generation.
// Run from the workspace root:
//
//	go generate ./pkg/monitor/bpf/
//
// Prerequisites:
//   - clang >= 14 on PATH (Linux only)
//   - Linux kernel headers in /usr/include or KERNELHEADERS env var
//
// The generated files (monitoring_bpfel.go / monitoring_bpfeb.go + *.o embedded)
// are committed to the repo so cross-compilation from Windows/macOS works without
// a local clang installation.

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall -g -target bpf" Monitoring monitoring.bpf.c
