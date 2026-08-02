// Package bpf builds and loads the drawbridge loopback gateway eBPF programs.
//
// Code generation runs INSIDE the Lima guest (needs clang/llvm); the
// generated *_bpfel.go/*.o files are committed so macOS builds never
// need a BPF toolchain. Regenerate with `make gen`.
package bpf

// The arch-triple -I paths fix `clang -target bpf` not finding <asm/types.h>
// on Debian/Ubuntu multiarch layouts; nonexistent paths are ignored.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpf -target bpfel -cflags "-O2 -g -Wall -Werror -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu" loopbackgw c/loopback_gw.c
// -mcpu=v3: the refcount's fetch-atomics (__sync_sub_and_fetch) need the
// v3 BPF ISA; kernel 6.8 supports it.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpf -target bpfel -type listener_event -cflags "-O2 -g -Wall -Werror -mcpu=v3 -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu" tracker c/tracker.c
