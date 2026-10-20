//go:build linux && arm64

package seccomp

const (
	auditArch = 0xC00000B7 // AUDIT_ARCH_AARCH64
	nrBind    = 200        // __NR_bind, arm64 generic syscall table
)

// bindNrs is bind(2) under every ABI a filter on this kernel can notify
// for: native, and the 32-bit arm compat table (a 32-bit container with
// SCMP_ARCH_ARM in its profile reports arch=ARM and nr=282).
var bindNrs = map[uint32][]int32{
	0xC00000B7: {200}, // AUDIT_ARCH_AARCH64
	0x40000028: {282}, // AUDIT_ARCH_ARM (EABI)
}
