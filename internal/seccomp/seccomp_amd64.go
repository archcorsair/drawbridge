//go:build linux && amd64

package seccomp

const (
	auditArch = 0xC000003E // AUDIT_ARCH_X86_64
	nrBind    = 49         // __NR_bind, x86_64
)

// bindNrs is bind(2) under every ABI a filter on this kernel can notify
// for: native, the i386 compat table (a 32-bit container with SCMP_ARCH_X86
// in its profile reports arch=I386 and nr=361), and x32 (same arch word as
// native, nr with the X32 bit set).
var bindNrs = map[uint32][]int32{
	0xC000003E: {49, 49 | 0x40000000}, // AUDIT_ARCH_X86_64: x86_64, x32
	0x40000003: {361},                 // AUDIT_ARCH_I386
}
