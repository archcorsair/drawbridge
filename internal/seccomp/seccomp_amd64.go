//go:build linux && amd64

package seccomp

const (
	auditArch = 0xC000003E // AUDIT_ARCH_X86_64
	nrBind    = 49         // __NR_bind, x86_64
)
