//go:build linux && arm64

package seccomp

const (
	auditArch = 0xC00000B7 // AUDIT_ARCH_AARCH64
	nrBind    = 200        // __NR_bind, arm64 generic syscall table
)
