//go:build linux

package agent

import (
	"bytes"
	"log"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/archcorsair/drawbridge/internal/seccomp"
)

// Audit finding 5: a notification for any syscall but bind is answered
// CONTINUE before target memory is read. The fd is a pipe, so the CONTINUE
// itself fails (ENOTTY) and shows up in the log — which is how the test
// sees that the early path ran, and that no "read sockaddr" attempt on a
// bogus pid preceded it.
func TestAnswerBindIgnoresNonBindSyscalls(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	a := &Agent{}
	nf := seccomp.Notif{ID: 7, PID: 0, Nr: seccomp.NrBind + 1, Arch: seccomp.NativeArch, Args: [6]uint64{3, 0xdead, 16}}
	a.answerBind(p[0], nf)
	a.answerBind(p[0], nf) // the once-only line must not repeat

	out := buf.String()
	if strings.Contains(out, "read sockaddr") {
		t.Fatalf("target memory was read for a non-bind notification:\n%s", out)
	}
	if n := strings.Count(out, "(not bind)"); n != 1 {
		t.Fatalf("want exactly one foreign-syscall line, got %d:\n%s", n, out)
	}
	if n := strings.Count(out, "continue id=7"); n != 2 {
		t.Fatalf("want CONTINUE attempted for both notifications, got %d:\n%s", n, out)
	}
}

// bind(2) is recognised under every ABI the kernel can notify for on this
// GOARCH, and nothing else is: a 32-bit container's compat bind must keep
// its synchronous EADDRINUSE (Greptile review on PR 1).
func TestIsBindPerABI(t *testing.T) {
	if !seccomp.IsBind(seccomp.NativeArch, seccomp.NrBind) {
		t.Fatal("native bind not recognised")
	}
	if seccomp.IsBind(seccomp.NativeArch, seccomp.NrBind+1) {
		t.Fatal("native bind+1 recognised")
	}
	if seccomp.IsBind(0, seccomp.NrBind) {
		t.Fatal("unknown arch recognised")
	}
	for arch, nrs := range seccomp.BindNrsForTest() {
		for _, nr := range nrs {
			if !seccomp.IsBind(arch, nr) {
				t.Fatalf("arch %#x nr %d not recognised", arch, nr)
			}
			if seccomp.IsBind(arch, nr+1) {
				t.Fatalf("arch %#x nr %d recognised", arch, nr+1)
			}
		}
	}
	switch runtime.GOARCH {
	case "amd64":
		if !seccomp.IsBind(unix.AUDIT_ARCH_I386, 361) || !seccomp.IsBind(unix.AUDIT_ARCH_X86_64, 49|0x40000000) {
			t.Fatal("i386 or x32 bind not recognised on amd64")
		}
	case "arm64":
		if !seccomp.IsBind(unix.AUDIT_ARCH_ARM, 282) {
			t.Fatal("arm compat bind not recognised on arm64")
		}
	}
}
