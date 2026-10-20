//go:build linux

package agent

import (
	"bytes"
	"log"
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
	nf := seccomp.Notif{ID: 7, PID: 0, Nr: seccomp.NrBind + 1, Args: [6]uint64{3, 0xdead, 16}}
	a.answerBind(p[0], nf)
	a.answerBind(p[0], nf) // the once-only line must not repeat

	out := buf.String()
	if strings.Contains(out, "read sockaddr") {
		t.Fatalf("target memory was read for a non-bind notification:\n%s", out)
	}
	if n := strings.Count(out, "not bind="); n != 1 {
		t.Fatalf("want exactly one foreign-syscall line, got %d:\n%s", n, out)
	}
	if n := strings.Count(out, "continue id=7"); n != 2 {
		t.Fatalf("want CONTINUE attempted for both notifications, got %d:\n%s", n, out)
	}
}
