package limaaddr

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

// dialErr wraps errno the way the net package does, so the classifier is
// exercised against the shape it actually sees at runtime:
// *net.OpError → *os.SyscallError → syscall.Errno.
func dialErr(errno syscall.Errno) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.IPv4(192, 168, 64, 2), Port: 4777},
		Err:  os.NewSyscallError("connect", errno),
	}
}

// timeoutErr is what net.DialTimeout returns when the deadline fires.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// TestClassifyProbe pins the docs/transport.md §2.2 classification table.
// The whole point of Phase 3 is that a fallback is *diagnosable*: an
// EHOSTUNREACH must name the macOS Local Network gate (the one failure a
// user can actually fix), and a refusal or timeout must not, or the note
// sends people into System Settings for a stale agent.
func TestClassifyProbe(t *testing.T) {
	const addr = "192.168.64.2:4777"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"ehostunreach", dialErr(syscall.EHOSTUNREACH), NoteLocalNetworkDenied},
		{"econnrefused", dialErr(syscall.ECONNREFUSED), NoteAgentNotListening},
		{"etimedout", dialErr(syscall.ETIMEDOUT), NoteAgentNotListening},
		{"dial timeout", &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}, NoteAgentNotListening},
		{"deadline sentinel", fmt.Errorf("probe: %w", os.ErrDeadlineExceeded), NoteAgentNotListening},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyProbe(addr, tc.err); got != tc.want {
				t.Fatalf("classifyProbe(%v) =\n  %q\nwant\n  %q", tc.err, got, tc.want)
			}
		})
	}
}

// An error outside the table keeps its raw text: guessing a remedy is worse
// than reporting what happened.
func TestClassifyProbeUnknownKeepsCause(t *testing.T) {
	note := classifyProbe("192.168.64.2:4777", errors.New("weird failure"))
	if note == NoteLocalNetworkDenied || note == NoteAgentNotListening {
		t.Fatalf("unknown error got a classified note: %q", note)
	}
	for _, want := range []string{"192.168.64.2:4777", "weird failure", "SSH forwarder"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note %q missing %q", note, want)
		}
	}
}

func TestClassifyNoGuestIP(t *testing.T) {
	if got := classifyNoGuestIP(); got != NoteNoGuestIP {
		t.Fatalf("classifyNoGuestIP() = %q, want %q", got, NoteNoGuestIP)
	}
}
