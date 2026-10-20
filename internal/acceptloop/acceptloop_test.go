package acceptloop

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

type tempErr struct{ temp bool }

func (e tempErr) Error() string   { return "tempErr" }
func (e tempErr) Timeout() bool   { return false }
func (e tempErr) Temporary() bool { return e.temp }

func TestRetryable(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{net.ErrClosed, false},
		{&net.OpError{Op: "accept", Err: net.ErrClosed}, false},
		{io.EOF, false},
		{errors.New("permanent"), false},
		{tempErr{false}, false},
		{tempErr{true}, true},
		{syscall.EMFILE, true},
		{syscall.ENFILE, true},
		{&net.OpError{Op: "accept", Err: syscall.EMFILE}, true},
		{&net.OpError{Op: "accept", Err: syscall.ECONNABORTED}, true},
	}
	for _, tc := range cases {
		if got := Retryable(tc.err); got != tc.want {
			t.Errorf("Retryable(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestNext(t *testing.T) {
	var d time.Duration
	var seq []time.Duration
	for i := 0; i < 10; i++ {
		d = Next(d)
		seq = append(seq, d)
	}
	want := []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000}
	for i := range want {
		if seq[i] != want[i]*time.Millisecond {
			t.Fatalf("step %d: %v, want %v (seq %v)", i, seq[i], want[i]*time.Millisecond, seq)
		}
	}
}

func TestServeBacksOffAndResets(t *testing.T) {
	var slept []time.Duration
	sleep = func(d time.Duration) { slept = append(slept, d) }
	defer func() { sleep = time.Sleep }()

	script := []struct {
		conn int
		err  error
	}{
		{err: &net.OpError{Op: "accept", Err: syscall.EMFILE}},
		{err: &net.OpError{Op: "accept", Err: syscall.EMFILE}},
		{err: tempErr{true}},
		{conn: 1},
		{err: syscall.ENFILE}, // delay restarts from MinDelay after a success
		{conn: 2},
		{err: net.ErrClosed},
	}
	i := 0
	accept := func() (int, error) {
		s := script[i]
		i++
		return s.conn, s.err
	}
	var handled []int
	var logged int
	err := Serve(accept, func(c int) { handled = append(handled, c) }, func(string, ...any) { logged++ })
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve returned %v, want ErrClosed", err)
	}
	if len(handled) != 2 || handled[0] != 1 || handled[1] != 2 {
		t.Fatalf("handled %v", handled)
	}
	want := []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond, 5 * time.Millisecond}
	if len(slept) != len(want) {
		t.Fatalf("slept %v, want %v", slept, want)
	}
	for k := range want {
		if slept[k] != want[k] {
			t.Fatalf("slept %v, want %v", slept, want)
		}
	}
	if logged != 4 {
		t.Fatalf("logged %d lines, want one per retry", logged)
	}
}

func TestServeReturnsOnPermanentError(t *testing.T) {
	perm := errors.New("listener broke")
	n := 0
	err := Serve(func() (int, error) { n++; return 0, perm }, func(int) {}, nil)
	if err != perm || n != 1 {
		t.Fatalf("err=%v calls=%d", err, n)
	}
}
