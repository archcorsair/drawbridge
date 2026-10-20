// Package acceptloop is the one accept loop every drawbridge listener runs:
// retry transient Accept errors with a bounded backoff instead of returning
// on the first one. Before it, EMFILE from a single fd-pressure event (a
// conn flood, a notify-socket abuse) killed the listener for the life of
// the process while systemd still reported the unit active (audit finding
// 12). The shape is net/http's Serve loop: 5 ms doubling to 1 s, reset on
// the next successful accept; a closed listener ends the loop.
package acceptloop

import (
	"errors"
	"net"
	"syscall"
	"time"
)

const (
	// MinDelay is the first backoff after a transient error.
	MinDelay = 5 * time.Millisecond
	// MaxDelay caps the doubling.
	MaxDelay = time.Second
)

// Retryable reports whether an Accept error is worth retrying: a net.Error
// that says it is temporary (EINTR, ECONNABORTED, timeouts, and — through
// syscall.Errno.Temporary — EMFILE/ENFILE), or fd exhaustion named
// explicitly in case it arrives unwrapped. A closed listener and every
// other error end the loop.
func Retryable(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Temporary()
}

// Next is the delay to sleep after a retryable error given the previous
// delay (0 for the first one).
func Next(prev time.Duration) time.Duration {
	if prev == 0 {
		return MinDelay
	}
	if prev >= MaxDelay/2 {
		return MaxDelay
	}
	return prev * 2
}

// sleep is a test seam.
var sleep = time.Sleep

// Serve accepts until accept returns a non-retryable error and returns that
// error (net.ErrClosed, normally). handle runs synchronously; callers that
// want per-conn goroutines start them inside it. logf may be nil.
func Serve[C any](accept func() (C, error), handle func(C), logf func(string, ...any)) error {
	var delay time.Duration
	for {
		c, err := accept()
		if err != nil {
			if !Retryable(err) {
				return err
			}
			delay = Next(delay)
			if logf != nil {
				logf("accept: %v; retrying in %v", err, delay)
			}
			sleep(delay)
			continue
		}
		delay = 0
		handle(c)
	}
}
