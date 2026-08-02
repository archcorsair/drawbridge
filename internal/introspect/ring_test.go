package introspect

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// The ring is recent evidence, not a log: past its depth the oldest entries
// go, and the newest RingSize survive in order.
func TestRingKeepsNewest(t *testing.T) {
	var r Ring
	for i := 0; i < RingSize+7; i++ {
		r.Record("id", fmt.Sprintf("line %d", i))
	}
	got := r.Snapshot()
	if len(got) != RingSize {
		t.Fatalf("len = %d, want %d", len(got), RingSize)
	}
	if got[0].Line != "line 7" {
		t.Fatalf("oldest retained = %q, want %q", got[0].Line, "line 7")
	}
	if last := got[len(got)-1].Line; last != fmt.Sprintf("line %d", RingSize+6) {
		t.Fatalf("newest = %q", last)
	}
}

func TestRingUnderfilled(t *testing.T) {
	var r Ring
	if got := r.Snapshot(); len(got) != 0 {
		t.Fatalf("empty ring returned %d entries", len(got))
	}
	r.Record("auth-mismatch", "a line")
	got := r.Snapshot()
	if len(got) != 1 || got[0].ID != "auth-mismatch" || got[0].Line != "a line" {
		t.Fatalf("Snapshot = %+v", got)
	}
	if got[0].At.IsZero() {
		t.Fatal("entry was not stamped at Record time")
	}
}

// Nil-safety is what makes the field injectable: mirror, macsync, and the
// auth throttle carry it unset in every test and harness that does not care.
func TestNilRingIsANoOp(t *testing.T) {
	var r *Ring
	r.Record("id", "line") // must not panic
	if got := r.Snapshot(); got != nil {
		t.Fatalf("nil ring returned %v", got)
	}
}

// Every refusal site is on a dial or accept path, and several run at once.
func TestRingConcurrentRecord(t *testing.T) {
	var r Ring
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				r.Record("id", fmt.Sprintf("%d/%d", i, j))
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				r.Snapshot()
			}
		}()
	}
	wg.Wait()
	if got := len(r.Snapshot()); got != RingSize {
		t.Fatalf("len = %d, want %d", got, RingSize)
	}
}

func TestRingStampSeam(t *testing.T) {
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	r := &Ring{now: func() time.Time { return at }}
	r.Record("id", "line")
	if got := r.Snapshot()[0].At; !got.Equal(at) {
		t.Fatalf("At = %v, want %v", got, at)
	}
}
