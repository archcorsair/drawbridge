package agent

import (
	"sync"
	"testing"
	"time"
)

func TestSuperviseCap(t *testing.T) {
	c := &superviseCap{max: 3}
	for i := 0; i < 3; i++ {
		if !c.acquire() {
			t.Fatalf("acquire %d refused below the cap", i)
		}
	}
	if c.acquire() {
		t.Fatal("acquire succeeded at the cap")
	}
	if c.inUse() != 3 {
		t.Fatalf("refused acquire leaked a slot: inUse=%d", c.inUse())
	}
	c.release()
	if !c.acquire() {
		t.Fatal("slot not reusable after release")
	}

	// Concurrent acquirers never exceed max and the count balances.
	big := &superviseCap{max: 50}
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if big.acquire() {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != 50 || big.inUse() != 50 {
		t.Fatalf("granted=%d inUse=%d, want 50/50", granted, big.inUse())
	}
	for i := 0; i < 50; i++ {
		big.release()
	}
	if big.inUse() != 0 {
		t.Fatalf("inUse=%d after releasing everything", big.inUse())
	}
}

func TestPeerLimiter(t *testing.T) {
	l := newPeerLimiter(time.Minute)
	t0 := time.Unix(1000, 0)
	if !l.allow(1000, t0) {
		t.Fatal("first line suppressed")
	}
	if l.allow(1000, t0.Add(30*time.Second)) {
		t.Fatal("second line within the window not suppressed")
	}
	if !l.allow(1001, t0.Add(time.Second)) {
		t.Fatal("another uid suppressed by the first")
	}
	if !l.allow(1000, t0.Add(61*time.Second)) {
		t.Fatal("line after the window suppressed")
	}
}
