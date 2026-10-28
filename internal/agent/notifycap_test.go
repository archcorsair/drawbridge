package agent

import (
	"os"
	"regexp"
	"strconv"
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

// fakeFiles maps fd numbers to the "open file" they refer to, standing in
// for kcmp(KCMP_FILE) on the Mac.
type fakeFiles map[int]string

func (f fakeFiles) same(a, b int) bool { return f[a] != "" && f[a] == f[b] }

// 2026-10-28 NEW-2: a file already under supervision is a duplicate,
// whichever fd number it arrives on, and a duplicate takes no slot.
func TestAdmitProbeDedupe(t *testing.T) {
	files := fakeFiles{3: "L1", 4: "L1", 5: "L2"}
	c := &superviseCap{max: 8}
	if v := c.admitProbe(3, files.same); v != admitted {
		t.Fatalf("first handoff of L1: %v, want admitted", v)
	}
	if v := c.admitProbe(4, files.same); v != admitDuplicate {
		t.Fatalf("second handoff of L1: %v, want admitDuplicate", v)
	}
	if v := c.admitProbe(5, files.same); v != admitted {
		t.Fatalf("first handoff of L2: %v, want admitted", v)
	}
	if c.inUse() != 2 || c.tracked() != 2 {
		t.Fatalf("inUse=%d tracked=%d, want 2/2", c.inUse(), c.tracked())
	}
	// Once L1's supervisor is gone, L1 is admissible again.
	c.untrack(3)
	c.release()
	if v := c.admitProbe(4, files.same); v != admitted {
		t.Fatalf("L1 after its supervisor ended: %v, want admitted", v)
	}
}

// A duplicate check that cannot run (kcmp missing) degrades to the cap.
func TestAdmitProbeNoComparator(t *testing.T) {
	never := func(a, b int) bool { return false }
	c := &superviseCap{max: 2}
	for fd := 3; fd < 5; fd++ {
		if v := c.admitProbe(fd, never); v != admitted {
			t.Fatalf("fd %d: %v, want admitted", fd, v)
		}
	}
	if v := c.admitProbe(5, never); v != admitFull {
		t.Fatalf("over the cap: %v, want admitFull", v)
	}
	if c.inUse() != 2 || c.tracked() != 2 {
		t.Fatalf("refusal leaked a slot or an entry: inUse=%d tracked=%d", c.inUse(), c.tracked())
	}
}

// Concurrent handoffs of one file: exactly one is admitted.
func TestAdmitProbeConcurrentDuplicates(t *testing.T) {
	files := fakeFiles{}
	for fd := 0; fd < 64; fd++ {
		files[fd] = "L"
	}
	c := &superviseCap{max: 64}
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for fd := 0; fd < 64; fd++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.admitProbe(fd, files.same) == admitted {
				mu.Lock()
				n++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if n != 1 || c.inUse() != 1 {
		t.Fatalf("admitted %d copies of one file (inUse=%d), want 1", n, c.inUse())
	}
}

// 2026-10-28 M3, decision E2: the trusted bucket (OCI socket, fd-store
// adoption) never refuses, whatever the capped bucket holds, and takes no
// capped slot.
func TestAdmitTrustedIgnoresProbeCap(t *testing.T) {
	never := func(a, b int) bool { return false }
	c := &superviseCap{max: 1}
	if v := c.admitProbe(3, never); v != admitted {
		t.Fatalf("probe: %v", v)
	}
	if v := c.admitProbe(4, never); v != admitFull {
		t.Fatalf("probe over the cap: %v, want admitFull", v)
	}
	for fd := 10; fd < 20; fd++ {
		if n := c.admitTrusted(fd); n != int64(fd-9) {
			t.Fatalf("trusted fd %d: count %d, want %d", fd, n, fd-9)
		}
	}
	if c.inUse() != 1 || c.trustedInUse() != 10 || c.tracked() != 11 {
		t.Fatalf("inUse=%d trusted=%d tracked=%d, want 1/10/11", c.inUse(), c.trustedInUse(), c.tracked())
	}
	// A trusted fd is still a known file for the probe path's check.
	files := fakeFiles{10: "ctr", 30: "ctr"}
	if v := c.admitProbe(30, files.same); v != admitDuplicate {
		t.Fatalf("probe copy of a trusted fd: %v, want admitDuplicate", v)
	}
	c.releaseTrusted()
	if c.trustedInUse() != 9 {
		t.Fatalf("trusted after release = %d, want 9", c.trustedInUse())
	}
}

// The adoption gate (fdstore.go) takes a capped slot and must never refuse
// an fd the unit's store can hold.
func TestProbeCapCoversFdStore(t *testing.T) {
	re := regexp.MustCompile(`FileDescriptorStoreMax=(\d+)`)
	for _, path := range []string{"../guestbin/assets/drawbridge-agent.service", "../../justfile"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s: no FileDescriptorStoreMax=", path)
		}
		n, _ := strconv.Atoi(string(m[1]))
		if int64(n) > maxSupervisedNotifyFds {
			t.Fatalf("%s: FileDescriptorStoreMax=%d > maxSupervisedNotifyFds %d: adoption could close a container's only listener",
				path, n, maxSupervisedNotifyFds)
		}
	}
}
