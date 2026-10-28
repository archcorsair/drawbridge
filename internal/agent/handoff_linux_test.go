//go:build linux

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// 2026-10-28 M3, L14, NEW-1 and NEW-2 (decision E2): the probe socket
// dedupes by open file and bounds its read, the OCI socket is never
// refused for capacity and never waits for EOF. None of these tests need
// BPF or root; they need seccomp, kcmp, and Linux.

// handoffAgent is an Agent with only the supervisor's parts: no BPF, no
// fd store (an empty socket path, whatever NOTIFY_SOCKET says).
func handoffAgent(probeCap int64) *Agent {
	return &Agent{
		store:    &notifyStore{},
		cap:      superviseCap{max: probeCap},
		refusals: newPeerLimiter(refusalLogEvery),
	}
}

// syncBuf is a log sink the supervisor goroutines may write while the
// test reads it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *syncBuf {
	t.Helper()
	buf := &syncBuf{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// threadListener installs an allow-everything filter with
// SECCOMP_FILTER_FLAG_NEW_LISTENER on one locked OS thread and returns the
// listener fd. A real listener, so IsListener and kcmp see what they see
// in production, and a filter that never notifies, so nothing in the test
// process blocks on it. release ends the thread (a locked goroutine that
// exits takes its thread with it), which is the filter's only task: the
// listener then reports POLLHUP and its supervisor returns. Each call
// needs its own thread: the kernel allows one listener per filter chain.
func threadListener(t *testing.T) (fd int, release func()) {
	t.Helper()
	type result struct {
		fd  int
		err error
	}
	ch := make(chan result, 1)
	done := make(chan struct{})
	go func() {
		// Never unlocked once the filter is in: the thread carries it.
		// Not the main thread, though: a locked goroutine exiting there
		// wedges the thread instead of ending it, and the filter would
		// keep a live task for the rest of the test binary.
		for tries := 0; ; tries++ {
			runtime.LockOSThread()
			if unix.Gettid() != unix.Getpid() {
				break
			}
			runtime.UnlockOSThread()
			if tries == 100 {
				ch <- result{-1, errors.New("could not get off the main thread")}
				return
			}
			time.Sleep(time.Millisecond)
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			ch <- result{-1, err}
			return
		}
		prog := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}}
		fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
		r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
			unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&fprog)))
		runtime.KeepAlive(prog)
		if errno != 0 {
			ch <- result{-1, errno}
			return
		}
		ch <- result{int(r), nil}
		<-done
	}()
	r := <-ch
	if r.err != nil {
		t.Fatalf("install listener filter: %v", r.err)
	}
	var once sync.Once
	release = func() { once.Do(func() { close(done) }) }
	t.Cleanup(func() {
		release()
		unix.Close(r.fd)
	})
	return r.fd, release
}

// openCopies counts the fds in this process that are the same open file
// as fd, fd included. The agent runs in-process here, so a handoff that
// was refused and closed leaves the count where it was, and one that is
// supervised raises it by one.
func openCopies(t *testing.T, fd int) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		other, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if sameOpenFile(fd, other) {
			n++
		}
	}
	return n
}

func requireKcmp(t *testing.T, fd int) {
	t.Helper()
	if !sameOpenFile(fd, fd) {
		t.Skip("kcmp(KCMP_FILE) unavailable on this kernel; the duplicate check degrades to off")
	}
}

func serveUnix(t *testing.T, name string, serve func(*net.UnixListener)) string {
	t.Helper()
	path := t.TempDir() + "/" + name
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serve(ln)
	return path
}

func handOver(t *testing.T, sock string, payload []byte, fd int) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, err := c.(*net.UnixConn).WriteMsgUnix(payload, unix.UnixRights(fd), nil); err != nil {
		t.Fatal(err)
	}
}

func ociState(t *testing.T, id string) []byte {
	t.Helper()
	st, err := json.Marshal(map[string]any{
		"ociVersion": "1.2.0",
		"fds":        []string{"seccompFd"},
		"pid":        os.Getpid(),
		"state":      map[string]any{"id": id, "status": "creating", "pid": os.Getpid(), "bundle": "/nonexistent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// NEW-2: one listener handed over twice is supervised once. The second
// copy is refused and closed; the first stays supervised until its filter
// dies.
func TestProbeDedupeByOpenFile(t *testing.T) {
	logs := captureLog(t)
	a := handoffAgent(8)
	sock := serveUnix(t, "notify.sock", a.ServeNotify)
	fd, release := threadListener(t)
	requireKcmp(t, fd)

	handOver(t, sock, []byte{0}, fd)
	waitFor(t, "first handoff supervised", func() bool { return a.cap.inUse() == 1 })
	handOver(t, sock, []byte{0}, fd)
	waitFor(t, "duplicate refused", func() bool { return strings.Contains(logs.String(), "already under supervision (same open file)") })

	if got := a.cap.inUse(); got != 1 {
		t.Fatalf("capped slots in use = %d after a duplicate, want 1", got)
	}
	if got := a.cap.tracked(); got != 1 {
		t.Fatalf("tracked fds = %d after a duplicate, want 1", got)
	}
	// The test's own fd plus the one supervised copy: the refused copy is
	// closed, not leaked.
	if got := openCopies(t, fd); got != 2 {
		t.Fatalf("open copies of the listener = %d, want 2 (ours + supervised)", got)
	}

	// The first copy was really under supervision: ending the filter's
	// only task ends it, frees the slot and closes the agent's copy.
	release()
	waitFor(t, "supervision to end on POLLHUP", func() bool { return a.cap.inUse() == 0 && a.cap.tracked() == 0 })
	waitFor(t, "supervised copy closed", func() bool { return openCopies(t, fd) == 1 })
}

// M3, decision E2: with the probe cap full, a probe handoff is refused and
// closed, and an OCI handoff is still supervised, under its own count.
func TestOCIAcceptedWhenProbeCapFull(t *testing.T) {
	logs := captureLog(t)
	a := handoffAgent(1)
	probeSock := serveUnix(t, "notify.sock", a.ServeNotify)
	ociSock := serveUnix(t, "oci.sock", a.ServeOCISeccomp)

	held, releaseHeld := threadListener(t)
	requireKcmp(t, held)
	handOver(t, probeSock, []byte{0}, held)
	waitFor(t, "probe cap filled", func() bool { return a.cap.inUse() == 1 })

	over, _ := threadListener(t)
	handOver(t, probeSock, []byte{0}, over)
	waitFor(t, "over-cap probe refused", func() bool {
		return strings.Contains(logs.String(), "probe-socket fds already under supervision")
	})
	if got := openCopies(t, over); got != 1 {
		t.Fatalf("over-cap probe fd: %d open copies, want 1 (refused and closed)", got)
	}

	ctr, releaseCtr := threadListener(t)
	handOver(t, ociSock, ociState(t, "cap-full"), ctr)
	waitFor(t, "OCI handoff supervised", func() bool { return a.cap.trustedInUse() == 1 })
	if !strings.Contains(logs.String(), "oci: supervising container cap-full") {
		t.Fatalf("no supervising line for the OCI handoff:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "via oci socket") {
		t.Fatalf("OCI handoff was refused:\n%s", logs.String())
	}
	if got := openCopies(t, ctr); got != 2 {
		t.Fatalf("OCI listener: %d open copies, want 2 (ours + supervised)", got)
	}
	if got := a.cap.inUse(); got != 1 {
		t.Fatalf("OCI handoff took a capped slot: inUse = %d, want 1", got)
	}

	releaseCtr()
	releaseHeld()
	waitFor(t, "both buckets to drain", func() bool {
		return a.cap.inUse() == 0 && a.cap.trustedInUse() == 0 && a.cap.tracked() == 0
	})
}

// L14: a connection that never sends is closed after probeHandoffTimeout
// rather than holding an agent fd and goroutine indefinitely.
func TestProbeHandoffReadDeadline(t *testing.T) {
	captureLog(t)
	prev := probeHandoffTimeout
	probeHandoffTimeout = 200 * time.Millisecond
	t.Cleanup(func() { probeHandoffTimeout = prev })

	a := handoffAgent(8)
	sock := serveUnix(t, "notify.sock", a.ServeNotify)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.SetReadDeadline(start.Add(5 * time.Second))
	_, err = c.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("idle conn: read = %v, want EOF from the agent closing it", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("idle conn closed after %v, want about %v", el, probeHandoffTimeout)
	}
}

// connPair returns two connected stream-socket ends as *net.UnixConn.
func connPair(t *testing.T) (agentEnd, senderEnd *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(fd int, name string) *net.UnixConn {
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c.(*net.UnixConn)
	}
	return wrap(fds[0], "agent"), wrap(fds[1], "sender")
}

// pipeHandoff returns a pipe whose read end is the fd to hand over. closed
// reports whether every read end is gone (a write fails with EPIPE) once
// the caller has closed its own copy.
func pipeHandoff(t *testing.T) (r int, closed func() bool) {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(p[1]) })
	return p[0], func() bool {
		_, err := unix.Write(p[1], []byte{0})
		return errors.Is(err, unix.EPIPE)
	}
}

// NEW-1: the state is decoded as soon as it is complete, even when it
// spans writes and the sender keeps the conn open (runc before 1.3.3).
func TestReadOCIStateNoEOF(t *testing.T) {
	ag, snd := connPair(t)
	r, _ := pipeHandoff(t)
	defer unix.Close(r)
	st := ociState(t, "split")
	half := len(st) / 2
	if _, _, err := snd.WriteMsgUnix(st[:half], unix.UnixRights(r), nil); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		snd.Write(st[half:]) // and never close
	}()
	ag.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	got, fds, err := readOCIState(ag)
	if err != nil {
		t.Fatalf("readOCIState: %v", err)
	}
	defer closeFds(fds)
	if got.State.ID != "split" || len(fds) != 1 {
		t.Fatalf("state id %q, %d fds; want split, 1", got.State.ID, len(fds))
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("decode waited %v: it should not wait for EOF", el)
	}
}

// The JSON is bounded: a sender that never finishes its object is cut off
// at ociStateMax and every fd it handed over is closed.
func TestReadOCIStateLimit(t *testing.T) {
	ag, snd := connPair(t)
	r, closed := pipeHandoff(t)
	if _, _, err := snd.WriteMsgUnix([]byte(`{"ociVersion":"`), unix.UnixRights(r), nil); err != nil {
		t.Fatal(err)
	}
	unix.Close(r)
	go func() {
		chunk := bytes.Repeat([]byte("a"), 64<<10)
		for i := 0; i <= ociStateMax/len(chunk)+1; i++ {
			if _, err := snd.Write(chunk); err != nil {
				return // the reader gave up: expected
			}
		}
	}()
	ag.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, fds, err := readOCIState(ag)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		closeFds(fds)
		t.Fatalf("oversized state: err = %v, want the size limit", err)
	}
	if !closed() {
		t.Fatal("handed-over fd still open after an oversized state")
	}
}

// A sender that stalls mid-JSON is cut off by the conn's deadline, and its
// fds are closed.
func TestReadOCIStateStalled(t *testing.T) {
	ag, snd := connPair(t)
	r, closed := pipeHandoff(t)
	if _, _, err := snd.WriteMsgUnix([]byte(`{"ociVersion":"1.2.0","fds":[`), unix.UnixRights(r), nil); err != nil {
		t.Fatal(err)
	}
	unix.Close(r)
	ag.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, fds, err := readOCIState(ag)
	if err == nil {
		closeFds(fds)
		t.Fatal("stalled sender: readOCIState succeeded")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("stalled sender: err = %v, want a deadline error", err)
	}
	if !closed() {
		t.Fatal("handed-over fd still open after a stalled handoff")
	}
}

// The wrapper's liveness probe (dial, close) reads as a bare io.EOF, which
// recvOCIState keeps out of the log.
func TestReadOCIStateLivenessProbe(t *testing.T) {
	ag, snd := connPair(t)
	snd.Close()
	ag.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := readOCIState(ag); err != io.EOF {
		t.Fatalf("dial+close: err = %v, want bare io.EOF", err)
	}
}
