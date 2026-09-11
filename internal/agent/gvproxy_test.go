package agent

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// gvproxyFake records what the agent sent to gvproxy's in-guest API.
type gvproxyFake struct {
	mu     sync.Mutex
	calls  []string          // "POST /services/forwarder/expose"
	bodies []map[string]any  // decoded, in order
	status map[string]int    // path → status to answer with
	text   map[string]string // path → body to answer with
}

func newGvproxyFake() *gvproxyFake {
	return &gvproxyFake{status: map[string]int{}, text: map[string]string{}}
}

func (f *gvproxyFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	blob, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(blob, &body)
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.bodies = append(f.bodies, body)
	code, text := f.status[r.URL.Path], f.text[r.URL.Path]
	f.mu.Unlock()
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	if text != "" {
		io.WriteString(w, text)
	}
}

func (f *gvproxyFake) seen() ([]string, []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...), append([]map[string]any(nil), f.bodies...)
}

// The exact exchange podman itself performs for `-p`: unexpose first (a
// duplicate key is answered with "proxy already running for tcp on <local>",
// so a re-publish after an agent restart would fail forever without it), then
// expose with the three keys gvproxy's forwarder reads.
func TestPublishUnexposesFirst(t *testing.T) {
	f := newGvproxyFake()
	srv := httptest.NewServer(f)
	defer srv.Close()

	p := &Publisher{Gateway: srv.URL, Local: "127.0.0.1:4778"}
	if err := p.Publish("192.168.127.2:4777"); err != nil {
		t.Fatal(err)
	}
	calls, bodies := f.seen()
	want := []string{"POST /services/forwarder/unexpose", "POST /services/forwarder/expose"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("call %d = %q, want %q", i, calls[i], want[i])
		}
	}
	if got := bodies[0]; got["local"] != "127.0.0.1:4778" || got["protocol"] != "tcp" || len(got) != 2 {
		t.Fatalf("unexpose body = %v, want {local, protocol}", got)
	}
	if got := bodies[1]; got["local"] != "127.0.0.1:4778" || got["remote"] != "192.168.127.2:4777" || got["protocol"] != "tcp" || len(got) != 3 {
		t.Fatalf("expose body = %v, want {local, remote, protocol}", got)
	}
}

// gvproxy's refusals are one sentence and they are the whole diagnosis, so
// the status line alone is not enough.
func TestPublishReportsTheGatewaysWords(t *testing.T) {
	f := newGvproxyFake()
	f.status["/services/forwarder/expose"] = http.StatusInternalServerError
	f.text["/services/forwarder/expose"] = "proxy already running for tcp on 127.0.0.1:4778\n"
	srv := httptest.NewServer(f)
	defer srv.Close()

	err := (&Publisher{Gateway: srv.URL, Local: "127.0.0.1:4778"}).Publish("192.168.127.2:4777")
	if err == nil {
		t.Fatal("a 500 from the expose call was accepted")
	}
	if !strings.Contains(err.Error(), "proxy already running") {
		t.Fatalf("error %q does not carry gvproxy's own words", err)
	}
}

// A failed expose must not leave the publisher believing it published: the
// shutdown unexpose would then remove a forward someone else owns.
func TestUnpublishOnlyAfterASuccessfulPublish(t *testing.T) {
	f := newGvproxyFake()
	f.status["/services/forwarder/expose"] = http.StatusBadRequest
	srv := httptest.NewServer(f)
	defer srv.Close()

	p := &Publisher{Gateway: srv.URL, Local: "127.0.0.1:4778"}
	if err := p.Publish("192.168.127.2:4777"); err == nil {
		t.Fatal("a 400 was accepted")
	}
	before, _ := f.seen()
	p.Unpublish()
	after, _ := f.seen()
	if len(after) != len(before) {
		t.Fatalf("Unpublish called the gateway after a failed publish: %v", after[len(before):])
	}

	f.status["/services/forwarder/expose"] = http.StatusOK
	if err := p.Publish("192.168.127.2:4777"); err != nil {
		t.Fatal(err)
	}
	p.Unpublish()
	calls, _ := f.seen()
	if last := calls[len(calls)-1]; last != "POST /services/forwarder/unexpose" {
		t.Fatalf("last call = %q, want the shutdown unexpose", last)
	}
}

// A gateway that does not answer must not hang the agent's startup or its
// shutdown: every call is bounded.
func TestPublishIsBounded(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// Order matters: srv.Close waits for in-flight handlers, so the handler
	// has to be released before it runs (defers are LIFO).
	defer srv.Close()
	defer close(block)

	p := &Publisher{Gateway: srv.URL, Local: "127.0.0.1:4778"}
	done := make(chan error, 1)
	go func() { done <- p.Publish("192.168.127.2:4777") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a gateway that never answers was accepted")
		}
	case <-time.After(4 * gvproxyTimeout):
		t.Fatal("Publish did not give up on an unresponsive gateway")
	}
}

// The publish hangs off the guest NIC listener, which is the address the Mac
// has to reach. Loopback and wildcard listeners are not publishable: gvproxy
// cannot forward to the guest's own loopback, and a wildcard bind names no
// address at all.
func TestPublishSkipsUnpublishableAddresses(t *testing.T) {
	f := newGvproxyFake()
	srv := httptest.NewServer(f)
	defer srv.Close()

	for _, addr := range []string{"127.0.0.1:4777", "[::1]:4777", "0.0.0.0:4777", "[::]:4777", "garbage"} {
		tl := &TransportListeners{
			logf:      func(string, ...any) {},
			done:      make(chan struct{}),
			publisher: &Publisher{Gateway: srv.URL, Local: "127.0.0.1:4778"},
		}
		tl.publish(addr)
		time.Sleep(20 * time.Millisecond)
		if calls, _ := f.seen(); len(calls) != 0 {
			t.Fatalf("publish(%q) reached the gateway: %v", addr, calls)
		}
		close(tl.done)
	}
}

// The whole point of the flag: after the guest NIC listener comes up, the
// forward exists, and Close removes it.
func TestTransportListenersPublishAndUnpublish(t *testing.T) {
	f := newGvproxyFake()
	srv := httptest.NewServer(f)
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	guestAddr := "192.168.127.2:4777"

	tl := &TransportListeners{
		allow:     newSourceAllow(nil),
		serve:     func(net.Listener) {},
		logf:      func(string, ...any) {},
		done:      make(chan struct{}),
		publisher: &Publisher{Gateway: srv.URL, Local: "127.0.0.1:4778"},
	}
	tl.lns = append(tl.lns, ln)
	tl.publish(guestAddr)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls, _ := f.seen(); len(calls) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	calls, bodies := f.seen()
	if len(calls) < 2 || calls[1] != "POST /services/forwarder/expose" {
		t.Fatalf("the guest NIC listener was not published: %v", calls)
	}
	if bodies[1]["remote"] != guestAddr {
		t.Fatalf("published remote = %v, want the guest NIC address %q", bodies[1]["remote"], guestAddr)
	}

	if err := tl.Close(); err != nil {
		t.Fatal(err)
	}
	calls, _ = f.seen()
	if last := calls[len(calls)-1]; last != "POST /services/forwarder/unexpose" {
		t.Fatalf("Close did not unexpose: %v", calls)
	}
}
