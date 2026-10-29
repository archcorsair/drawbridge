package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/macsync"
	"github.com/archcorsair/drawbridge/internal/mirror"
	"github.com/archcorsair/drawbridge/internal/transport"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// unresolvedColima is a colima target no machine can satisfy: the instance
// and lease names exist nowhere, so limactl and the lease db both come up
// empty. With no loopback forward of its own, it resolves to nothing.
func unresolvedColima() limaaddr.Target {
	return limaaddr.Target{
		VM:        "colima-p08-no-such-instance",
		LeaseName: "colima-p08-no-such-instance",
		Provider:  vmprovider.ProviderColima,
	}
}

// NEW-X1 / E5 on the live re-resolve path: a daemon that was on a vzNAT
// address when its colima VM stopped publishes "no endpoint" and the
// resolver's note, returns "" to the reconnect loops, and does not drift to
// 127.0.0.1:4777.
func TestRefreshPublishesAnUnresolvedTarget(t *testing.T) {
	r := newResolver(unresolvedColima(), transport.DefaultAgentPort, "tcp://192.168.64.20:4777", limaaddr.SourceVZNATLeases, "")
	if got := r.refresh(); got != "" {
		t.Fatalf("refresh() = %q, want no endpoint", got)
	}
	res := r.resolution()
	if res.Endpoint != "" || res.Source != limaaddr.SourceUnresolved {
		t.Fatalf("resolution = %+v, want empty endpoint, source %q", res, limaaddr.SourceUnresolved)
	}
	for _, want := range []string{"no endpoint for colima instance", "Not falling back to 127.0.0.1:4777"} {
		if !strings.Contains(res.Note, want) {
			t.Fatalf("note %q missing %q", res.Note, want)
		}
	}
	if r.currentSource() != limaaddr.SourceUnresolved {
		t.Fatalf("currentSource = %q", r.currentSource())
	}
	// Inside the coalescing window the answer is the stored one: still none.
	if got := r.refresh(); got != "" {
		t.Fatalf("coalesced refresh() = %q, want no endpoint", got)
	}
}

// The Lima half of the same table at the daemon layer: the same missing VM,
// provider lima, still lands on the SSH forward.
func TestRefreshLimaStillFallsBackToTheForward(t *testing.T) {
	tgt := unresolvedColima()
	tgt.Provider = vmprovider.ProviderLima
	r := newResolver(tgt, transport.DefaultAgentPort, "", limaaddr.SourceUnresolved, "")
	if got := r.refresh(); got != "tcp://127.0.0.1:4777" {
		t.Fatalf("refresh() = %q, want the Lima loopback forward", got)
	}
	if res := r.resolution(); res.Source != limaaddr.SourceSSHForwarder {
		t.Fatalf("source = %q, want %q", res.Source, limaaddr.SourceSSHForwarder)
	}
}

// Startup with an empty endpoint is a state, not an error, and carries the
// auto port so the resolver and the skip-list still know where the
// transport will be.
func TestParseAgent(t *testing.T) {
	addr, port, err := parseAgent("")
	if err != nil || addr != "" || port != transport.DefaultAgentPort {
		t.Fatalf("parseAgent(\"\") = %q, %d, %v", addr, port, err)
	}
	addr, port, err = parseAgent("192.168.64.5:4790")
	if err != nil || addr != "tcp://192.168.64.5:4790" || port != 4790 {
		t.Fatalf("parseAgent(host:port) = %q, %d, %v", addr, port, err)
	}
	if _, _, err := parseAgent("not an endpoint"); err == nil {
		t.Fatal("parseAgent accepted garbage")
	}
}

// The consumers of an empty endpoint, as drawbridged wires them: the 'E'
// mirror and the 'M' syncer both reconnect once a second, so with no
// endpoint they must neither crash nor dial (transport.Dial("") fails in
// Parse, before any socket exists), and they must keep consulting the
// re-resolve hook, which is the only thing that can end the state.
func TestConsumersRetryWithoutAnEndpoint(t *testing.T) {
	var mirrorCalls, syncCalls atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	m := mirror.New("", "127.0.0.1")
	m.ReResolve = func() string { mirrorCalls.Add(1); return "" }
	s := &macsync.Syncer{
		AgentAddr: "",
		Poll:      func() ([]macsync.Listener, error) { return nil, nil },
		ReResolve: func() string { syncCalls.Add(1); return "" },
		PoolSize:  1,
	}

	done := make(chan struct{}, 2)
	go func() { m.Run(ctx); done <- struct{}{} }()
	go func() { s.Run(ctx); done <- struct{}{} }()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a consumer did not stop with its context")
		}
	}
	if mirrorCalls.Load() == 0 || syncCalls.Load() == 0 {
		t.Fatalf("re-resolve hook not consulted: mirror %d, sync %d", mirrorCalls.Load(), syncCalls.Load())
	}
	if m.Snapshot().SessionUp || s.Snapshot().SessionUp {
		t.Fatal("a session reported up with no endpoint")
	}
}
