// The gvproxy port-forward publisher (docs/podman.md §3.2, branch A).
//
// Deliberately not linux-tagged, like listen.go: it is net/http and string
// handling, and its unit tests run on the Mac in `go test ./internal/...`.
//
// Why the guest publishes its own port. On macOS podman starts gvproxy with
// no host-side control socket at all (no -listen, no -services: verified in
// the 7.0 spike), so the only port-forwarding API that exists is the one
// inside the guest at http://192.168.127.1, the same endpoint podman itself
// POSTs to for `-p`. And gvproxy's forwards die with gvproxy on every
// `podman machine stop`, so a Mac-side publish would have to be re-created by
// hand after every machine restart. The agent restarts with the machine
// because systemd supervises it, so hanging the publish off the agent's
// transport start is what makes the forward come back on its own.
//
// Nothing about the wire changes: the transport protocol on the forwarded
// conn is byte-identical, and the Mac still writes nothing before the
// conn-type frame.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultGvproxyGateway is gvproxy's in-guest API. The subnet is fixed
// (192.168.127.0/24, gateway .1, machine .2) and podman never changes it, but
// this is a flag's default rather than a constant so a non-podman gvproxy
// user can point the agent elsewhere.
const DefaultGvproxyGateway = "http://192.168.127.1"

// gvproxyTimeout bounds each API call. The gateway is one hop away over a
// user-mode network; anything slower than this is a gvproxy that is not
// answering, and the retry loop is the right response to that.
const gvproxyTimeout = 2 * time.Second

// unexposeBudget is the shutdown allowance. Best effort: the agent is on its
// way out, and a forward that outlives it is cleaned up by the next publish
// (which unexposes first) or by the next machine stop.
const unexposeBudget = time.Second

// expose is gvproxy's request body, and podman's own
// (libpod/networking_machine.go's machineExpose).
type expose struct {
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	Protocol string `json:"protocol"`
}

type unexpose struct {
	Local    string `json:"local"`
	Protocol string `json:"protocol"`
}

// Publisher publishes one guest address on one Mac loopback port through
// gvproxy's in-guest forwarding API.
type Publisher struct {
	// Gateway is the API base URL (DefaultGvproxyGateway).
	Gateway string

	// Local is the Mac-side address gvproxy binds, host:port. It is the
	// endpoint `drawbridge up` recorded and the Mac dials.
	Local string

	// Logf is the agent's logger; nil silences the publisher.
	Logf func(string, ...any)

	// Client is the HTTP client, defaulted on first use. No redirects are
	// followed: the gateway is a fixed local address, and a redirect from it
	// is not something to chase.
	Client *http.Client

	mu     sync.Mutex
	remote string // the last successfully published remote, for the unexpose
}

func (p *Publisher) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

func (p *Publisher) client() *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Client == nil {
		p.Client = &http.Client{
			Timeout: gvproxyTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return p.Client
}

// Publish points gvproxy's forward for p.Local at remote (the guest address
// the transport is listening on).
//
// Unexpose first, errors ignored: gvproxy answers a duplicate key with
// "proxy already running for tcp on <local>", so a re-publish after an agent
// restart would fail forever without it. Nothing is read back except the
// status, the agent has no use for the body and no business parsing it.
func (p *Publisher) Publish(remote string) error {
	_ = p.post("/services/forwarder/unexpose", unexpose{Local: p.Local, Protocol: "tcp"}, gvproxyTimeout)
	if err := p.post("/services/forwarder/expose", expose{Local: p.Local, Remote: remote, Protocol: "tcp"}, gvproxyTimeout); err != nil {
		return err
	}
	p.mu.Lock()
	p.remote = remote
	p.mu.Unlock()
	return nil
}

// Unpublish removes the forward. Best effort, on a shorter budget: it runs on
// the agent's way out.
func (p *Publisher) Unpublish() {
	p.mu.Lock()
	published := p.remote != ""
	p.mu.Unlock()
	if !published {
		return
	}
	if err := p.post("/services/forwarder/unexpose", unexpose{Local: p.Local, Protocol: "tcp"}, unexposeBudget); err != nil {
		p.logf("drawbridge-agent: gvproxy: unexpose %s on shutdown: %v (it dies with gvproxy anyway)", p.Local, err)
		return
	}
	p.logf("drawbridge-agent: gvproxy: unexposed %s", p.Local)
}

// post sends one API call and reports the status. The budget is per request
// (a context, not Client.Timeout) so the shutdown unexpose can be tighter
// than a publish without mutating a client another goroutine may be using.
// The response body is drained and discarded so the connection can be reused,
// and bounded so a gateway that answers with a novel does not become the
// agent's memory problem.
func (p *Publisher) post(path string, body any, budget time.Duration) error {
	blob, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := strings.TrimRight(p.gateway(), "/") + path
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(blob))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	trailer, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s: %s%s", url, resp.Status, statusTail(trailer))
	}
	return nil
}

func (p *Publisher) gateway() string {
	if strings.TrimSpace(p.Gateway) == "" {
		return DefaultGvproxyGateway
	}
	return p.Gateway
}

// statusTail appends gvproxy's own words to a non-2xx, on one line. Its
// refusals are one sentence ("proxy already running for tcp on …") and they
// are the whole diagnosis.
func statusTail(b []byte) string {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return ": " + s
}
