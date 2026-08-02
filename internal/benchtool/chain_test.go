package benchtool

import (
	"net"
	"testing"

	"github.com/archcorsair/drawbridge/internal/proxy"
)

// hop relays every accepted conn to backend through proxy.Splice — the same
// two-hop chain a drawbridge flow crosses (gateway proxy + transport
// stream). Regression: a bulk upload's half-close and the sink's 1-byte ack
// must both survive the chain.
func hop(t *testing.T, backend string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				b, err := net.Dial("tcp", backend)
				if err != nil {
					c.Close()
					return
				}
				proxy.Splice(c, b)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestUploadThroughSpliceChain(t *testing.T) {
	sink := server(t, "sink")
	chain := hop(t, hop(t, sink))
	const n = 64 << 20
	if d, err := Upload(chain, n); err != nil {
		t.Fatalf("upload through 2-hop splice chain: %v (after %v)", err, d)
	}
}

func TestDownloadThroughSpliceChain(t *testing.T) {
	src := server(t, "source")
	chain := hop(t, hop(t, src))
	const n = 64 << 20
	if d, err := Download(chain, n); err != nil {
		t.Fatalf("download through 2-hop splice chain: %v (after %v)", err, d)
	}
}
