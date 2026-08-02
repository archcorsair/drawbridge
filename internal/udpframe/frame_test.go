package udpframe

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

var mu sync.Mutex

func roundTrip(t *testing.T, peer netip.AddrPort, payload []byte) (netip.AddrPort, []byte) {
	t.Helper()
	var b bytes.Buffer
	if err := WriteFrame(&b, &mu, peer, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b.Len() != HeaderLen+len(payload) {
		t.Fatalf("frame size %d, want %d", b.Len(), HeaderLen+len(payload))
	}
	buf := make([]byte, MaxPayload)
	gotPeer, gotPayload, err := ReadFrame(&b, buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return gotPeer, gotPayload
}

func TestRoundTripV4Mapped(t *testing.T) {
	peer := netip.MustParseAddrPort("192.0.2.7:5353")
	p, pl := roundTrip(t, peer, []byte("hello"))
	// v4 goes over the wire v4-mapped and comes back Unmap()ed.
	if p != peer {
		t.Fatalf("peer %v, want %v", p, peer)
	}
	if string(pl) != "hello" {
		t.Fatalf("payload %q", pl)
	}
}

func TestRoundTripV6(t *testing.T) {
	peer := netip.MustParseAddrPort("[fd77::2]:53")
	p, pl := roundTrip(t, peer, []byte{0xde, 0xad})
	if p != peer || len(pl) != 2 {
		t.Fatalf("got %v %x", p, pl)
	}
}

func TestZeroLengthPayload(t *testing.T) {
	peer := netip.MustParseAddrPort("127.0.0.1:9999")
	_, pl := roundTrip(t, peer, nil)
	if len(pl) != 0 {
		t.Fatalf("payload %x, want empty", pl)
	}
}

func TestMaxPayload(t *testing.T) {
	peer := netip.MustParseAddrPort("127.0.0.1:1")
	big := bytes.Repeat([]byte{0xab}, MaxPayload)
	_, pl := roundTrip(t, peer, big)
	if !bytes.Equal(pl, big) {
		t.Fatal("max payload corrupted")
	}
}

func TestOversizePayloadRejectedOnWrite(t *testing.T) {
	var b bytes.Buffer
	err := WriteFrame(&b, &mu, netip.MustParseAddrPort("127.0.0.1:1"), make([]byte, MaxPayload+1))
	if err == nil {
		t.Fatal("oversize write accepted")
	}
	if b.Len() != 0 {
		t.Fatal("partial frame written")
	}
}

func TestOversizeLengthRejectedOnRead(t *testing.T) {
	raw := make([]byte, HeaderLen)
	raw[0], raw[1] = 0xff, 0xff // 65535 > MaxPayload
	raw[19], raw[20] = 0x12, 0x34
	_, _, err := ReadFrame(bytes.NewReader(raw), make([]byte, MaxPayload))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestNonzeroFlagsRejected(t *testing.T) {
	var b bytes.Buffer
	if err := WriteFrame(&b, &mu, netip.MustParseAddrPort("127.0.0.1:1"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	raw[2] = 0x80
	_, _, err := ReadFrame(bytes.NewReader(raw), make([]byte, MaxPayload))
	if err == nil || !strings.Contains(err.Error(), "flags") {
		t.Fatalf("err = %v", err)
	}
}

func TestZeroPortRejectedBothWays(t *testing.T) {
	var b bytes.Buffer
	peer := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)
	if err := WriteFrame(&b, &mu, peer, []byte("x")); err == nil {
		t.Fatal("zero-port write accepted")
	}
	raw := make([]byte, HeaderLen+1)
	raw[1] = 1 // length 1, port stays 0
	_, _, err := ReadFrame(bytes.NewReader(raw), make([]byte, MaxPayload))
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("err = %v", err)
	}
}

func TestTornReadSurfacesAsError(t *testing.T) {
	var b bytes.Buffer
	if err := WriteFrame(&b, &mu, netip.MustParseAddrPort("10.0.0.1:53"), []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	// Truncate mid-payload: reader must fail, not return a short datagram.
	raw := b.Bytes()[:HeaderLen+3]
	_, _, err := ReadFrame(bytes.NewReader(raw), make([]byte, MaxPayload))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want unexpected EOF", err)
	}
	// Truncate mid-header too.
	_, _, err = ReadFrame(bytes.NewReader(b.Bytes()[:HeaderLen-5]), make([]byte, MaxPayload))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("header err = %v, want unexpected EOF", err)
	}
}

// TestConcurrentWritersFrameGranularity proves the single-Write + mutex
// contract: two goroutines hammering one stream never interleave inside a
// frame.
func TestConcurrentWritersFrameGranularity(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	var wmu sync.Mutex
	peers := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:1111"),
		netip.MustParseAddrPort("127.0.0.1:2222"),
	}
	payloads := [][]byte{
		bytes.Repeat([]byte{0x11}, 1000),
		bytes.Repeat([]byte{0x22}, 3000),
	}
	const perWriter = 50
	var wg sync.WaitGroup
	for i := range peers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range perWriter {
				if err := WriteFrame(a, &wmu, peers[i], payloads[i]); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); a.Close(); close(done) }()

	buf := make([]byte, MaxPayload)
	counts := map[netip.AddrPort]int{}
	for {
		peer, payload, err := ReadFrame(b, buf)
		if err != nil {
			break
		}
		want := byte(0x11)
		wantLen := 1000
		if peer == peers[1] {
			want, wantLen = 0x22, 3000
		}
		if len(payload) != wantLen {
			t.Fatalf("peer %v payload len %d, want %d", peer, len(payload), wantLen)
		}
		for _, c := range payload {
			if c != want {
				t.Fatalf("peer %v interleaved payload", peer)
			}
		}
		counts[peer]++
	}
	<-done
	if counts[peers[0]] != perWriter || counts[peers[1]] != perWriter {
		t.Fatalf("frame counts %v, want %d each", counts, perWriter)
	}
}
