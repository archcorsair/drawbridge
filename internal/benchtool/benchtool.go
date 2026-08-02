// Package benchtool is both halves of the drawbridge latency/throughput
// benchmark: fixed-mode servers (echo / sink / source) and measuring
// clients (first-byte RTT, bulk transfer, connect bursts). Portable Go —
// the Mac orchestrator uses it in-process, and the guest runs it through
// the drawbridge-agent benchclient/benchserve subcommands.
package benchtool

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"
)

// FirstBytePayload is the echo payload for RTT measurements: small enough
// to sit in one segment, large enough to be a realistic request line.
const FirstBytePayload = 16

// Serve accepts on ln until it closes. Modes:
//
//	echo   — copy bytes back to the client.
//	sink   — discard until client half-close, then write a 1-byte ack
//	         (lets the client time a fully-delivered upload).
//	source — read an 8-byte BE size request, write that many bytes, close.
func Serve(ln net.Listener, mode string) error {
	if mode != "echo" && mode != "sink" && mode != "source" {
		return fmt.Errorf("unknown serve mode %q", mode)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go serveConn(c, mode)
	}
}

func serveConn(c net.Conn, mode string) {
	defer c.Close()
	switch mode {
	case "echo":
		io.Copy(c, c)
	case "sink":
		io.Copy(io.Discard, c)
		c.Write([]byte{1})
	case "source":
		var hdr [8]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint64(hdr[:])
		buf := make([]byte, 256<<10)
		for sent := uint64(0); sent < n; {
			chunk := uint64(len(buf))
			if n-sent < chunk {
				chunk = n - sent
			}
			w, err := c.Write(buf[:chunk])
			if err != nil {
				return
			}
			sent += uint64(w)
		}
	}
}

// Sample is one connect + echo round trip.
type Sample struct {
	Connect time.Duration // dial start -> connect() returned
	RTT     time.Duration // dial start -> echo fully read
}

// FirstByte runs iters sequential connect+echo cycles against an echo
// server.
func FirstByte(addr string, iters int) ([]Sample, error) {
	out := make([]Sample, 0, iters)
	for i := 0; i < iters; i++ {
		s, err := firstByteOnce(addr)
		if err != nil {
			return nil, fmt.Errorf("iter %d: %w", i, err)
		}
		out = append(out, s)
	}
	return out, nil
}

func firstByteOnce(addr string) (Sample, error) {
	payload := make([]byte, FirstBytePayload)
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return Sample{}, err
	}
	defer c.Close()
	connect := time.Since(start)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return Sample{}, err
	}
	if _, err := io.ReadFull(c, payload); err != nil {
		return Sample{}, fmt.Errorf("echo read: %w", err)
	}
	return Sample{Connect: connect, RTT: time.Since(start)}, nil
}

// Burst runs rounds waves of conns simultaneous connect+echo cycles and
// returns every sample. With conns above the reverse-dial pool size, the
// tail of the distribution shows the replenish serialization.
func Burst(addr string, conns, rounds int) ([]Sample, error) {
	var (
		mu  sync.Mutex
		out []Sample
	)
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		errs := make(chan error, conns)
		start := make(chan struct{})
		for i := 0; i < conns; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				s, err := firstByteOnce(addr)
				if err != nil {
					errs <- err
					return
				}
				mu.Lock()
				out = append(out, s)
				mu.Unlock()
			}()
		}
		close(start)
		wg.Wait()
		select {
		case err := <-errs:
			return nil, fmt.Errorf("round %d: %w", r, err)
		default:
		}
	}
	return out, nil
}

// Upload writes n bytes to a sink server and waits for its ack.
func Upload(addr string, n int64) (time.Duration, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	start := time.Now()
	buf := make([]byte, 1<<20)
	for sent := int64(0); sent < n; {
		chunk := int64(len(buf))
		if n-sent < chunk {
			chunk = n - sent
		}
		w, err := c.Write(buf[:chunk])
		if err != nil {
			return 0, err
		}
		sent += int64(w)
	}
	if t, ok := c.(*net.TCPConn); ok {
		t.CloseWrite()
	}
	var ack [1]byte
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		return 0, fmt.Errorf("sink ack: %w", err)
	}
	return time.Since(start), nil
}

// Download requests n bytes from a source server and reads to EOF.
func Download(addr string, n int64) (time.Duration, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	start := time.Now()
	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], uint64(n))
	if _, err := c.Write(hdr[:]); err != nil {
		return 0, err
	}
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	got, err := io.Copy(io.Discard, c)
	if err != nil {
		return 0, err
	}
	if got != n {
		return 0, fmt.Errorf("source sent %d bytes, want %d", got, n)
	}
	return time.Since(start), nil
}

// Quantiles are microseconds so they read naturally in JSON output.
type Quantiles struct {
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	P99 int64 `json:"p99"`
	Max int64 `json:"max"`
}

func QuantilesOf(ds []time.Duration) Quantiles {
	if len(ds) == 0 {
		return Quantiles{}
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	at := func(q float64) int64 {
		i := int(q * float64(len(s)-1))
		return s[i].Microseconds()
	}
	return Quantiles{P50: at(0.50), P95: at(0.95), P99: at(0.99), Max: s[len(s)-1].Microseconds()}
}

func Connects(samples []Sample) []time.Duration {
	out := make([]time.Duration, len(samples))
	for i, s := range samples {
		out[i] = s.Connect
	}
	return out
}

func RTTs(samples []Sample) []time.Duration {
	out := make([]time.Duration, len(samples))
	for i, s := range samples {
		out[i] = s.RTT
	}
	return out
}

// MBps is decimal megabytes per second.
func MBps(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / 1e6 / d.Seconds()
}
