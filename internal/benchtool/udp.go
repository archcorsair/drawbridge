package benchtool

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"time"
)

// UDP bench legs (docs/udp.md U4). Drops are legal UDP — every measuring
// loop counts them instead of failing, and callers bound the tolerable
// rate. Warmup absorbs the one-time stream-activation cost so the
// steady-state numbers are honest; the activation cost is what the first
// burst wave shows.

// UDPEchoServe echoes datagrams verbatim until the socket closes.
func UDPEchoServe(pc *net.UDPConn) error {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		pc.WriteToUDPAddrPort(buf[:n], from)
	}
}

// UDPHashServe replies to each datagram with the 8-byte BE FNV-1a of its
// payload — the ack for large-datagram integrity legs (the reply stays
// tiny, so macOS's net.inet.udp.maxdgram send cap never bites the server).
func UDPHashServe(pc *net.UDPConn) error {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		h := fnv.New64a()
		h.Write(buf[:n])
		var ack [8]byte
		binary.BigEndian.PutUint64(ack[:], h.Sum64())
		pc.WriteToUDPAddrPort(ack[:], from)
	}
}

// udpWarm round-trips one datagram with retries until the path is live
// (first-flight activation may drop) or the deadline passes.
func udpWarm(c *net.UDPConn, payload []byte, deadline time.Time) error {
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		c.Write(payload)
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := c.Read(buf); err == nil {
			return nil
		}
	}
	return fmt.Errorf("udp path to %s never became live", c.RemoteAddr())
}

// UDPRTT measures iters echo round trips of size-byte datagrams on one
// connected socket, after warmup. Timed-out iterations count as drops.
func UDPRTT(target string, iters, size int) ([]time.Duration, int, error) {
	c, err := net.Dial("udp", target)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()
	uc := c.(*net.UDPConn)
	payload := bytes.Repeat([]byte{0x55}, size)
	if err := udpWarm(uc, payload, time.Now().Add(10*time.Second)); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 65535)
	samples := make([]time.Duration, 0, iters)
	drops := 0
	for range iters {
		start := time.Now()
		uc.Write(payload)
		uc.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := uc.Read(buf); err != nil {
			drops++
			continue
		}
		samples = append(samples, time.Since(start))
	}
	return samples, drops, nil
}

// UDPBurst runs rounds waves of k FRESH sockets, each doing one echo round
// trip concurrently — the socket-per-query pattern (stub resolvers), which
// exercises flow-table churn. No per-socket warmup: the first wave shows
// the activation cost, later waves the steady state.
func UDPBurst(target string, k, rounds, size int) ([]time.Duration, int, error) {
	payload := bytes.Repeat([]byte{0x55}, size)
	var samples []time.Duration
	drops := 0
	for range rounds {
		type out struct {
			d  time.Duration
			ok bool
		}
		ch := make(chan out, k)
		for range k {
			go func() {
				c, err := net.Dial("udp", target)
				if err != nil {
					ch <- out{}
					return
				}
				defer c.Close()
				uc := c.(*net.UDPConn)
				start := time.Now()
				// A couple of in-socket retries: the very first datagram
				// of a wave can race stream activation.
				buf := make([]byte, 65535)
				for attempt := 0; attempt < 3; attempt++ {
					uc.Write(payload)
					uc.SetReadDeadline(time.Now().Add(time.Second))
					if _, err := uc.Read(buf); err == nil {
						ch <- out{time.Since(start), true}
						return
					}
				}
				ch <- out{}
			}()
		}
		for range k {
			o := <-ch
			if o.ok {
				samples = append(samples, o.d)
			} else {
				drops++
			}
		}
	}
	return samples, drops, nil
}

// UDPLarge sends one n-byte datagram and verifies the hash ack from a
// UDPHashServe peer — datagram boundary and payload integrity at sizes
// far above the loopback MTU.
func UDPLarge(target string, n int) error {
	c, err := net.Dial("udp", target)
	if err != nil {
		return err
	}
	defer c.Close()
	uc := c.(*net.UDPConn)
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	h := fnv.New64a()
	h.Write(payload)
	want := h.Sum64()
	buf := make([]byte, 64)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := uc.Write(payload); err != nil {
			return fmt.Errorf("send %dB datagram: %w", n, err)
		}
		uc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		rn, err := uc.Read(buf)
		if err != nil {
			continue // dropped: retry, UDP-style
		}
		if rn != 8 {
			return fmt.Errorf("ack size %d, want 8", rn)
		}
		if got := binary.BigEndian.Uint64(buf[:8]); got != want {
			return fmt.Errorf("hash mismatch: got %x want %x — payload corrupted in transit", got, want)
		}
		return nil
	}
	return fmt.Errorf("no intact %dB round trip within deadline", n)
}
