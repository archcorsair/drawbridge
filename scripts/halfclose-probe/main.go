// halfclose-probe is the standalone transport probe for the Phase 7 spike
// (docs/podman.md §3.1). It imports nothing from this module on purpose: the
// verdict it produces must be about the path under test, never about
// drawbridge code.
//
// Server:  halfclose-probe -listen HOST:PORT
// Client:  halfclose-probe -dial tcp://HOST:PORT|unix:///PATH -leg N [-hold 45s]
//
// The client opens one connection per leg and sends a one-line header
// "<leg> <holdSeconds>\n"; the server dispatches on it. Four legs:
//
//	1 fin-propagates  client writes 1 MiB, CloseWrite, expects "ack N".
//	2 survives-fin    client half-closes, then must keep receiving heartbeats
//	                  for -hold (default 45 s) — outlasts the agent's 15 s ping.
//	3 reverse-fin     server half-closes first; client must see EOF fast and
//	                  its 64 KiB reply must land (server prints the count).
//	4 bulk            256 MiB each way, concurrently, no read stall > 5 s.
//
// Exit status is 0 on pass, 1 on fail; every line printed is prefixed with
// the leg so a transcript reads without context.
package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	leg1Bytes  = 1 << 20
	leg3Bytes  = 64 << 10
	leg4Bytes  = 256 << 20
	hbInterval = 5 * time.Second
	stallLimit = 5 * time.Second
)

type halfCloser interface {
	CloseWrite() error
}

func main() {
	listen := flag.String("listen", "", "server: TCP address to listen on (host:port)")
	dial := flag.String("dial", "", "client: endpoint, tcp://host:port or unix:///path")
	leg := flag.Int("leg", 0, "client: leg to run (1-4)")
	hold := flag.Duration("hold", 45*time.Second, "leg 2: how long the client keeps reading after its FIN")
	flag.Parse()

	switch {
	case *listen != "" && *dial == "":
		if err := serve(*listen); err != nil {
			fmt.Fprintln(os.Stderr, "server:", err)
			os.Exit(2)
		}
	case *dial != "" && *listen == "":
		if *leg < 1 || *leg > 4 {
			fmt.Fprintln(os.Stderr, "client: -leg must be 1..4")
			os.Exit(2)
		}
		if err := client(*dial, *leg, *hold); err != nil {
			fmt.Printf("leg%d FAIL: %v\n", *leg, err)
			os.Exit(1)
		}
		fmt.Printf("leg%d PASS\n", *leg)
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// ---- server ----

func serve(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Printf("server listening on %s\n", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			if err := handle(c); err != nil {
				fmt.Printf("server conn %s: %v\n", c.RemoteAddr(), err)
			}
		}()
	}
}

func handle(c net.Conn) error {
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("header: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return fmt.Errorf("bad header %q", line)
	}
	leg, _ := strconv.Atoi(fields[0])
	holdSec, _ := strconv.Atoi(fields[1])
	hc, ok := c.(halfCloser)
	if !ok {
		return errors.New("conn cannot half-close")
	}
	fmt.Printf("server leg%d from %s\n", leg, c.RemoteAddr())
	switch leg {
	case 1:
		n, err := io.Copy(io.Discard, br)
		if err != nil {
			return fmt.Errorf("leg1 read: %w", err)
		}
		fmt.Printf("server leg1 saw EOF after %d bytes\n", n)
		_, err = fmt.Fprintf(c, "ack %d\n", n)
		return err
	case 2:
		n, err := io.Copy(io.Discard, br)
		if err != nil {
			return fmt.Errorf("leg2 read: %w", err)
		}
		fin := time.Now()
		fmt.Printf("server leg2 saw EOF after %d bytes; heartbeating for %ds\n", n, holdSec)
		hold := time.Duration(holdSec) * time.Second
		for i := 1; ; i++ {
			time.Sleep(hbInterval)
			since := time.Since(fin)
			if since > hold {
				break
			}
			if _, err := fmt.Fprintf(c, "hb %d %.1f\n", i, since.Seconds()); err != nil {
				return fmt.Errorf("leg2 heartbeat %d: %w", i, err)
			}
		}
		fmt.Println("server leg2 done")
		return nil
	case 3:
		if _, err := c.Write([]byte("x")); err != nil {
			return err
		}
		if err := hc.CloseWrite(); err != nil {
			return fmt.Errorf("leg3 CloseWrite: %w", err)
		}
		n, err := io.Copy(io.Discard, br)
		fmt.Printf("server leg3 read %d bytes after its own FIN (want %d)\n", n, leg3Bytes)
		return err
	case 4:
		n, err := io.Copy(c, br)
		if err != nil {
			return fmt.Errorf("leg4 echo: %w", err)
		}
		fmt.Printf("server leg4 echoed %d bytes\n", n)
		return hc.CloseWrite()
	default:
		return fmt.Errorf("unknown leg %d", leg)
	}
}

// ---- client ----

func connect(endpoint string) (net.Conn, error) {
	switch {
	case strings.HasPrefix(endpoint, "tcp://"):
		return net.DialTimeout("tcp", strings.TrimPrefix(endpoint, "tcp://"), 5*time.Second)
	case strings.HasPrefix(endpoint, "unix://"):
		return net.DialTimeout("unix", strings.TrimPrefix(endpoint, "unix://"), 5*time.Second)
	default:
		return net.DialTimeout("tcp", endpoint, 5*time.Second)
	}
}

func client(endpoint string, leg int, hold time.Duration) error {
	c, err := connect(endpoint)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	hc, ok := c.(halfCloser)
	if !ok {
		return errors.New("conn cannot half-close")
	}
	if _, err := fmt.Fprintf(c, "%d %d\n", leg, int(hold.Seconds())); err != nil {
		return fmt.Errorf("header: %w", err)
	}
	switch leg {
	case 1:
		return leg1(c, hc)
	case 2:
		return leg2(c, hc, hold)
	case 3:
		return leg3(c, hc)
	case 4:
		return leg4(c, hc)
	}
	return nil
}

func leg1(c net.Conn, hc halfCloser) error {
	buf := make([]byte, leg1Bytes)
	rand.Read(buf)
	if _, err := c.Write(buf); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	t0 := time.Now()
	if err := hc.CloseWrite(); err != nil {
		return fmt.Errorf("CloseWrite: %w", err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return fmt.Errorf("no ack within 5s of FIN (forwarder swallowed the FIN?): %w", err)
	}
	want := fmt.Sprintf("ack %d\n", leg1Bytes)
	if line != want {
		return fmt.Errorf("ack %q, want %q", strings.TrimSpace(line), strings.TrimSpace(want))
	}
	fmt.Printf("leg1 ack after %v\n", time.Since(t0).Round(time.Millisecond))
	return nil
}

func leg2(c net.Conn, hc halfCloser, hold time.Duration) error {
	if _, err := c.Write([]byte("hold\n")); err != nil {
		return err
	}
	if err := hc.CloseWrite(); err != nil {
		return fmt.Errorf("CloseWrite: %w", err)
	}
	fin := time.Now()
	c.SetReadDeadline(fin.Add(hold + 10*time.Second))
	br := bufio.NewReader(c)
	var late int // heartbeats after fin+15s
	var last time.Duration
	total := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read after %d heartbeats (last at +%.1fs): %w", total, last.Seconds(), err)
		}
		since := time.Since(fin)
		total++
		last = since
		if since > 15*time.Second {
			late++
		}
		fmt.Printf("leg2 %s at +%.1fs\n", strings.TrimSpace(line), since.Seconds())
	}
	if total == 0 {
		return errors.New("zero heartbeats after FIN (check-8 killer signature)")
	}
	if late < 2 {
		return fmt.Errorf("only %d heartbeats after +15s (want >= 2); last at +%.1fs", late, last.Seconds())
	}
	if last < 30*time.Second && hold >= 45*time.Second {
		return fmt.Errorf("last heartbeat at +%.1fs, want >= 30s", last.Seconds())
	}
	fmt.Printf("leg2 %d heartbeats, %d after +15s, last at +%.1fs\n", total, late, last.Seconds())
	return nil
}

func leg3(c net.Conn, hc halfCloser) error {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	t0 := time.Now()
	n, err := io.Copy(io.Discard, c)
	if err != nil {
		return fmt.Errorf("waiting for server FIN: %w", err)
	}
	eofAfter := time.Since(t0)
	if n != 1 {
		return fmt.Errorf("read %d bytes before EOF, want 1", n)
	}
	if eofAfter > time.Second {
		return fmt.Errorf("server FIN took %v to arrive (want < 1s)", eofAfter.Round(time.Millisecond))
	}
	buf := make([]byte, leg3Bytes)
	rand.Read(buf)
	if _, err := c.Write(buf); err != nil {
		return fmt.Errorf("write after server FIN: %w", err)
	}
	if err := hc.CloseWrite(); err != nil {
		return err
	}
	fmt.Printf("leg3 EOF after %v, wrote %d bytes; confirm the server log says %d\n",
		eofAfter.Round(time.Millisecond), leg3Bytes, leg3Bytes)
	return nil
}

func leg4(c net.Conn, hc halfCloser) error {
	var wg sync.WaitGroup
	var werr, rerr error
	var got int64
	t0 := time.Now()
	wg.Add(2)
	go func() {
		defer wg.Done()
		chunk := make([]byte, 1<<20)
		rand.Read(chunk)
		var sent int64
		for sent < leg4Bytes {
			n, err := c.Write(chunk)
			sent += int64(n)
			if err != nil {
				werr = fmt.Errorf("write after %d bytes: %w", sent, err)
				return
			}
		}
		if err := hc.CloseWrite(); err != nil {
			werr = err
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 1<<20)
		for {
			c.SetReadDeadline(time.Now().Add(stallLimit))
			n, err := c.Read(buf)
			got += int64(n)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				rerr = fmt.Errorf("read stalled/failed after %d bytes: %w", got, err)
				return
			}
		}
	}()
	wg.Wait()
	if werr != nil {
		return werr
	}
	if rerr != nil {
		return rerr
	}
	if got != leg4Bytes {
		return fmt.Errorf("echoed %d bytes, want %d", got, leg4Bytes)
	}
	el := time.Since(t0)
	fmt.Printf("leg4 %d MiB each way in %v, %.0f MB/s per direction\n",
		leg4Bytes>>20, el.Round(time.Millisecond), float64(leg4Bytes)/el.Seconds()/1e6)
	return nil
}
