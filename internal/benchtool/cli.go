package benchtool

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
)

// Result is the JSON line a benchclient run prints on stdout.
type Result struct {
	Mode      string     `json:"mode"`
	Target    string     `json:"target,omitempty"`
	Iters     int        `json:"iters,omitempty"`
	Conns     int        `json:"conns,omitempty"`
	Rounds    int        `json:"rounds,omitempty"`
	Bytes     int64      `json:"bytes,omitempty"`
	Seconds   float64    `json:"seconds,omitempty"`
	MBPerSec  float64    `json:"mb_per_sec,omitempty"`
	ConnectUS *Quantiles `json:"connect_us,omitempty"`
	RTTUS     *Quantiles `json:"rtt_us,omitempty"`
	Drops     int        `json:"drops,omitempty"` // UDP legs: timed-out round trips
}

// ServeMain is the benchserve subcommand: -listen ADDR -mode MODE.
func ServeMain(args []string) error {
	fs := flag.NewFlagSet("benchserve", flag.ContinueOnError)
	listen := fs.String("listen", "", "address to listen on (e.g. :47801)")
	mode := fs.String("mode", "echo", "echo | sink | source | udpecho | udphash")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *listen == "" {
		return fmt.Errorf("benchserve: -listen required")
	}
	if *mode == "udpecho" || *mode == "udphash" {
		ua, err := net.ResolveUDPAddr("udp", *listen)
		if err != nil {
			return err
		}
		pc, err := net.ListenUDP("udp", ua)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "benchserve: %s on %s\n", *mode, pc.LocalAddr())
		if *mode == "udphash" {
			return UDPHashServe(pc)
		}
		return UDPEchoServe(pc)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "benchserve: %s on %s\n", *mode, ln.Addr())
	return Serve(ln, *mode)
}

// ClientMain is the benchclient subcommand. Modes: firstbyte | baseline |
// burst | upload | download. Prints one Result JSON line on stdout.
func ClientMain(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("benchclient", flag.ContinueOnError)
	target := fs.String("target", "", "server address (unused for baseline)")
	mode := fs.String("mode", "firstbyte", "firstbyte | baseline | burst | upload | download | udprtt | udpbaseline | udpburst | udplarge")
	iters := fs.Int("iters", 200, "iterations (firstbyte/baseline/udprtt/udpbaseline)")
	conns := fs.Int("conns", 8, "simultaneous conns/sockets (burst/udpburst)")
	rounds := fs.Int("rounds", 5, "waves (burst/udpburst)")
	bytes := fs.Int64("bytes", 256<<20, "transfer size (upload/download) or datagram size (udplarge)")
	size := fs.Int("size", 64, "datagram payload bytes (udprtt/udpbaseline/udpburst)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res := Result{Mode: *mode, Target: *target}
	switch *mode {
	case "baseline":
		// Native loopback echo in-process: same kernel, BPF hooks attached,
		// no drawbridge steering (own listener => guest_ports precedence).
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer ln.Close()
		go Serve(ln, "echo")
		res.Target = ln.Addr().String()
		samples, err := FirstByte(ln.Addr().String(), *iters)
		if err != nil {
			return err
		}
		res.Iters = *iters
		c, r := QuantilesOf(Connects(samples)), QuantilesOf(RTTs(samples))
		res.ConnectUS, res.RTTUS = &c, &r
	case "firstbyte":
		samples, err := FirstByte(*target, *iters)
		if err != nil {
			return err
		}
		res.Iters = *iters
		c, r := QuantilesOf(Connects(samples)), QuantilesOf(RTTs(samples))
		res.ConnectUS, res.RTTUS = &c, &r
	case "burst":
		samples, err := Burst(*target, *conns, *rounds)
		if err != nil {
			return err
		}
		res.Conns, res.Rounds = *conns, *rounds
		c, r := QuantilesOf(Connects(samples)), QuantilesOf(RTTs(samples))
		res.ConnectUS, res.RTTUS = &c, &r
	case "upload":
		d, err := Upload(*target, *bytes)
		if err != nil {
			return err
		}
		res.Bytes, res.Seconds, res.MBPerSec = *bytes, d.Seconds(), MBps(*bytes, d)
	case "download":
		d, err := Download(*target, *bytes)
		if err != nil {
			return err
		}
		res.Bytes, res.Seconds, res.MBPerSec = *bytes, d.Seconds(), MBps(*bytes, d)
	case "udprtt":
		samples, drops, err := UDPRTT(*target, *iters, *size)
		if err != nil {
			return err
		}
		res.Iters, res.Drops = *iters, drops
		r := QuantilesOf(samples)
		res.RTTUS = &r
	case "udpbaseline":
		// Native loopback UDP echo in-process: hooks attached, no steering
		// (own listener => guest_ports precedence).
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return err
		}
		defer pc.Close()
		go UDPEchoServe(pc)
		res.Target = pc.LocalAddr().String()
		samples, drops, err := UDPRTT(pc.LocalAddr().String(), *iters, *size)
		if err != nil {
			return err
		}
		res.Iters, res.Drops = *iters, drops
		r := QuantilesOf(samples)
		res.RTTUS = &r
	case "udpburst":
		samples, drops, err := UDPBurst(*target, *conns, *rounds, *size)
		if err != nil {
			return err
		}
		res.Conns, res.Rounds, res.Drops = *conns, *rounds, drops
		r := QuantilesOf(samples)
		res.RTTUS = &r
	case "udplarge":
		if err := UDPLarge(*target, int(*bytes)); err != nil {
			return err
		}
		res.Bytes = *bytes
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
	return json.NewEncoder(stdout).Encode(res)
}
