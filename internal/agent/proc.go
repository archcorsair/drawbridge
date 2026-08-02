//go:build linux

package agent

import (
	"bufio"
	"encoding/binary"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// /proc/net seeding catches listeners that existed before the BPF tracker
// attached. Attach happens first, then the scan; entries are added
// put-if-absent so a listener racing the scan is not double counted.

type procFile struct {
	path  string
	proto string
	v6    bool
	// tcp files list all sockets; only state 0A (LISTEN) is a listener.
	// udp files only contain bound sockets; every row counts.
	listenOnly bool
}

var procFiles = []procFile{
	{"/proc/net/tcp", "tcp", false, true},
	{"/proc/net/tcp6", "tcp", true, true},
	{"/proc/net/udp", "udp", false, false},
	{"/proc/net/udp6", "udp", true, false},
}

func scanProcNet() []Listener {
	var out []Listener
	for _, f := range procFiles {
		out = append(out, parseProcNet(f)...)
	}
	return out
}

func parseProcNet(f procFile) []Listener {
	file, err := os.Open(f.path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var out []Listener
	sc := bufio.NewScanner(file)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if f.listenOnly && fields[3] != "0A" {
			continue
		}
		addr, port, ok := parseProcAddr(fields[1], f.v6)
		if !ok || port == 0 {
			continue
		}
		out = append(out, Listener{Proto: f.proto, Port: port, Addr: addr.Unmap()})
	}
	return out
}

// parseProcAddr decodes /proc/net's "HEXADDR:HEXPORT". Addresses are printed
// as native-endian dwords of the network-order bytes: on little-endian,
// 127.0.0.1 appears as 0100007F; v6 is four such dwords.
func parseProcAddr(s string, v6 bool) (netip.Addr, uint16, bool) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	wantLen := 8
	if v6 {
		wantLen = 32
	}
	if len(host) != wantLen {
		return netip.Addr{}, 0, false
	}
	var b [16]byte
	n := len(host) / 8
	for i := 0; i < n; i++ {
		dw, err := strconv.ParseUint(host[i*8:(i+1)*8], 16, 32)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		binary.LittleEndian.PutUint32(b[i*4:], uint32(dw))
	}
	if !v6 {
		var a4 [4]byte
		copy(a4[:], b[:4])
		return netip.AddrFrom4(a4), uint16(port64), true
	}
	return netip.AddrFrom16(b), uint16(port64), true
}
