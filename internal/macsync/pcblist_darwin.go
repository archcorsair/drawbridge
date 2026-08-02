package macsync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// sysctl net.inet.tcp.pcblist_n emits a struct xinpgen header, then
// per-socket groups of typed blocks — each {u32 len, u32 kind}, advanced
// with len rounded up to 8 — then a trailing xinpgen (any block with
// len <= sizeof(xinpgen) terminates the walk). A repeated kind inside a
// group marks the start of the next socket's group. This is the same walk
// netstat performs; the *_n structs are xnu-private but layout-stable, and
// every offset below is verified by the tests against live listeners.
const (
	xsoInpcb = 0x010
	xsoTcpcb = 0x020

	inpIPv6 = 0x2 // inp_vflag

	tcpsListen = 1 // t_state

	// struct xinpcb_n (packed — no padding after the u16 ports): xi_len(0)
	// xi_kind(4) xi_inpp(8) inp_fport(16) inp_lport(18) inp_ppcb(20)
	// inp_gencnt(28) inp_flags(36) inp_flow(40) inp_vflag(44)
	// inp_ip_ttl(45) inp_ip_p(46) inp_dependfaddr(48) inp_dependladdr(64).
	inpLportOff = 18 // u16, network byte order
	inpVflagOff = 44 // u8
	inpLaddrOff = 64 // 16-byte union; v4 occupies the last 4 bytes
	// struct xtcpcb_n: xt_len(0) xt_kind(4) t_segq(8) t_dupacks(16)
	// t_timer[4](20) t_state(36).
	tcpStateOff = 36 // i32
)

// errTruncated marks a pcblist_n buffer that ended without the trailing
// xinpgen: the read raced socket churn (SysctlRaw sizes then reads, and the
// set can grow in between). Retryable — the next read sees a quiet window.
var errTruncated = errors.New("no trailing xinpgen")

// pcblistAttempts bounds the reread loop. The race window is microseconds
// wide, so one clean retry is the norm; three losses in a row means
// something structural, and the caller's error path (session restart)
// beats spinning here.
const pcblistAttempts = 3

// Listeners returns the current set of Mac TCP listening sockets.
//
// A torn read — ENOMEM from the sysctl's size-then-read race, or a buffer
// missing its trailing xinpgen — is retried, then reported as an error,
// never as a silently smaller set: the syncer advertises exactly what this
// returns, and an empty set refuses every reverse activation (§7).
func Listeners() ([]Listener, error) {
	var lastErr error
	for i := 0; i < pcblistAttempts; i++ {
		raw, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
		if err != nil {
			lastErr = fmt.Errorf("sysctl net.inet.tcp.pcblist_n: %w", err)
			if errors.Is(err, unix.ENOMEM) {
				continue // sockets appeared between the size probe and the read
			}
			return nil, lastErr
		}
		ls, err := parsePcblistN(raw)
		if errors.Is(err, errTruncated) {
			lastErr = err
			continue
		}
		return ls, err
	}
	return nil, fmt.Errorf("pcblist_n: torn read persisted across %d attempts (heavy socket churn?): %w", pcblistAttempts, lastErr)
}

func roundup8(n uint32) int {
	if n == 0 {
		return 8
	}
	return int((n + 7) &^ 7)
}

func parsePcblistN(b []byte) ([]Listener, error) {
	if len(b) < 24 {
		return nil, fmt.Errorf("pcblist_n: short read (%d bytes)", len(b))
	}
	xigLen := binary.LittleEndian.Uint32(b)
	xigCount := binary.LittleEndian.Uint32(b[4:]) // pcb count at lock time
	var (
		out      []Listener
		seen     uint32
		inp, tcp []byte
	)
	flush := func() {
		if l, ok := listenerFrom(inp, tcp); ok {
			out = append(out, l)
		}
		seen, inp, tcp = 0, nil, nil
	}
	terminated := false
	off := roundup8(xigLen)
	for off+8 <= len(b) {
		blen := binary.LittleEndian.Uint32(b[off:])
		if blen <= xigLen { // trailing xinpgen
			terminated = true
			break
		}
		end := off + int(blen)
		if end > len(b) {
			break // block extends past the buffer: torn read
		}
		kind := binary.LittleEndian.Uint32(b[off+4:])
		if seen&kind != 0 {
			flush()
		}
		seen |= kind
		switch kind {
		case xsoInpcb:
			inp = b[off:end]
		case xsoTcpcb:
			tcp = b[off:end]
		}
		off += roundup8(blen)
	}
	// The kernel emits the trailing xinpgen whenever it emitted any pcbs
	// (and skips it only in the n == 0 header-only reply), so a walk that
	// ran off the end without seeing it is a torn read, not a small socket
	// set — returning partial output here is how a healthy Mac briefly
	// advertises nothing.
	if !terminated && xigCount != 0 {
		return nil, fmt.Errorf("pcblist_n: %d bytes for %d pcbs: %w", len(b), xigCount, errTruncated)
	}
	flush()
	return out, nil
}

func listenerFrom(inp, tcp []byte) (Listener, bool) {
	if len(inp) < inpLaddrOff+16 || len(tcp) < tcpStateOff+4 {
		return Listener{}, false
	}
	if int32(binary.LittleEndian.Uint32(tcp[tcpStateOff:])) != tcpsListen {
		return Listener{}, false
	}
	port := binary.BigEndian.Uint16(inp[inpLportOff:])
	var addr netip.Addr
	if inp[inpVflagOff]&inpIPv6 != 0 {
		addr = netip.AddrFrom16([16]byte(inp[inpLaddrOff : inpLaddrOff+16]))
	} else {
		addr = netip.AddrFrom4([4]byte(inp[inpLaddrOff+12 : inpLaddrOff+16]))
	}
	return Listener{Proto: "tcp", Port: port, Addr: addr}, true
}
