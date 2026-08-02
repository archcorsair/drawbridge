package mirror

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/archcorsair/drawbridge/internal/udpframe"
)

// UDP mirror (docs/udp.md, inbound): one local UDP socket per mirrored
// guest port plus one eager proto-17 'S' stream to the agent, pumping
// framed datagrams both ways. The Mac side is stateless — reply frames
// carry their destination — so flow state lives only on the agent end.
type udpMirror struct {
	c    *Client
	port uint16
	uc   *net.UDPConn
	done chan struct{}
	once sync.Once
}

func (c *Client) openUDPLocked(key mirrorKey, refs int) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(c.MirrorIP),
		Port: int(key.port),
	})
	if err != nil {
		c.logBindError(key, err)
		return
	}
	// Guest replies can be full-size datagrams; macOS caps a UDP send at
	// the socket's send buffer (~9216 default) — raise it so mirrored
	// replies over ~9 KiB don't die EMSGSIZE on the way to Mac clients.
	uc.SetWriteBuffer(udpframe.MaxPayload)
	log.Printf("drawbridged: mirroring guest udp :%d on %s", key.port, uc.LocalAddr())
	m := &udpMirror{c: c, port: key.port, uc: uc, done: make(chan struct{})}
	c.mirrors[key] = &mirrorEntry{stop: m.stop, refs: refs, since: time.Now()}
	c.forget(key)
	go m.run()
}

func (m *udpMirror) stop() {
	m.once.Do(func() {
		close(m.done)
		m.uc.Close()
	})
}

func (m *udpMirror) closed() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

// run maintains the stream for the mirror's lifetime: dial, pump, and on
// stream death back off and redial (datagrams arriving in the gap are
// dropped — UDP semantics).
func (m *udpMirror) run() {
	for {
		if m.closed() {
			return
		}
		s, err := m.dialStream()
		if err != nil {
			if !m.sleep(time.Second) {
				return
			}
			continue
		}
		m.pump(s)
		s.Close()
		if m.closed() {
			return
		}
		if !m.sleep(time.Second) {
			return
		}
	}
}

func (m *udpMirror) sleep(d time.Duration) bool {
	select {
	case <-m.done:
		return false
	case <-time.After(d):
		return true
	}
}

// dialStream opens the framed UDP relay stream: an 'S' conn like the TCP
// splice's, proto 17, sharing the same one-write hello and proof gate.
func (m *udpMirror) dialStream() (net.Conn, error) { return m.c.dialStream(17, m.port) }

// pump runs until the stream or the socket dies. Frames from the agent are
// written to their carried destination; local datagrams are framed with
// the client's AddrPort.
func (m *udpMirror) pump(s net.Conn) {
	var wmu sync.Mutex
	streamDead := make(chan struct{})
	go func() {
		defer close(streamDead)
		buf := make([]byte, udpframe.MaxPayload)
		for {
			peer, payload, err := udpframe.ReadFrame(s, buf)
			if err != nil {
				return
			}
			m.uc.WriteToUDPAddrPort(payload, peer)
		}
	}()
	buf := make([]byte, udpframe.MaxPayload)
	for {
		n, client, err := m.uc.ReadFromUDPAddrPort(buf)
		if err != nil {
			// Socket closed (mirror removed) — or transient; either way
			// the caller decides via closed().
			s.Close()
			<-streamDead
			return
		}
		if err := udpframe.WriteFrame(s, &wmu, client, buf[:n]); err != nil {
			s.Close()
			<-streamDead
			return
		}
	}
}
