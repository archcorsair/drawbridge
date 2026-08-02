//go:build linux

package bpf

import (
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ListenerEvent is the ringbuf record emitted on 0<->1 listener transitions.
type ListenerEvent = trackerListenerEvent

const (
	EventAdd uint8 = 1
	EventDel uint8 = 2
)

// Tracker holds the fexit/fentry listener-tracking programs.
type Tracker struct {
	objs  trackerObjects
	links []link.Link
}

// LoadTracker loads the tracker, sharing guest_ports with the already-loaded
// gateway (MapReplacements) so kernel-side listener updates feed the same
// map the loopback arbitration hooks read.
func LoadTracker(gw *Gateway) (*Tracker, error) {
	spec, err := loadTracker()
	if err != nil {
		return nil, fmt.Errorf("load tracker spec: %w", err)
	}
	// The hooks are kernel-global and also fire in bridged container netns;
	// scope tracking to the loading process's netns so those listeners never
	// reach guest_ports or the Mac mirror.
	inum, err := netnsInum()
	if err != nil {
		return nil, fmt.Errorf("read netns inum: %w", err)
	}
	v, ok := spec.Variables["host_netns_inum"]
	if !ok {
		return nil, fmt.Errorf("host_netns_inum missing from spec")
	}
	if err := v.Set(inum); err != nil {
		return nil, fmt.Errorf("set host_netns_inum: %w", err)
	}
	opts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"guest_ports": gw.GuestPorts()},
	}
	t := &Tracker{}
	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return nil, fmt.Errorf("load tracker objects: %w", err)
	}
	progs := []struct {
		name string
		prog *ebpf.Program
	}{
		{"tcp_listen_start", t.objs.TcpListenStart},
		{"tcp_listen_stop", t.objs.TcpListenStop},
		{"udp4_bind", t.objs.Udp4Bind},
		{"udp6_bind", t.objs.Udp6Bind},
		{"udp_unbind", t.objs.UdpUnbind},
	}
	for _, p := range progs {
		ps, ok := spec.Programs[p.name]
		if !ok {
			t.Close()
			return nil, fmt.Errorf("program %s missing from spec", p.name)
		}
		l, err := link.AttachTracing(link.TracingOptions{
			Program:    p.prog,
			AttachType: ps.AttachType,
		})
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("attach %s: %w", p.name, err)
		}
		t.links = append(t.links, l)
	}
	return t, nil
}

// netnsInum returns the inode number of the caller's network namespace —
// the same value struct net's ns.inum holds in the kernel.
func netnsInum() (uint32, error) {
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		return 0, err
	}
	return uint32(st.Ino), nil
}

// EventReader returns a ringbuf reader over listener events.
func (t *Tracker) EventReader() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(t.objs.TrackerEvents)
}

func (t *Tracker) Close() error {
	for _, l := range t.links {
		l.Close()
	}
	t.links = nil
	return t.objs.Close()
}
