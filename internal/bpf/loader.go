//go:build linux

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Gateway holds the loaded loopback-gateway programs, their cgroup links,
// and the two decision maps.
type Gateway struct {
	objs  loopbackgwObjects
	links []link.Link
}

// LoadAndAttach loads the programs and attaches them to the cgroup at path
// (normally the v2 root, /sys/fs/cgroup, so the whole guest is covered).
// Attach types are taken from the ELF section names via the collection spec.
func LoadAndAttach(cgroupPath string) (*Gateway, error) {
	spec, err := loadLoopbackgw()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	// Root-cgroup attach covers bridged containers too, whose 127.0.0.1
	// is a different loopback: scope every hook to the loading process's
	// netns (same rule as the tracker's host_netns_inum). The cookie is
	// mandatory — a gateway attached without it would rewrite
	// intra-container loopback connects to a dead 127.0.0.2.
	cookie, err := NetnsCookie()
	if err != nil {
		return nil, fmt.Errorf("read netns cookie: %w", err)
	}
	v, ok := spec.Variables["host_netns_cookie"]
	if !ok {
		return nil, fmt.Errorf("host_netns_cookie missing from spec")
	}
	if err := v.Set(cookie); err != nil {
		return nil, fmt.Errorf("set host_netns_cookie: %w", err)
	}
	g := &Gateway{}
	if err := spec.LoadAndAssign(&g.objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}
	progs := []struct {
		name string
		prog *ebpf.Program
	}{
		{"connect4", g.objs.Connect4},
		{"connect6", g.objs.Connect6},
		{"sendmsg4", g.objs.Sendmsg4},
		{"sendmsg6", g.objs.Sendmsg6},
		{"recvmsg4", g.objs.Recvmsg4},
		{"recvmsg6", g.objs.Recvmsg6},
		{"getpeername4", g.objs.Getpeername4},
		{"getpeername6", g.objs.Getpeername6},
	}
	for _, p := range progs {
		ps, ok := spec.Programs[p.name]
		if !ok {
			g.Close()
			return nil, fmt.Errorf("program %s missing from spec", p.name)
		}
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ps.AttachType,
			Program: p.prog,
		})
		if err != nil {
			g.Close()
			return nil, fmt.Errorf("attach %s: %w", p.name, err)
		}
		g.links = append(g.links, l)
	}
	return g, nil
}

// NetnsCookie returns the caller's network-namespace cookie — the value
// bpf_get_netns_cookie() reports for sockets in this netns. Read through
// SO_NETNS_COOKIE (kernel 5.14+) on a throwaway socket; the kernel never
// hands out 0, so a zero is treated as a failed read rather than a scope.
// Exported for `drawbridge-agent features`, so the preflight probe makes
// exactly the read this loader refuses to start without.
func NetnsCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return 0, fmt.Errorf("getsockopt(SO_NETNS_COOKIE): %w", err)
	}
	if cookie == 0 {
		return 0, fmt.Errorf("getsockopt(SO_NETNS_COOKIE) returned 0")
	}
	return cookie, nil
}

func (g *Gateway) GuestPorts() *ebpf.Map { return g.objs.GuestPorts }
func (g *Gateway) MacPorts() *ebpf.Map   { return g.objs.MacPorts }

func (g *Gateway) Close() error {
	for _, l := range g.links {
		l.Close()
	}
	g.links = nil
	return g.objs.Close()
}
