//go:build linux

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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

func (g *Gateway) GuestPorts() *ebpf.Map { return g.objs.GuestPorts }
func (g *Gateway) MacPorts() *ebpf.Map   { return g.objs.MacPorts }

func (g *Gateway) Close() error {
	for _, l := range g.links {
		l.Close()
	}
	g.links = nil
	return g.objs.Close()
}
