//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	"github.com/archcorsair/drawbridge/internal/bpf"
)

// Control is the JSON-over-unix-socket API used by `drawbridge-agent testctl`
// and, later, by the vsock bridge from the Mac daemon.
//
// Request:  {"op":"add-mac-port","proto":"tcp","port":8080,
//            "bind_addr":"0.0.0.0","backend":"127.0.0.3:18080"}
// Response: {"ok":true} | {"ok":false,"error":"..."}

type ControlRequest struct {
	Op       string `json:"op"`
	Proto    string `json:"proto,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	BindAddr string `json:"bind_addr,omitempty"`
	Backend  string `json:"backend,omitempty"`
}

type ControlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ServeControl accepts control connections until the listener is closed.
func (a *Agent) ServeControl(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go a.serveConn(c)
	}
}

func (a *Agent) serveConn(c net.Conn) {
	defer c.Close()
	dec := json.NewDecoder(c)
	enc := json.NewEncoder(c)
	for {
		var req ControlRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		if err := a.dispatch(req); err != nil {
			enc.Encode(ControlResponse{OK: false, Error: err.Error()})
		} else {
			enc.Encode(ControlResponse{OK: true})
		}
	}
}

func (a *Agent) dispatch(req ControlRequest) error {
	var proto uint8
	switch req.Proto {
	case "tcp":
		proto = bpf.ProtoTCP
	case "udp":
		proto = bpf.ProtoUDP
	case "":
		// ops without proto (ping)
	default:
		return fmt.Errorf("unknown proto %q", req.Proto)
	}
	bind := netip.IPv4Unspecified()
	if req.BindAddr != "" {
		var err error
		bind, err = netip.ParseAddr(req.BindAddr)
		if err != nil {
			return fmt.Errorf("bind_addr: %w", err)
		}
	}
	switch req.Op {
	case "ping":
		return nil
	case "add-mac-port":
		return a.AddMacPort(proto, req.Port, bind, req.Backend)
	case "remove-mac-port":
		return a.RemoveMacPort(proto, req.Port)
	case "add-guest-port":
		return a.AddGuestPort(proto, req.Port, bind)
	case "remove-guest-port":
		return a.RemoveGuestPort(proto, req.Port)
	default:
		return fmt.Errorf("unknown op %q", req.Op)
	}
}
