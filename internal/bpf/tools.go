//go:build tools

package bpf

// Keeps bpf2go pinned in go.mod for `go generate`.
import _ "github.com/cilium/ebpf/cmd/bpf2go"
