//go:build linux

package main

import (
	"encoding/json"
	"io"

	"github.com/archcorsair/drawbridge/internal/bpf"
	"github.com/archcorsair/drawbridge/internal/kernelfeat"
)

// runFeatures is `drawbridge-agent features`: the kernel feature probe `up`
// and doctor check 2 run before trusting a guest kernel (internal/kernelfeat).
//
// Strictly read-only: one socket, one getsockopt, one close, through the same
// function the gateway loader calls, so the probe cannot disagree with the
// load it predicts. No BPF, no root, no files. A missing feature is an
// answer, not an error: the exit status is 0 whenever the report was
// written, and the caller reads the JSON.
func runFeatures(w io.Writer) error {
	r := kernelfeat.Report{Probe: kernelfeat.Marker}
	if _, err := bpf.NetnsCookie(); err != nil {
		r.NetnsCookieErr = err.Error()
	} else {
		r.NetnsCookie = true
	}
	return json.NewEncoder(w).Encode(r)
}
