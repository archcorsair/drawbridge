// Package buildinfo carries the one build-time fact every drawbridge
// binary needs: which version it is. It is deliberately a single variable
// with no init logic — the CLI, the daemon and the guest agent all link it,
// and the release build stamps it at link time:
//
//	go build -ldflags "-X github.com/archcorsair/drawbridge/internal/buildinfo.Version=v0.1.0" ./cmd/...
//
// An unstamped build (plain `go build`, `go test`, `go run`) reports "dev".
// This is the substrate for the CLI↔daemon↔agent skew checks
// (docs/ergonomics.md §2.4, §6): the agent writes it to
// /run/drawbridge-agent.version and `drawbridged -version` prints it, so a
// stale component can be named rather than guessed at.
package buildinfo

// Version is the binary's version, set via -ldflags -X at link time.
var Version = "dev"
