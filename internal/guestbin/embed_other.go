//go:build !darwin

package guestbin

import "embed"

// Off darwin there is nothing bundled, and that is not a degraded mode: the
// provisioning path is macOS-only by design. Every Binary call returns
// ErrNotBundled, which is exactly what an -agent-bin override is for — and
// what keeps `GOOS=linux go vet ./...` covering this package.
var bundled embed.FS
