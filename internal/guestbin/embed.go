package guestbin

import "embed"

// The committed assets: text, tiny, and identical on every platform, so they
// are embedded unconditionally. Keeping them out of the platform-gated file
// is what lets the unit and script renderers be unit-tested on any GOOS.
//
//go:embed assets
var assets embed.FS
