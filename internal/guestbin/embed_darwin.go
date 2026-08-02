//go:build darwin

package guestbin

import "embed"

// The guest binaries, bundled only into the macOS CLI (docs/ergonomics.md
// §2.2). Only the Mac side provisions a guest, and the artifacts are tens of
// megabytes — embedding them into the Linux agent build would inflate the
// binary that gets *pushed into* the guest with four copies of itself.
//
// `all:` is load-bearing: the directory holds a committed `.keep` and
// nothing else on a fresh checkout, and a plain `//go:embed bin` skips
// dot-prefixed names, so the pattern would match no files and fail to
// compile. With `all:` the pattern always matches, and absence becomes
// ErrNotBundled at run time — a message instead of a broken build.
//
//go:embed all:bin
var bundled embed.FS
