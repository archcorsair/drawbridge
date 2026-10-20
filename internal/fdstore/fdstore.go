// Package fdstore is the agent's side of systemd's file-descriptor store
// (sd_pid_notify_with_fds(3), FileDescriptorStoreMax=): the mechanism that
// lets a seccomp notify fd outlive the agent process that holds it.
//
// Why it exists: runc hands the agent the only reference to each
// host-network container's notify fd. When that reference closes (crash,
// `systemctl restart`, a `drawbridge up` re-provision) the kernel clears
// the filter's listener and every later bind() in the container returns
// ENOSYS for the rest of its life (audit finding 2). Parking a duplicate in
// systemd's store keeps the listener alive across restarts; the restarted
// agent re-adopts it through LISTEN_FDS/LISTEN_FDNAMES.
//
// No build tag and no cgo: message encoding and the LISTEN_* parse are
// pure and tested on the Mac; the one syscall-bearing function lives in
// fdstore_linux.go.
package fdstore

import (
	"fmt"
	"strconv"
	"strings"
)

// Prefix is the FDNAME prefix every stored notify fd carries. Adoption
// ignores every other name, so a future store user cannot be mistaken for
// a seccomp listener.
const Prefix = "notify-"

// MaxNameLen is systemd's FDNAME= limit.
const MaxNameLen = 255

// ValidName reports whether name is acceptable as FDNAME=: non-empty, at
// most 255 bytes, no ':' (the LISTEN_FDNAMES separator) and no control
// characters (the datagram is newline-delimited).
func ValidName(name string) error {
	if name == "" {
		return fmt.Errorf("fdstore: empty name")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("fdstore: name %q longer than %d bytes", name, MaxNameLen)
	}
	for _, r := range name {
		if r == ':' || r < 0x20 || r == 0x7f {
			return fmt.Errorf("fdstore: name %q contains %q", name, r)
		}
	}
	return nil
}

// StoreMessage is the sd_notify datagram that stores the fds riding its
// SCM_RIGHTS under name.
func StoreMessage(name string) ([]byte, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	return []byte("FDSTORE=1\nFDNAME=" + name + "\n"), nil
}

// RemoveMessage is the datagram that drops every stored fd named name.
func RemoveMessage(name string) ([]byte, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	return []byte("FDSTOREREMOVE=1\nFDNAME=" + name + "\n"), nil
}

// Inherited is one fd systemd passed at start.
type Inherited struct {
	Fd   int
	Name string
}

// ListenFdStart is the first fd number systemd passes (SD_LISTEN_FDS_START).
const ListenFdStart = 3

// ParseListenEnv reads LISTEN_PID, LISTEN_FDS and LISTEN_FDNAMES through
// getenv and returns the fds addressed to pid. Nothing addressed to us (or
// no LISTEN_FDS at all) is an empty slice and a nil error: a plain start.
// Malformed values are an error so a caller can log them rather than
// adopting fds it cannot name.
//
// LISTEN_FDNAMES is optional; systemd fills "unknown" for fds without a
// name, and so does this. A names list of the wrong length is malformed.
func ParseListenEnv(getenv func(string) string, pid int) ([]Inherited, error) {
	pidStr := getenv("LISTEN_PID")
	fdsStr := getenv("LISTEN_FDS")
	if pidStr == "" || fdsStr == "" {
		return nil, nil
	}
	lp, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, fmt.Errorf("fdstore: LISTEN_PID=%q: %w", pidStr, err)
	}
	if lp != pid {
		return nil, nil // addressed to a parent or a sibling, not us
	}
	n, err := strconv.Atoi(fdsStr)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("fdstore: LISTEN_FDS=%q is not a count", fdsStr)
	}
	if n == 0 {
		return nil, nil
	}
	names := make([]string, n)
	for i := range names {
		names[i] = "unknown"
	}
	if raw := getenv("LISTEN_FDNAMES"); raw != "" {
		parts := strings.Split(raw, ":")
		if len(parts) != n {
			return nil, fmt.Errorf("fdstore: LISTEN_FDNAMES has %d names for LISTEN_FDS=%d", len(parts), n)
		}
		copy(names, parts)
	}
	out := make([]Inherited, n)
	for i := range out {
		out[i] = Inherited{Fd: ListenFdStart + i, Name: names[i]}
	}
	return out, nil
}

// IsNotifyName reports whether a stored fd's name marks it as one of ours.
func IsNotifyName(name string) bool {
	return strings.HasPrefix(name, Prefix)
}
