package macsync

import "net/netip"

// Wildcard holders (audit H1). Go sets SO_REUSEADDR on every TCP listener,
// and on XNU that makes a bind compare exact addresses only: a mirror's
// net.Listen("tcp", "127.0.0.1:P") succeeds beside a Mac socket holding
// 0.0.0.0:P or dual-stack [::]:P, and then wins every 127.0.0.1 connect the
// native service used to answer. The mirror's own bind result therefore
// cannot see these holders; the Mac's LISTEN set can. Keeping SO_REUSEADDR
// is deliberate: clearing it makes a just-closed mirror port unbindable for
// the 30 s TIME_WAIT (the 2026-10-28 evaluation's rejected fix).

// WildcardHolder returns a listener in ls that holds port on a wildcard
// address serving mirrorIP: a native Mac service that a mirror bound at
// mirrorIP:port would silently take loopback traffic from.
//
// Only unspecified-address holders count. An exact holder of mirrorIP:port
// is already caught by the mirror's own bind (EADDRINUSE), and leaving it out
// means the daemon can never count its own mirror listener as a Mac service.
// For a v4 mirrorIP that is 0.0.0.0 and dual-stack `::` (not v6-only `::`,
// which never answers 127.0.0.1 — the Linux semantics too, where
// 127.0.0.1:P binds fine beside a v6-only [::]:P). For a v6 mirrorIP it is
// any `::`. Holders on other specific addresses (`::1`, a LAN address) do not
// serve mirrorIP and never count.
func WildcardHolder(ls []Listener, port uint16, mirrorIP netip.Addr) (Listener, bool) {
	ip := mirrorIP.Unmap()
	for _, l := range ls {
		if l.Proto != "tcp" || l.Port != port {
			continue
		}
		a := l.Addr.Unmap()
		if !a.IsUnspecified() {
			continue
		}
		switch {
		case ip.Is4() && a.Is4():
			return l, true
		case ip.Is4() && a.Is6() && !l.V6Only:
			return l, true
		case ip.Is6() && a.Is6():
			return l, true
		}
	}
	return Listener{}, false
}

// HolderCheck returns the predicate mirror.Client.MacHolder expects: on
// every call it takes a fresh read of the Mac's TCP listeners (poll; nil means
// Listeners) and names the wildcard holder of port, if any, as it would appear
// in a log line.
//
// known is false whenever the answer cannot be trusted either way, and the
// caller must then fall back to its own bind result: a poll error, a mirrorIP
// that is not an address literal, a proto other than tcp (UDP binds already
// collide natively: Go sets no SO_REUSEADDR on unicast UDP), and above all an
// empty enumeration. A Mac never legitimately has zero LISTEN sockets, and on
// macOS 27.0b4 an unprivileged daemon gets exactly that from a
// per-responsible-app-filtered pcblist (AGENTS.md): empty is "unknown", never
// "free" and never "taken".
//
// A fresh read rather than the syncer's set, on purpose: the syncer's set is
// post-Exclude (a port drops out of it the moment a mirror or reservation
// exists for it), post-normalize (v6-only and dual-stack `::` both read as
// 0.0.0.0), and up to one poll interval stale. One read is ~125 µs.
func HolderCheck(mirrorIP string, poll func() ([]Listener, error)) func(proto string, port uint16) (holder string, known bool) {
	if poll == nil {
		poll = Listeners
	}
	ip, ipErr := netip.ParseAddr(mirrorIP)
	return func(proto string, port uint16) (string, bool) {
		if proto != "tcp" || ipErr != nil {
			return "", false
		}
		ls, err := poll()
		if err != nil || len(ls) == 0 {
			return "", false
		}
		if l, ok := WildcardHolder(ls, port, ip); ok {
			return describeHolder(l), true
		}
		return "", true
	}
}

// describeHolder spells a holder for a log line: the bind address as lsof
// would show it, plus which kind of `::` it is.
func describeHolder(l Listener) string {
	s := netip.AddrPortFrom(l.Addr, l.Port).String()
	if l.Addr.Is6() && !l.Addr.Is4In6() {
		if l.V6Only {
			return s + " (v6-only)"
		}
		return s + " (dual-stack)"
	}
	return s
}
