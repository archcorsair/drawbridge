//go:build !darwin

package macsync

import "errors"

// Listeners is implemented on macOS only; other platforms must inject
// Syncer.Poll (tests do).
func Listeners() ([]Listener, error) {
	return nil, errors.New("macsync: listener polling is darwin-only")
}
