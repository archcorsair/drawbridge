//go:build linux

package seccomp

import (
	"fmt"
	"os"
)

// SameNetNS reports whether pid shares the caller's network namespace.
// The OCI arbitration backstop: only binds from the agent's own (host)
// netns may reach the Mac — a bridged container's bind must degrade to
// CONTINUE no matter what fed its notify fd to the agent.
func SameNetNS(pid uint32) (bool, error) {
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return false, err
	}
	other, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return false, err
	}
	return self == other, nil
}
