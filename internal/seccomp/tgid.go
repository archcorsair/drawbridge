package seccomp

import (
	"bytes"
	"errors"
	"os"
	"strconv"
)

// A seccomp user notification names the *thread* that made the syscall
// (its TID), and pidfd_open refuses a thread that is not its group leader:
// EINVAL on 6.8, ENOENT on 7.1. Any process that binds from a non-main
// thread (Go servers, Java, worker pools) therefore failed classification
// and degraded to CONTINUE, losing synchronous EADDRINUSE. Threads share
// the fd table, so the fix is to open the thread group instead: resolve
// Tgid from /proc/<tid>/status (procfs exposes every task under /proc)
// and pidfd_open that.

// parseTgid extracts the "Tgid:" field of a /proc/<pid>/status document.
func parseTgid(status []byte) (int, error) {
	for _, line := range bytes.Split(status, []byte("\n")) {
		if rest, ok := bytes.CutPrefix(line, []byte("Tgid:")); ok {
			n, err := strconv.Atoi(string(bytes.TrimSpace(rest)))
			if err != nil {
				return 0, errors.New("malformed Tgid line: " + string(bytes.TrimSpace(line)))
			}
			return n, nil
		}
	}
	return 0, errors.New("no Tgid line in status")
}

// tgidOf resolves the thread group leader of any task id.
func tgidOf(tid uint32) (int, error) {
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(tid), 10) + "/status")
	if err != nil {
		return 0, err
	}
	return parseTgid(b)
}
