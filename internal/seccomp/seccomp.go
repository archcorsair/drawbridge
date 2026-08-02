//go:build linux

// Package seccomp is the Phase 4 user-notification machinery, pure Go (the
// agent builds with CGO_ENABLED=0): install a bind()-only USER_NOTIF filter
// on the calling process, and supervise a notify fd — receive blocked
// binds, read the target's sockaddr, and answer with an errno or CONTINUE.
//
// CONTINUE is safe here because drawbridge uses seccomp for coordination,
// not security enforcement: the classic unotify TOCTOU caveat (target can
// rewrite args after the check) doesn't apply — a raced answer degrades to
// today's async mirror behavior, never to a privilege problem.
package seccomp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	seccompSetModeFilter = 1
	seccompGetNotifSizes = 3

	flagTSync       = 1 << 0
	flagNewListener = 1 << 3
	flagTSyncESRCH  = 1 << 4

	retAllow     = 0x7fff0000
	retUserNotif = 0x7fc00000

	// BPF classic opcodes (the few we need).
	bpfLdWAbs = 0x20
	bpfJmpJeq = 0x15
	bpfRetK   = 0x06

	// _IOC('!', nr, size): dir<<30 | size<<16 | '!'<<8 | nr.
	iocWrite = 1
	iocRead  = 2

	// struct seccomp_notif_resp flags.
	userNotifFlagContinue = 1
)

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	len    uint16
	_      [6]byte
	filter *sockFilter
}

func ioc(dir, nr, size uintptr) uintptr {
	return dir<<30 | size<<16 | '!'<<8 | nr
}

// notifSizes is filled from SECCOMP_GET_NOTIF_SIZES once; the kernel
// requires ioctl buffers of exactly these sizes, zeroed before RECV.
type notifSizes struct {
	notif     uint16
	notifResp uint16
	data      uint16
}

var sizes notifSizes

func getSizes() error {
	if sizes.notif != 0 {
		return nil
	}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, seccompGetNotifSizes, 0,
		uintptr(unsafe.Pointer(&sizes)))
	if errno != 0 {
		return fmt.Errorf("SECCOMP_GET_NOTIF_SIZES: %v", errno)
	}
	return nil
}

// InstallBindFilter sets NO_NEW_PRIVS and installs a filter that sends
// bind() to user notification on every thread (TSYNC), returning the
// listener fd. Everything else is allowed.
func InstallBindFilter() (int, error) {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	prog := []sockFilter{
		{code: bpfLdWAbs, k: 4},                       // load seccomp_data.arch
		{code: bpfJmpJeq, k: auditArch, jt: 1, jf: 0}, // our arch?
		{code: bpfRetK, k: retAllow},                  //   no: allow
		{code: bpfLdWAbs, k: 0},                       // load seccomp_data.nr
		{code: bpfJmpJeq, k: nrBind, jt: 1, jf: 0},    // bind?
		{code: bpfRetK, k: retAllow},                  //   no: allow
		{code: bpfRetK, k: retUserNotif},              //   yes: notify
	}
	fprog := sockFprog{len: uint16(len(prog)), filter: &prog[0]}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter,
		flagTSync|flagTSyncESRCH|flagNewListener, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if errno != 0 {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER): %v", errno)
	}
	return int(fd), nil
}

// Notif is one blocked syscall.
type Notif struct {
	ID   uint64
	PID  uint32
	Nr   int32
	Args [6]uint64
}

// Recv blocks until a notification arrives on the listener fd.
func Recv(fd int) (Notif, error) {
	if err := getSizes(); err != nil {
		return Notif{}, err
	}
	n := int(sizes.notif)
	if n < 80 {
		n = 80
	}
	buf := make([]byte, n) // fresh allocation = zeroed, as the kernel requires
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		ioc(iocRead|iocWrite, 0, uintptr(sizes.notif)), uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		// %w: callers distinguish ENOENT (task gone mid-notification, or
		// filter dead — see FilterDead) from real failures.
		return Notif{}, fmt.Errorf("NOTIF_RECV: %w", errno)
	}
	le := binary.LittleEndian
	nf := Notif{
		ID:  le.Uint64(buf[0:]),
		PID: le.Uint32(buf[8:]),
		Nr:  int32(le.Uint32(buf[16:])),
	}
	for i := 0; i < 6; i++ {
		nf.Args[i] = le.Uint64(buf[32+8*i:])
	}
	return nf, nil
}

// IDValid reports whether the notified syscall is still blocked — the guard
// to run after reading target memory.
func IDValid(fd int, id uint64) bool {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		ioc(iocWrite, 2, 8), uintptr(unsafe.Pointer(&id)))
	return errno == 0
}

func send(fd int, id uint64, sysErr int32, flags uint32) error {
	if err := getSizes(); err != nil {
		return err
	}
	n := int(sizes.notifResp)
	if n < 24 {
		n = 24
	}
	buf := make([]byte, n)
	le := binary.LittleEndian
	le.PutUint64(buf[0:], id)
	// val (int64) stays 0.
	le.PutUint32(buf[16:], uint32(sysErr))
	le.PutUint32(buf[20:], flags)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		ioc(iocRead|iocWrite, 1, uintptr(sizes.notifResp)), uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return fmt.Errorf("NOTIF_SEND: %w", errno)
	}
	return nil
}

// FilterDead reports whether the notify fd's filter has no live tasks left:
// the kernel raises EPOLLHUP on the listener once the last filtered task
// exits. Note NOTIF_RECV on a dead filter BLOCKS forever rather than
// erroring (observed on 6.8; pinned by TestNotifyFilterExitSemantics), so
// supervisors must poll before receiving — see PollNotif.
func FilterDead(fd int) bool {
	pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(pfds, 0)
		if err == unix.EINTR {
			continue
		}
		return err == nil && n > 0 && pfds[0].Revents&unix.POLLHUP != 0
	}
}

// PollNotif blocks until the notify fd has a receivable notification
// (in), its filter has no tasks left (hup), or both. The poll-first shape
// exists because a bare NOTIF_RECV never returns once the filter dies —
// a supervisor looping on Recv alone leaks its OS thread per dead
// container.
func PollNotif(fd int) (in, hup bool, err error) {
	pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, perr := unix.Poll(pfds, -1)
		if perr == unix.EINTR {
			continue
		}
		if perr != nil {
			return false, false, perr
		}
		if n == 0 {
			continue
		}
		return pfds[0].Revents&unix.POLLIN != 0, pfds[0].Revents&unix.POLLHUP != 0, nil
	}
}

// SendErrno fails the blocked syscall with -errno; it never executes.
func SendErrno(fd int, id uint64, errno unix.Errno) error {
	return send(fd, id, -int32(errno), 0)
}

// SendContinue lets the blocked syscall execute natively.
func SendContinue(fd int, id uint64) error {
	return send(fd, id, 0, userNotifFlagContinue)
}

// BindAddr is the sockaddr a blocked bind() carries.
type BindAddr struct {
	Family uint16 // unix.AF_INET | unix.AF_INET6 (others: zero value)
	Port   uint16
	Addr   netip.Addr
}

// ReadBindAddr reads the target's sockaddr out of /proc/pid/mem. The caller
// must confirm IDValid afterwards before trusting it.
func ReadBindAddr(pid uint32, ptr, length uint64) (BindAddr, error) {
	if length < 8 || length > 128 {
		return BindAddr{}, fmt.Errorf("sockaddr len %d out of range", length)
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return BindAddr{}, err
	}
	defer mem.Close()
	buf := make([]byte, length)
	if _, err := mem.ReadAt(buf, int64(ptr)); err != nil {
		return BindAddr{}, err
	}
	family := binary.LittleEndian.Uint16(buf[0:])
	out := BindAddr{Family: family}
	switch family {
	case unix.AF_INET:
		if length < 8 {
			return BindAddr{}, fmt.Errorf("short sockaddr_in")
		}
		out.Port = binary.BigEndian.Uint16(buf[2:])
		out.Addr = netip.AddrFrom4([4]byte(buf[4:8]))
	case unix.AF_INET6:
		if length < 24 {
			return BindAddr{}, fmt.Errorf("short sockaddr_in6")
		}
		out.Port = binary.BigEndian.Uint16(buf[2:])
		out.Addr = netip.AddrFrom16([16]byte(buf[8:24])).Unmap()
	}
	return out, nil
}

// IsInetStream reports whether the target's socket fd is an IP stream
// socket, borrowing a dup via pidfd_getfd.
//
// Deliberately SO_TYPE + SO_DOMAIN, not SO_PROTOCOL: Go 1.24+ creates TCP
// listeners as Multipath TCP, so SO_PROTOCOL reports IPPROTO_MPTCP (262)
// rather than IPPROTO_TCP (6) — an equality check on protocol silently
// rejects ordinary Go servers. Stream + AF_INET/AF_INET6 covers TCP and
// MPTCP and still excludes UDP.
func IsInetStream(pid uint32, sockfd uint64) (bool, error) {
	pidfd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return false, fmt.Errorf("pidfd_open: %w", err)
	}
	defer unix.Close(pidfd)
	fd, err := unix.PidfdGetfd(pidfd, int(sockfd), 0)
	if err != nil {
		return false, fmt.Errorf("pidfd_getfd: %w", err)
	}
	defer unix.Close(fd)
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return false, fmt.Errorf("SO_TYPE: %w", err)
	}
	dom, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return false, fmt.Errorf("SO_DOMAIN: %w", err)
	}
	return typ == unix.SOCK_STREAM && (dom == unix.AF_INET || dom == unix.AF_INET6), nil
}
