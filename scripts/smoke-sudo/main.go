// smoke-sudo is the one-command acceptance run for everything on the Mac
// that needs root: install the freshly built daemon for a VM, prove the
// three semantics through it, uninstall, and put back whatever daemon was
// installed before. It asks for the sudo password once (`sudo -v`) and
// prints a single JSON document on stdout that can be pasted back verbatim;
// progress goes to stderr.
//
//	just smoke-sudo vm=podman:spike
//
// Every step is a named check with ok/detail; a failed step does not skip
// the cleanup steps, so the machine is left the way it was found. Exit
// status is 1 when any check failed.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Millis int64  `json:"ms"`
}

type report struct {
	VM         string  `json:"vm"`
	PreviousVM string  `json:"previous_vm,omitempty"`
	Binary     string  `json:"binary"`
	Version    string  `json:"version,omitempty"`
	RestoreBin string  `json:"restore_binary,omitempty"`
	Ran        int     `json:"ran"`
	Passed     int     `json:"passed"`
	Failed     int     `json:"failed"`
	Restored   bool    `json:"restored"`
	Checks     []check `json:"checks"`
}

const (
	guestHTTPPort = 48080 // guest listener, expected on Mac 127.0.0.1
	macHTTPPort   = 48081 // Mac listener, expected inside the guest
	guestUnit     = "drawbridge-smoke"
)

func main() {
	vm := flag.String("vm", "", "VM to install the daemon for (provider:name)")
	bin := flag.String("bin", "bin/drawbridge", "drawbridge CLI whose sibling drawbridged gets installed")
	restoreBin := flag.String("restore-bin", "", "CLI used to reinstall the previous daemon (default: `drawbridge` on PATH if it differs from -bin, else -bin)")
	flag.Parse()
	if *vm == "" {
		fmt.Fprintln(os.Stderr, "smoke-sudo: -vm is required")
		os.Exit(2)
	}
	ref, err := vmprovider.ParseRef(*vm)
	if err != nil {
		fmt.Fprintln(os.Stderr, "smoke-sudo:", err)
		os.Exit(2)
	}
	binAbs, _ := filepath.Abs(*bin)
	r := &report{VM: *vm, Binary: binAbs}
	if out, err := exec.Command(binAbs, "version").Output(); err == nil {
		r.Version = strings.TrimSpace(string(out))
	}
	if prev, ok := install.InstalledVM(); ok {
		r.PreviousVM = prev
	}
	r.RestoreBin = pickRestoreBin(*restoreBin, binAbs)

	s := &suite{r: r, ref: ref, bin: binAbs, prov: vmprovider.ForRef(ref)}
	s.run()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(r)
	if r.Failed > 0 {
		os.Exit(1)
	}
}

func pickRestoreBin(explicit, bin string) string {
	if explicit != "" {
		p, _ := filepath.Abs(explicit)
		return p
	}
	if p, err := exec.LookPath("drawbridge"); err == nil {
		if rp, err := filepath.EvalSymlinks(p); err == nil && rp != bin {
			return p
		}
	}
	return bin
}

type suite struct {
	r    *report
	ref  vmprovider.Ref
	bin  string
	prov vmprovider.Provider
}

func (s *suite) step(name string, f func() (string, error)) bool {
	fmt.Fprintf(os.Stderr, "smoke-sudo: %s ...\n", name)
	t0 := time.Now()
	detail, err := f()
	c := check{Name: name, OK: err == nil, Detail: detail, Millis: time.Since(t0).Milliseconds()}
	if err != nil {
		if detail != "" {
			c.Detail = detail + ": " + err.Error()
		} else {
			c.Detail = err.Error()
		}
		s.r.Failed++
		fmt.Fprintf(os.Stderr, "smoke-sudo:   FAIL %s\n", c.Detail)
	} else {
		s.r.Passed++
		fmt.Fprintf(os.Stderr, "smoke-sudo:   ok %s\n", detail)
	}
	s.r.Ran++
	s.r.Checks = append(s.r.Checks, c)
	return err == nil
}

func (s *suite) run() {
	// One password prompt, up front, on the terminal.
	if !s.step("sudo", func() (string, error) {
		c := exec.Command("sudo", "-v")
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stderr, os.Stderr
		return "credentials cached", c.Run()
	}) {
		return
	}

	// Cleanup runs no matter what happened in between.
	defer s.restore()
	defer s.step("guest-listener-stop", func() (string, error) {
		_, err := s.prov.Shell(s.ref.Instance, nil, "sudo", "systemctl", "stop", guestUnit)
		return "unit " + guestUnit + " stopped", err
	})

	s.step("install", func() (string, error) {
		out, err := sudo(s.bin, "install", "-vm", s.r.VM)
		return firstLine(out), err
	})

	s.step("daemon-sessions-up", func() (string, error) {
		st, err := waitState(25*time.Second, func(st *introspect.State) bool {
			return st.VM.Ref == s.r.VM && st.Mirror.SessionUp && st.Sync.SessionUp
		})
		return describe(st), err
	})

	s.step("guest-listener-mirrored-on-mac", func() (string, error) {
		port := fmt.Sprint(guestHTTPPort)
		if _, err := s.prov.Shell(s.ref.Instance, nil, "sudo", "systemd-run", "--unit="+guestUnit, "--collect",
			"python3", "-m", "http.server", port, "--bind", "0.0.0.0"); err != nil {
			return "", fmt.Errorf("start guest listener: %w", err)
		}
		url := "http://127.0.0.1:" + port + "/"
		body, err := waitHTTP(url, 20*time.Second)
		if err != nil {
			return "", err
		}
		if !strings.Contains(body, "Directory listing") {
			return "", fmt.Errorf("unexpected body %q", firstLine([]byte(body)))
		}
		return "guest :" + port + " answered on Mac " + url, nil
	})

	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", macHTTPPort), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "drawbridge-smoke\n")
	})}
	ln, lnErr := net.Listen("tcp", srv.Addr)
	if lnErr == nil {
		go srv.Serve(ln)
		defer srv.Close()
	}

	s.step("mac-listener-reachable-in-guest", func() (string, error) {
		if lnErr != nil {
			return "", fmt.Errorf("mac listen: %w", lnErr)
		}
		url := fmt.Sprintf("http://127.0.0.1:%d/", macHTTPPort)
		deadline := time.Now().Add(20 * time.Second)
		var last string
		for time.Now().Before(deadline) {
			out, err := s.prov.Shell(s.ref.Instance, nil, "curl", "-sS", "--max-time", "2", url)
			last = strings.TrimSpace(string(out))
			if err == nil && strings.Contains(last, "drawbridge-smoke") {
				return "Mac :" + fmt.Sprint(macHTTPPort) + " answered inside the guest", nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return "", fmt.Errorf("guest never reached the Mac listener (last: %q)", last)
	})

	for _, offThread := range []bool{false, true} {
		name := "guest-bind-on-mac-port-is-eaddrinuse"
		argv := []string{"sudo", guestbin.GuestPath(guestbin.NameAgent), "bindprobe",
			"-addr", fmt.Sprintf("127.0.0.1:%d", macHTTPPort), "-hold", "0s"}
		if offThread {
			name += "-off-thread"
			argv = append(argv, "-off-thread")
		}
		s.step(name, func() (string, error) {
			// The supervised probe the e2e leg uses: a bind that goes through
			// the agent's seccomp arbitration and reports the errno as one JSON
			// line. The off-thread variant binds from a non-leader thread, the
			// placement that once degraded to CONTINUE.
			out, err := s.prov.Shell(s.ref.Instance, nil, argv...)
			if err != nil {
				return lastLine(out), err
			}
			var r struct {
				Errno int    `json:"errno"`
				Error string `json:"error,omitempty"`
			}
			for _, line := range strings.Split(string(out), "\n") {
				if line = strings.TrimSpace(line); strings.HasPrefix(line, "{") {
					if err := json.Unmarshal([]byte(line), &r); err != nil {
						return line, err
					}
					if r.Errno != 98 { // Linux EADDRINUSE
						return "", fmt.Errorf("guest bind :%d = errno %d (%s), want EADDRINUSE(98)", macHTTPPort, r.Errno, r.Error)
					}
					return fmt.Sprintf("guest bind :%d refused synchronously with EADDRINUSE", macHTTPPort), nil
				}
			}
			return "", fmt.Errorf("no probe result in %q", strings.TrimSpace(string(out)))
		})
	}

	s.step("uninstall", func() (string, error) {
		out, err := sudo(s.bin, "uninstall")
		return firstLine(out), err
	})
}

func (s *suite) restore() {
	if s.r.PreviousVM == "" {
		s.step("restore-previous-daemon", func() (string, error) {
			return "nothing was installed before; left uninstalled", nil
		})
		return
	}
	ok := s.step("restore-previous-daemon", func() (string, error) {
		out, err := sudo(s.r.RestoreBin, "install", "-vm", s.r.PreviousVM)
		if err != nil {
			return firstLine(out), err
		}
		st := install.Query()
		if !st.PlistInstalled || st.PID == 0 {
			return firstLine(out), fmt.Errorf("daemon not running after reinstall (state=%q)", st.State)
		}
		return fmt.Sprintf("%s reinstalled via %s, pid %d", s.r.PreviousVM, s.r.RestoreBin, st.PID), nil
	})
	s.r.Restored = ok
}

func sudo(args ...string) ([]byte, error) {
	c := exec.Command("sudo", append([]string{"-n"}, args...)...)
	var buf bytes.Buffer
	c.Stdout, c.Stderr = &buf, &buf
	err := c.Run()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, lastLine(buf.Bytes()))
	}
	return buf.Bytes(), err
}

func waitState(d time.Duration, ready func(*introspect.State) bool) (*introspect.State, error) {
	deadline := time.Now().Add(d)
	var last *introspect.State
	var lastErr error
	for time.Now().Before(deadline) {
		snap, err := introspect.Fetch(introspect.EffectiveRootSocketPath(), 2*time.Second)
		if err == nil && snap.Usable {
			last = &snap.State
			if ready(last) {
				return last, nil
			}
		} else if err != nil {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if last == nil {
		if lastErr == nil {
			lastErr = errors.New("no usable snapshot")
		}
		return nil, fmt.Errorf("introspection: %w", lastErr)
	}
	return last, errors.New("sessions not up within " + d.String())
}

func describe(st *introspect.State) string {
	if st == nil {
		return ""
	}
	bound := 0
	for _, e := range st.Mirror.Entries {
		if e.State == introspect.EntryBound {
			bound++
		}
	}
	return fmt.Sprintf("%s %s (source=%s) mirror=%v %d/%d bound sync=%v %d advertised",
		st.Version, st.Resolution.Endpoint, st.Resolution.Source, st.Mirror.SessionUp, bound, len(st.Mirror.Entries),
		st.Sync.SessionUp, len(st.Sync.Advertised))
}

func waitHTTP(url string, d time.Duration) (string, error) {
	deadline := time.Now().Add(d)
	client := &http.Client{Timeout: 2 * time.Second}
	var last error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return string(b), nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("%s not reachable within %s: %v", url, d, last)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}
