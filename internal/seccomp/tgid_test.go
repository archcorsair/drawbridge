package seccomp

import "testing"

func TestParseTgid(t *testing.T) {
	status := []byte("Name:\tprobe\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t10630\nNgid:\t0\nPid:\t10668\nPPid:\t10600\n")
	got, err := parseTgid(status)
	if err != nil || got != 10630 {
		t.Fatalf("parseTgid = %d, %v; want 10630", got, err)
	}
	if _, err := parseTgid([]byte("Name:\tx\nPid:\t3\n")); err == nil {
		t.Fatal("missing Tgid line must error")
	}
	if _, err := parseTgid([]byte("Tgid:\tabc\n")); err == nil {
		t.Fatal("malformed Tgid must error")
	}
}
