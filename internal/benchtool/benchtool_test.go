package benchtool

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func server(t *testing.T, mode string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go Serve(ln, mode)
	return ln.Addr().String()
}

func TestFirstByteAgainstEcho(t *testing.T) {
	addr := server(t, "echo")
	samples, err := FirstByte(addr, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 20 {
		t.Fatalf("got %d samples", len(samples))
	}
	for _, s := range samples {
		if s.Connect <= 0 || s.RTT < s.Connect {
			t.Fatalf("bad sample %+v", s)
		}
	}
}

func TestBurstCollectsAllSamples(t *testing.T) {
	addr := server(t, "echo")
	samples, err := Burst(addr, 8, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 24 {
		t.Fatalf("got %d samples, want 24", len(samples))
	}
}

func TestUploadDownload(t *testing.T) {
	sink := server(t, "sink")
	src := server(t, "source")
	const n = 8 << 20
	if d, err := Upload(sink, n); err != nil || d <= 0 {
		t.Fatalf("upload: %v (%v)", err, d)
	}
	if d, err := Download(src, n); err != nil || d <= 0 {
		t.Fatalf("download: %v (%v)", err, d)
	}
}

func TestQuantiles(t *testing.T) {
	ds := make([]time.Duration, 100)
	for i := range ds {
		ds[i] = time.Duration(i+1) * time.Microsecond // 1..100µs
	}
	q := QuantilesOf(ds)
	if q.P50 != 50 || q.P95 != 95 || q.P99 != 99 || q.Max != 100 {
		t.Fatalf("quantiles = %+v", q)
	}
}

func TestClientMainFirstByteJSON(t *testing.T) {
	addr := server(t, "echo")
	var out bytes.Buffer
	if err := ClientMain([]string{"-mode", "firstbyte", "-target", addr, "-iters", "10"}, &out); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("bad JSON %q: %v", out.String(), err)
	}
	if res.Mode != "firstbyte" || res.Iters != 10 || res.RTTUS == nil || res.RTTUS.P50 <= 0 {
		t.Fatalf("result = %+v", res)
	}
}

func TestClientMainBaseline(t *testing.T) {
	var out bytes.Buffer
	if err := ClientMain([]string{"-mode", "baseline", "-iters", "10"}, &out); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.RTTUS == nil || res.RTTUS.P50 <= 0 {
		t.Fatalf("result = %+v", res)
	}
}
