package fdstore

import (
	"reflect"
	"strings"
	"testing"
)

func TestMessages(t *testing.T) {
	got, err := StoreMessage("notify-1a2b-7")
	if err != nil || string(got) != "FDSTORE=1\nFDNAME=notify-1a2b-7\n" {
		t.Fatalf("StoreMessage = %q, %v", got, err)
	}
	got, err = RemoveMessage("notify-1a2b-7")
	if err != nil || string(got) != "FDSTOREREMOVE=1\nFDNAME=notify-1a2b-7\n" {
		t.Fatalf("RemoveMessage = %q, %v", got, err)
	}
	for _, bad := range []string{"", "a:b", "a\nFDSTOREREMOVE=1", "x\x00y", strings.Repeat("n", MaxNameLen+1)} {
		if _, err := StoreMessage(bad); err == nil {
			t.Errorf("StoreMessage(%q) accepted", bad)
		}
		if _, err := RemoveMessage(bad); err == nil {
			t.Errorf("RemoveMessage(%q) accepted", bad)
		}
	}
	if _, err := StoreMessage(strings.Repeat("n", MaxNameLen)); err != nil {
		t.Errorf("255-byte name refused: %v", err)
	}
}

func TestParseListenEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name    string
		env     map[string]string
		pid     int
		want    []Inherited
		wantErr bool
	}{
		{name: "plain start", env: map[string]string{}, pid: 10},
		{name: "addressed elsewhere", env: map[string]string{"LISTEN_PID": "9", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "notify-a:notify-b"}, pid: 10},
		{name: "zero fds", env: map[string]string{"LISTEN_PID": "10", "LISTEN_FDS": "0"}, pid: 10},
		{
			name: "two named",
			env:  map[string]string{"LISTEN_PID": "10", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "notify-a:notify-b"},
			pid:  10,
			want: []Inherited{{Fd: 3, Name: "notify-a"}, {Fd: 4, Name: "notify-b"}},
		},
		{
			name: "no names",
			env:  map[string]string{"LISTEN_PID": "10", "LISTEN_FDS": "2"},
			pid:  10,
			want: []Inherited{{Fd: 3, Name: "unknown"}, {Fd: 4, Name: "unknown"}},
		},
		{
			name: "mixed with a foreign fd",
			env:  map[string]string{"LISTEN_PID": "10", "LISTEN_FDS": "3", "LISTEN_FDNAMES": "notify-a:unknown:notify-c"},
			pid:  10,
			want: []Inherited{{Fd: 3, Name: "notify-a"}, {Fd: 4, Name: "unknown"}, {Fd: 5, Name: "notify-c"}},
		},
		{name: "bad pid", env: map[string]string{"LISTEN_PID": "x", "LISTEN_FDS": "1"}, pid: 10, wantErr: true},
		{name: "bad count", env: map[string]string{"LISTEN_PID": "10", "LISTEN_FDS": "-1"}, pid: 10, wantErr: true},
		{name: "names length mismatch", env: map[string]string{"LISTEN_PID": "10", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "notify-a"}, pid: 10, wantErr: true},
	}
	for _, tc := range cases {
		got, err := ParseListenEnv(env(tc.env), tc.pid)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
	if !IsNotifyName("notify-1-2") || IsNotifyName("unknown") || IsNotifyName("stored-notify-1") {
		t.Fatal("IsNotifyName")
	}
}
