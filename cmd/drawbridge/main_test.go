package main

import "testing"

// Bare `drawbridge` panicked in v0.0.1 and v0.1.0: the verb had a length
// guard but argv[2:] did not. The empty verb must route to usage with no
// slicing on the way.
func TestVerbArgs(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		verb string
		args int
	}{
		{"bare invocation", []string{"drawbridge"}, "", 0},
		{"verb only", []string{"drawbridge", "status"}, "status", 0},
		{"verb with args", []string{"drawbridge", "up", "colima", "--oci"}, "up", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verb, args := verbArgs(c.argv)
			if verb != c.verb || len(args) != c.args {
				t.Fatalf("verbArgs(%v) = %q, %d args; want %q, %d", c.argv, verb, len(args), c.verb, c.args)
			}
		})
	}
}
