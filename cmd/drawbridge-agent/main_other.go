//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "drawbridge-agent runs inside the Linux guest; cross-compile with GOOS=linux")
	os.Exit(1)
}
