//go:build !windows

package main

// enableVTMode is a no-op on non-Windows systems — ANSI escapes work by
// default in POSIX terminals.
func enableVTMode() {}
