//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVTMode turns on ENABLE_VIRTUAL_TERMINAL_PROCESSING for stdout so that
// ANSI escape codes (cursor movement, line erasure) emitted via fmt.Print
// are interpreted by the Windows console. Modern Windows Terminal enables
// this automatically, but legacy cmd.exe and some configurations don't.
// Safe no-op on non-Windows (see vt_other.go).
func enableVTMode() {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	_ = windows.SetConsoleMode(h, mode)
}
