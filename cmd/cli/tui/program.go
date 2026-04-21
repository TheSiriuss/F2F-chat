package tui

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/TheSiriuss/aski/pkg/aski"
)

// Run starts the full-screen TUI event loop. Blocks until the user quits.
// Call this AFTER f2f.NewNode so listener callbacks have somewhere to go.
//
// Typical wiring:
//
//   adapter := tui.NewAdapter()
//   node, err := f2f.NewNode(ctx, adapter, password)
//   ...
//   tui.Run(node, adapter)
func Run(node *f2f.Node, adapter *Adapter) error {
	// If the terminal is cramped, ask it (via xterm/Windows-Terminal-
	// compatible CSI) to resize itself to something more comfortable
	// for the three-pane TUI. Legacy consoles silently ignore the escape.
	ensureTerminalSize(130, 40)

	model := NewModel(node)
	prog := tea.NewProgram(
		model,
		tea.WithAltScreen(), // own the terminal — clean on exit
		// Intentionally NO mouse capture: native terminal right-click
		// paste + text selection stay working.
	)
	adapter.Attach(prog)
	_, err := prog.Run()
	return err
}

// ensureTerminalSize nudges the host terminal to at least (cols × rows)
// using the DECSLPP "resize to" control sequence (CSI 8 ; rows ; cols t).
// Windows Terminal, xterm, iTerm2, mintty and kitty all honour it.
// Legacy cmd.exe ignores it — harmless.
func ensureTerminalSize(cols, rows int) {
	// Only adjust if we can detect the current size AND it's smaller
	// than the target — don't shrink a user-chosen large window.
	if fd := int(os.Stdout.Fd()); term.IsTerminal(fd) {
		if w, h, err := term.GetSize(fd); err == nil {
			if w >= cols && h >= rows {
				return
			}
		}
	}
	fmt.Printf("\x1b[8;%d;%dt", rows, cols)
}
