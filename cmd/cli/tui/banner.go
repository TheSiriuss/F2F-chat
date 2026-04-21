package tui

import (
	_ "embed"
)

// askiBanner is the big ASCII "ASKI CHAT" splash shown in the welcome
// panel. Embedded from pkg/f2f/aski_banner.ascii. Width ≈ 65 chars, 6
// rows. The welcome panel centers it horizontally via lipgloss.Place.
//
//go:embed banner.ascii
var askiBanner string
