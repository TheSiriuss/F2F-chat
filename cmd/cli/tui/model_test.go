package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// resize simulates a WindowSizeMsg so the model has non-zero dimensions.
func resizeTo(t *testing.T, m Model, w, h int) Model {
	t.Helper()
	res, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return res.(Model)
}

// typeRune pushes a single printable character through the Update pipeline
// as bubbletea would deliver it from the terminal.
func typeRune(t *testing.T, m Model, r rune) Model {
	t.Helper()
	key := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
	res, _ := m.Update(key)
	return res.(Model)
}

// -----------------------------------------------------------------------------

func TestModel_InitialFocusIsChat(t *testing.T) {
	m := NewModel(nil)
	if m.focus != focusChat {
		t.Fatalf("expected focusChat on start, got %d", m.focus)
	}
}

func TestModel_TypingAppearsInInput(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)

	for _, r := range "привет" {
		m = typeRune(t, m, r)
	}
	got := m.input.Value()
	if got != "привет" {
		t.Fatalf("input.Value = %q, want %q", got, "привет")
	}
}

func TestModel_DotOpensSuggestions(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	m = typeRune(t, m, '.')
	if m.focus != focusChat {
		t.Fatal("should remain in chat focus (suggestions overlay the input)")
	}
	if len(m.suggestions) == 0 {
		t.Fatal("typing . should show full suggestions list")
	}
	if m.input.Value() != "." {
		t.Fatalf("input value = %q, want '.'", m.input.Value())
	}
}

func TestModel_DotFiltersAsTyped(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	for _, r := range ".con" {
		m = typeRune(t, m, r)
	}
	if len(m.suggestions) == 0 {
		t.Fatal("expected non-empty suggestions for .con")
	}
	// "connect" should be among results.
	found := false
	for _, s := range m.suggestions {
		if s.Name == "connect" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf(".con should surface 'connect': got %v", m.suggestions)
	}
}

func TestModel_QuestionMarkOpensHelp(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = res.(Model)
	if m.focus != focusHelp {
		t.Fatalf("'?' should open help overlay, got focus=%d", m.focus)
	}
}

func TestModel_AnyKeyClosesHelp(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = res.(Model)
	// Press any key.
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	m = res.(Model)
	if m.focus != focusChat {
		t.Fatalf("help overlay should close on any key, focus=%d", m.focus)
	}
}

func TestModel_TabNoOpWithoutSuggestions(t *testing.T) {
	// With the sidebar removed, Tab does nothing when there are no
	// dot-command suggestions active — it's reserved for autocomplete.
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	before := m.focus
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = res.(Model)
	if m.focus != before {
		t.Fatalf("tab should not change focus without sidebar, was %d now %d", before, m.focus)
	}
}

func TestSidebarGone(t *testing.T) {
	m := NewModel(nil)
	if w := m.sidebarWidth(); w != 0 {
		t.Fatalf("sidebar should be gone, width=%d", w)
	}
}

func TestModel_BackspaceEditsInput(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	for _, r := range "abc" {
		m = typeRune(t, m, r)
	}
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m = res.(Model)
	if got := m.input.Value(); got != "ab" {
		t.Fatalf("after backspace: %q, want 'ab'", got)
	}
}

func TestModel_EnterOnEmptyDoesNothing(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	res, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = res.(Model)
	if m.input.Value() != "" {
		t.Fatal("input should remain empty")
	}
	_ = cmd
}

func TestModel_EscClearsDotCommand(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	for _, r := range ".con" {
		m = typeRune(t, m, r)
	}
	if len(m.suggestions) == 0 {
		t.Fatal("expected suggestions")
	}
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = res.(Model)
	if m.input.Value() != "" {
		t.Fatalf("esc should clear input, got %q", m.input.Value())
	}
	if len(m.suggestions) != 0 {
		t.Fatal("suggestions should be hidden after esc")
	}
}

func TestModel_TabAutocompletes(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	for _, r := range ".con" {
		m = typeRune(t, m, r)
	}
	// Before tab, input is ".con"
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = res.(Model)
	// After tab, input should be ".connect " (or ".connect" if command has no args — but connect takes <nick>)
	if m.input.Value() != ".connect " {
		t.Fatalf("after tab: %q, want '.connect '", m.input.Value())
	}
}

func TestModel_SystemPanelAppendsToHistory(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	// Simulate command emitting a raw panel.
	res, _ := m.Update(MsgSystemPanel{PeerID: "", Kind: "", Raw: "PANEL CONTENT"})
	m = res.(Model)
	entries := m.history[""]
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Rendered != "PANEL CONTENT" {
		t.Fatalf("unexpected rendered content: %q", entries[0].Rendered)
	}
}

func TestRenderWelcomePanel_NotEmpty(t *testing.T) {
	s := newStyles()
	out := renderWelcomePanel(s, 80)
	if len(out) == 0 {
		t.Fatal("welcome panel should render something")
	}
	if !containsAny(out, "F2F") {
		t.Fatal("welcome should mention F2F")
	}
}

func TestStartupPanelsRenderAfterWindowSize(t *testing.T) {
	m := NewModel(nil)
	// Before WindowSizeMsg — no panels should exist yet.
	if len(m.history[""]) != 0 {
		t.Fatal("history should be empty before first resize")
	}
	m = resizeTo(t, m, 150, 40)
	// startupShown flag should be set, welcome panel appended.
	if !m.startupShown {
		t.Fatal("startupShown should be true after first resize")
	}
	// Welcome gets emitted as a tea.Cmd — we'd need to invoke it. For
	// this test we just verify the flag flipped so the next resize
	// doesn't duplicate.
	m2 := resizeTo(t, m, 160, 42)
	if m2.startupShown != true {
		t.Fatal("second resize should keep startupShown")
	}
}

func TestPanelsRerenderOnResize(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 80, 30)
	// Inject a welcome panel as if by command.
	res, _ := m.Update(MsgSystemPanel{Kind: "welcome"})
	m = res.(Model)
	if len(m.history[""]) != 1 {
		t.Fatal("expected welcome in history")
	}
	firstRender := m.history[""][0].Rendered
	// Simulate a much wider resize.
	m = resizeTo(t, m, 200, 40)
	second := m.history[""][0].Rendered
	if firstRender == second {
		t.Fatal("welcome panel should re-render with new width; content should differ")
	}
	if m.history[""][0].Kind != "welcome" {
		t.Fatal("entry Kind should remain 'welcome'")
	}
}


func TestRenderContactsBox_EmptyList(t *testing.T) {
	s := newStyles()
	out := renderContactsBox(nil, s, 80)
	if !containsAny(out, "addfriend") {
		t.Fatal("empty contacts box should hint at .addfriend")
	}
}

func containsAny(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestModel_ArrowDownMovesSuggestion(t *testing.T) {
	m := NewModel(nil)
	m = resizeTo(t, m, 120, 30)
	// Type "." to see ALL commands.
	m = typeRune(t, m, '.')
	if len(m.suggestions) < 2 {
		t.Skip("not enough commands for this test")
	}
	startIdx := m.suggestIdx
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = res.(Model)
	if m.suggestIdx != startIdx+1 {
		t.Fatalf("down arrow should move idx from %d to %d, got %d", startIdx, startIdx+1, m.suggestIdx)
	}
}
