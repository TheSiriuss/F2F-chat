package main

import (
	"context"
	"os"

	"gioui.org/app"
	"gioui.org/op"
	"gioui.org/unit"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
)

func main() {
	state := NewUIState()
	gui := &GUIAdapter{state: state}

	go func() {
		w := new(app.Window)
		w.Option(app.Title("F2F Messenger"), app.Size(unit.Dp(1000), unit.Dp(700)))
		state.Window = w

		var node *f2f.Node
		ctx := context.Background()

		var ops op.Ops

		for {
			switch e := w.Event().(type) {
			case app.DestroyEvent:
				if node != nil {
					node.Shutdown()
				}
				os.Exit(0)

			case app.FrameEvent:
				gtx := app.NewContext(&ops, e)

				// Обработка переключения темы
				if state.BtnToggleTheme.Clicked(gtx) {
					state.IsDarkMode = !state.IsDarkMode
					if state.IsDarkMode {
						state.Theme = &DarkTheme
					} else {
						state.Theme = &LightTheme
					}
				}

				paintBackground(gtx, state.Theme.Background)

				// Роутинг экранов
				if !state.IsUnlocked {
					node = handlePasswordScreen(gtx, state, gui, ctx)
				} else if !state.IsLoggedIn {
					handleLoginScreen(gtx, state, node)
				} else {
					state.mu.Lock()
					updateNodeData(state, node)
					state.mu.Unlock()
					drawMainLayout(gtx, state, node)
				}

				e.Frame(gtx.Ops)
			}
		}
	}()

	app.Main()
}