package main

import (
	"context"
	"image/color"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
)

// handlePasswordScreen обрабатывает экран ввода пароля
func handlePasswordScreen(gtx layout.Context, s *UIState, gui *GUIAdapter, ctx context.Context) *f2f.Node {
	var node *f2f.Node

	if s.BtnUnlock.Clicked(gtx) {
		password := s.PasswordInput.Text()

		if s.IsNewUser {
			confirm := s.PasswordConfirm.Text()
			if password != confirm {
				s.PasswordError = "Пароли не совпадают"
			} else if len(password) < 8 {
				s.PasswordError = "Минимум 8 символов"
			} else {
				var err error
				node, err = f2f.NewNode(ctx, gui, password)
				if err != nil {
					s.PasswordError = err.Error()
				} else {
					s.IsUnlocked = true
					node.LoadContacts()
					return node
				}
			}
		} else {
			var err error
			node, err = f2f.NewNode(ctx, gui, password)
			if err != nil {
				if err == f2f.ErrWrongPassword {
					s.PasswordError = "Неверный пароль"
				} else {
					s.PasswordError = err.Error()
				}
			} else {
				s.IsUnlocked = true
				node.LoadContacts()
				return node
			}
		}
	}

	drawPasswordScreen(gtx, s)
	return nil
}

// drawPasswordScreen рисует экран ввода пароля
func drawPasswordScreen(gtx layout.Context, s *UIState) layout.Dimensions {
	th := s.Theme

	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
			// Заголовок
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.H3(s.MatTheme, "🔐 F2F Messenger")
				l.Color = th.Text
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),

			// Подзаголовок
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				var msg string
				if s.IsNewUser {
					msg = "Создайте мастер-пароль"
				} else {
					msg = "Введите мастер-пароль"
				}
				l := material.Body1(s.MatTheme, msg)
				l.Color = th.TextMuted
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),

			// Поле пароля
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.PasswordInput, "Пароль...", 300)
			}),

			// Подтверждение (для нового пользователя)
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.IsNewUser {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return drawStyledEditor(gtx, s, &s.PasswordConfirm, "Подтвердите пароль...", 300)
						}),
					)
				}
				return layout.Dimensions{}
			}),

			// Ошибка
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.PasswordError != "" {
					return layout.Inset{Top: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						l := material.Body2(s.MatTheme, s.PasswordError)
						l.Color = th.Danger
						return l.Layout(gtx)
					})
				}
				return layout.Dimensions{}
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),

			// Кнопка
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := "Войти"
				if s.IsNewUser {
					label = "Создать"
				}
				btn := material.Button(s.MatTheme, &s.BtnUnlock, label)
				btn.Background = th.Primary
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				return btn.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(30)}.Layout),

			// Переключатель темы
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawThemeToggle(gtx, s)
			}),
		)
	})
}

// handleLoginScreen обрабатывает экран логина
func handleLoginScreen(gtx layout.Context, s *UIState, node *f2f.Node) {
	// Проверяем автологин
	if node != nil && node.GetNickname() != "" {
		s.IsLoggedIn = true
		return
	}

	if s.BtnLogin.Clicked(gtx) {
		nick := s.LoginNick.Text()
		if nick != "" && node != nil {
			node.Login(nick)
			s.mu.Lock()
			s.IsLoggedIn = true
			s.mu.Unlock()
		}
	}

	drawLoginScreen(gtx, s)
}

// drawLoginScreen рисует экран логина
func drawLoginScreen(gtx layout.Context, s *UIState) layout.Dimensions {
	th := s.Theme

	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.H3(s.MatTheme, "F2F Messenger")
				l.Color = th.Text
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body2(s.MatTheme, "Secure P2P Chat")
				l.Color = th.TextMuted
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(30)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.LoginNick, "Enter nickname...", 250)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(s.MatTheme, &s.BtnLogin, "LOGIN")
				btn.Background = th.Primary
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				return btn.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(30)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawThemeToggle(gtx, s)
			}),
		)
	})
}