package main

import (
	"fmt"
	"image/color"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
)

// drawSidebar рисует боковую панель
func drawSidebar(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Dp(320)
	gtx.Constraints.Max.X = gtx.Dp(320)

	th := s.Theme
	paintBackground(gtx, th.Sidebar)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawMyInfo(gtx, s, node)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawToolbar(gtx, s, node)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return drawContactsList(gtx, s, node)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawAddForm(gtx, s, node)
		}),
	)
}

// drawMyInfo рисует информацию о пользователе
func drawMyInfo(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme

	// Обработка Logout
	if s.BtnLogout.Clicked(gtx) {
		go func() {
			node.Logout()
			s.mu.Lock()
			s.IsLoggedIn = false
			s.Messages = nil
			s.mu.Unlock()
			s.Window.Invalidate()
		}()
	}

	// Обработка копирования
	if s.BtnCopyID.Clicked(gtx) {
		// TODO: реализовать копирование в буфер обмена
		s.CopyNotification = "Скопировано!"
		s.CopyNotificationTime = time.Now()
	}

	return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// Ник и кнопки
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.H6(s.MatTheme, s.MyInfo.Nick)
						l.Color = th.Text
						return l.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return drawThemeToggle(gtx, s)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(s.MatTheme, &s.BtnLogout, "Logout")
								btn.Background = th.Danger
								btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
								btn.TextSize = unit.Sp(12)
								return btn.Layout(gtx)
							}),
						)
					}),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),

			// Статус сети
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				stat := "OFFLINE"
				c := th.Danger
				if s.MyInfo.PeersCount > 0 {
					stat = fmt.Sprintf("ONLINE (%d peers)", s.MyInfo.PeersCount)
					c = th.Success
				}
				if s.MyInfo.HasRelay {
					stat = "GLOBAL (Relay)"
					c = th.Primary
				}
				l := material.Body2(s.MatTheme, stat)
				l.Color = c
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),

			// Fingerprint
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Caption(s.MatTheme, "FP: "+s.MyInfo.Fingerprint)
				l.Color = th.TextMuted
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),

			// Кнопка копирования
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(s.MatTheme, &s.BtnCopyID, "Copy AddFriend")
				btn.Background = th.Secondary
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				btn.TextSize = unit.Sp(12)
				return btn.Layout(gtx)
			}),

			// Уведомление о копировании
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.CopyNotification != "" && time.Since(s.CopyNotificationTime) < 2*time.Second {
					l := material.Caption(s.MatTheme, s.CopyNotification)
					l.Color = th.Success
					return layout.Inset{Top: unit.Dp(4)}.Layout(gtx, l.Layout)
				}
				s.CopyNotification = ""
				return layout.Dimensions{}
			}),
		)
	})
}

// drawToolbar рисует панель инструментов
func drawToolbar(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme

	if s.BtnRefresh.Clicked(gtx) {
		go node.ForceCheckAll()
	}

	return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		btn := material.Button(s.MatTheme, &s.BtnRefresh, "Refresh Status")
		btn.Background = th.Primary
		btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
		btn.TextSize = unit.Sp(12)
		return btn.Layout(gtx)
	})
}

// drawAddForm рисует форму добавления контакта
func drawAddForm(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme

	if s.BtnAdd.Clicked(gtx) {
		nick := s.AddNick.Text()
		id := s.AddID.Text()
		key := s.AddKey.Text()
		if nick != "" && id != "" && key != "" {
			go node.AddFriend(nick, id, key)
			s.AddNick.SetText("")
			s.AddID.SetText("")
			s.AddKey.SetText("")
		}
	}

	return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body2(s.MatTheme, "Add Friend:")
				l.Color = th.Text
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.AddNick, "Nickname", 0)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.AddID, "PeerID", 0)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.AddKey, "PubKey", 0)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(s.MatTheme, &s.BtnAdd, "Add Contact")
				btn.Background = th.Primary
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				return btn.Layout(gtx)
			}),
		)
	})
}