package main

import (
	"fmt"
	"image"
	"image/color"
	"strings"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
)

// drawFilePanel рисует панель управления файлами
func drawFilePanel(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme
	ft := s.FileTransfer

	// Определяем что показывать
	if ft.HasIncoming {
		return drawIncomingFileOffer(gtx, s, node)
	}

	if ft.IsActive {
		return drawFileProgress(gtx, s, node)
	}

	if ft.ShowResult {
		return drawFileResult(gtx, s)
	}

	// Показываем форму отправки файла
	return drawSendFileForm(gtx, s, node, th)
}

// drawSendFileForm рисует форму отправки файла
func drawSendFileForm(gtx layout.Context, s *UIState, node *f2f.Node, th *Theme) layout.Dimensions {
	// Обработка клика отправки
	if s.BtnSendFile.Clicked(gtx) {
		path := strings.TrimSpace(s.FilePath.Text())
		if path != "" {
			activeID := node.GetActiveChat()
			if activeID.String() != "" {
				go func() {
					if err := node.SendFile(activeID, path); err != nil {
						s.mu.Lock()
						s.FileTransfer.ShowResult = true
						s.FileTransfer.ResultSuccess = false
						s.FileTransfer.ResultMessage = err.Error()
						s.mu.Unlock()
						s.Window.Invalidate()
					} else {
						s.mu.Lock()
						s.FilePath.SetText("")
						s.mu.Unlock()
					}
				}()
			}
		}
	}

	return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				// Поле ввода пути
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return drawStyledEditor(gtx, s, &s.FilePath, "Путь к файлу...", 0)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				// Кнопка отправки
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(s.MatTheme, &s.BtnSendFile, "📁 Send")
					btn.Background = th.Secondary
					btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
					btn.TextSize = unit.Sp(12)
					return btn.Layout(gtx)
				}),
			)
		})
}

// drawIncomingFileOffer рисует предложение входящего файла
func drawIncomingFileOffer(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme
	ft := s.FileTransfer

	// Обработка кнопок
	if s.BtnAcceptFile.Clicked(gtx) {
		go func() {
			if err := node.AcceptFile(""); err != nil {
				s.mu.Lock()
				s.FileTransfer.HasIncoming = false
				s.FileTransfer.ShowResult = true
				s.FileTransfer.ResultSuccess = false
				s.FileTransfer.ResultMessage = err.Error()
				s.mu.Unlock()
				s.Window.Invalidate()
			}
		}()
	}

	if s.BtnDeclineFile.Clicked(gtx) {
		go func() {
			node.DeclineFile("")
			s.mu.Lock()
			s.FileTransfer.HasIncoming = false
			s.mu.Unlock()
			s.Window.Invalidate()
		}()
	}

	return layout.Stack{}.Layout(gtx,
		// Фон
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			paint.FillShape(gtx.Ops, th.BtnPending, clip.Rect{Max: gtx.Constraints.Min}.Op())
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		// Контент
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					// Заголовок
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.Body1(s.MatTheme, fmt.Sprintf("📁 %s предлагает файл:", ft.IncomingNick))
						l.Color = th.Text
						return l.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					// Имя файла и размер
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.Body2(s.MatTheme, fmt.Sprintf("%s (%s)", ft.IncomingName, formatSize(ft.IncomingSize)))
						l.Color = th.Text
						return l.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					// Кнопки
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(s.MatTheme, &s.BtnAcceptFile, "✓ Accept")
								btn.Background = th.Success
								btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
								return btn.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(s.MatTheme, &s.BtnDeclineFile, "✕ Decline")
								btn.Background = th.Danger
								btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
								return btn.Layout(gtx)
							}),
						)
					}),
				)
			})
		}),
	)
}

// drawFileProgress рисует прогресс передачи
func drawFileProgress(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme
	ft := s.FileTransfer

	// Обработка отмены
	if s.BtnCancelFile.Clicked(gtx) {
		go func() {
			node.DeclineFile("")
			s.mu.Lock()
			s.FileTransfer.IsActive = false
			s.mu.Unlock()
			s.Window.Invalidate()
		}()
	}

	bgColor := th.Surface
	if ft.IsUpload {
		bgColor = color.NRGBA{R: 200, G: 230, B: 255, A: 255} // Голубой для отправки
		if s.IsDarkMode {
			bgColor = color.NRGBA{R: 40, G: 60, B: 80, A: 255}
		}
	} else {
		bgColor = color.NRGBA{R: 200, G: 255, B: 200, A: 255} // Зелёный для получения
		if s.IsDarkMode {
			bgColor = color.NRGBA{R: 40, G: 80, B: 50, A: 255}
		}
	}

	return layout.Stack{}.Layout(gtx,
		// Фон
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			paint.FillShape(gtx.Ops, bgColor, clip.Rect{Max: gtx.Constraints.Min}.Op())
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		// Контент
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					// Статус
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						icon := "📤"
						if !ft.IsUpload {
							icon = "📥"
						}
						l := material.Body1(s.MatTheme, fmt.Sprintf("%s %s", icon, ft.StatusText))
						l.Color = th.Text
						return l.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					// Имя файла
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.Caption(s.MatTheme, ft.FileName)
						l.Color = th.TextMuted
						return l.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					// Прогресс-бар
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return drawProgressBar(gtx, s, ft.Progress)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					// Кнопка отмены
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(s.MatTheme, &s.BtnCancelFile, "✕ Cancel")
						btn.Background = th.Warning
						btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
						btn.TextSize = unit.Sp(12)
						return btn.Layout(gtx)
					}),
				)
			})
		}),
	)
}

// drawProgressBar рисует прогресс-бар
func drawProgressBar(gtx layout.Context, s *UIState, progress float64) layout.Dimensions {
	th := s.Theme

	height := gtx.Dp(8)
	width := gtx.Constraints.Max.X

	// Фон
	bgRect := image.Rectangle{Max: image.Pt(width, height)}
	paint.FillShape(gtx.Ops, th.Divider, clip.UniformRRect(bgRect, height/2).Op(gtx.Ops))

	// Заполненная часть
	filledWidth := int(float64(width) * progress)
	if filledWidth > 0 {
		fillRect := image.Rectangle{Max: image.Pt(filledWidth, height)}
		paint.FillShape(gtx.Ops, th.Primary, clip.UniformRRect(fillRect, height/2).Op(gtx.Ops))
	}

	return layout.Dimensions{Size: image.Pt(width, height)}
}

// drawFileResult рисует результат передачи
func drawFileResult(gtx layout.Context, s *UIState) layout.Dimensions {
	th := s.Theme
	ft := s.FileTransfer

	bgColor := th.Success
	icon := "✅"
	if !ft.ResultSuccess {
		bgColor = th.Danger
		icon = "❌"
	}

	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			paint.FillShape(gtx.Ops, bgColor, clip.Rect{Max: gtx.Constraints.Min}.Op())
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				l := material.Body2(s.MatTheme, fmt.Sprintf("%s %s", icon, ft.ResultMessage))
				l.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				return l.Layout(gtx)
			})
		}),
	)
}