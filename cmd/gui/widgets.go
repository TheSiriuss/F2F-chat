package main

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// paintBackground заливает фон цветом
func paintBackground(gtx layout.Context, c color.NRGBA) {
	rect := clip.Rect{Max: gtx.Constraints.Max}
	paint.FillShape(gtx.Ops, c, rect.Op())
}

// drawDivider рисует разделитель
func drawDivider(gtx layout.Context, c color.NRGBA) layout.Dimensions {
	paint.FillShape(gtx.Ops, c, clip.Rect{Max: image.Pt(gtx.Constraints.Max.X, 1)}.Op())
	return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, 1)}
}

// drawStyledEditor рисует стилизованный редактор
func drawStyledEditor(gtx layout.Context, s *UIState, editor *widget.Editor, hint string, minWidth int) layout.Dimensions {
	th := s.Theme

	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			r := gtx.Dp(4)
			rect := image.Rectangle{Max: gtx.Constraints.Min}
			paint.FillShape(gtx.Ops, th.Surface, clip.UniformRRect(rect, r).Op(gtx.Ops))
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			if minWidth > 0 {
				gtx.Constraints.Min.X = gtx.Dp(unit.Dp(minWidth))
			}
			return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				e := material.Editor(s.MatTheme, editor, hint)
				e.Color = th.Text
				e.HintColor = th.TextMuted
				return e.Layout(gtx)
			})
		}),
	)
}

// drawThemeToggle рисует кнопку переключения темы
func drawThemeToggle(gtx layout.Context, s *UIState) layout.Dimensions {
	th := s.Theme

	label := "Light"
	if s.IsDarkMode {
		label = "Dark"
	}

	btn := material.Button(s.MatTheme, &s.BtnToggleTheme, label)
	btn.Background = th.Surface
	btn.Color = th.Text
	btn.TextSize = unit.Sp(11)
	return btn.Layout(gtx)
}