package main

import (
	"os"
	"runtime"
)

type UIStyle struct {
	TopLeft, TopRight, BottomLeft, BottomRight string
	Horizontal, Vertical, TeeLeft, TeeRight    string
	Online, Offline, InChat, Connected         string
	Pending, Global, Searching, Unknown        string
	OK, Fail, Warning, Info, Arrow, Bell, Mail string
}

var Style UIStyle

func initStyle() {
	useUnicode := runtime.GOOS != "windows"
	if os.Getenv("F2F_ASCII") == "1" {
		useUnicode = false
	}
	if os.Getenv("F2F_UNICODE") == "1" {
		useUnicode = true
	}

	if useUnicode {
		Style = UIStyle{
			TopLeft: "┌", TopRight: "┐", BottomLeft: "└", BottomRight: "┘",
			Horizontal: "─", Vertical: "│", TeeLeft: "├", TeeRight: "┤",
			Online: "[*]", Offline: "[-]", InChat: "[#]", Connected: "[+]",
			Pending: "[~]", Global: "[G]", Searching: "[?]", Unknown: "[.]",
			OK: "[+]", Fail: "[!]", Warning: "[!]", Info: "[i]",
			Arrow: "->", Bell: "[!]", Mail: "[>]",
		}
	} else {
		Style = UIStyle{
			TopLeft: "+", TopRight: "+", BottomLeft: "+", BottomRight: "+",
			Horizontal: "-", Vertical: "|", TeeLeft: "+", TeeRight: "+",
			Online: "[*]", Offline: "[-]", InChat: "[#]", Connected: "[+]",
			Pending: "[~]", Global: "[G]", Searching: "[?]", Unknown: "[.]",
			OK: "[+]", Fail: "[X]", Warning: "[!]", Info: "[i]",
			Arrow: "->", Bell: "[!]", Mail: "[>]",
		}
	}
}
