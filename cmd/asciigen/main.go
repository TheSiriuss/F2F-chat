// One-shot: convert aski2.png to an 80x24 ASCII string and print it.
// Run once, paste the output into pkg/f2f/ascii_logo.go.
package main

import (
	"fmt"
	"os"

	"github.com/TheSiriuss/aski/pkg/aski"
)

func main() {
	path := "aski2.png"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	img, err := f2f.LoadImage(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	frame := f2f.AsciiFrame(img, f2f.VideoCols, f2f.VideoRows)
	fmt.Println(frame)
}
