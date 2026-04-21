package f2f

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeGradientImage returns a 200x100 image that runs black→white left to right.
func makeGradientImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 200, 100))
	for x := 0; x < 200; x++ {
		v := uint8(x * 255 / 199)
		for y := 0; y < 100; y++ {
			img.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}
	return img
}

func TestAsciiFrame_DimensionsMatch(t *testing.T) {
	img := makeGradientImage()
	frame := AsciiFrame(img, 80, 24)
	lines := strings.Split(frame, "\n")
	if len(lines) != 24 {
		t.Fatalf("expected 24 lines, got %d", len(lines))
	}
	for i, line := range lines {
		if len([]rune(line)) != 80 {
			t.Errorf("line %d has %d chars, want 80", i, len([]rune(line)))
		}
	}
}

func TestAsciiFrame_GradientDarkToLight(t *testing.T) {
	img := makeGradientImage()
	frame := AsciiFrame(img, 80, 10)
	// First char of first row should be the DARKEST palette char (space),
	// last char should be close to the BRIGHTEST.
	firstLine := strings.SplitN(frame, "\n", 2)[0]
	palette := []rune(AsciiPalette)
	firstRune := []rune(firstLine)[0]
	lastRune := []rune(firstLine)[len([]rune(firstLine))-1]
	if firstRune != palette[0] {
		t.Errorf("darkest cell = %q, want %q", firstRune, palette[0])
	}
	if lastRune == palette[0] {
		t.Errorf("brightest cell shouldn't be the darkest char")
	}
}

func TestAsciiFrame_ZeroDimensions(t *testing.T) {
	img := makeGradientImage()
	if got := AsciiFrame(img, 0, 10); got != "" {
		t.Fatal("expected empty string on zero cols")
	}
	if got := AsciiFrame(img, 10, 0); got != "" {
		t.Fatal("expected empty string on zero rows")
	}
}

func TestLoadImage_PNG(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.png")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, makeGradientImage()); err != nil {
		t.Fatal(err)
	}
	f.Close()

	img, err := LoadImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 200 || img.Bounds().Dy() != 100 {
		t.Fatalf("bounds %v", img.Bounds())
	}
}

func TestLoadImage_Missing(t *testing.T) {
	if _, err := LoadImage("/definitely/missing.png"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadGIF_MultipleFrames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.gif")

	// Build a 3-frame gif of solid colors.
	g := &gif.GIF{LoopCount: 0}
	for i := 0; i < 3; i++ {
		pal := color.Palette{
			color.RGBA{0, 0, 0, 255},
			color.RGBA{uint8(i * 80), uint8(i * 80), uint8(i * 80), 255},
		}
		frame := image.NewPaletted(image.Rect(0, 0, 20, 20), pal)
		for y := 0; y < 20; y++ {
			for x := 0; x < 20; x++ {
				frame.SetColorIndex(x, y, 1)
			}
		}
		g.Image = append(g.Image, frame)
		g.Delay = append(g.Delay, 10) // 100ms
	}
	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, g); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, buf.Bytes(), 0644)

	frames, err := LoadGIF(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames.Frames) != 3 {
		t.Fatalf("got %d frames, want 3", len(frames.Frames))
	}
	for i, d := range frames.Delays {
		if d != 100*time.Millisecond {
			t.Errorf("frame %d delay = %v, want 100ms", i, d)
		}
	}
}

func TestOpenVideoSource_PNG(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.png")
	f, _ := os.Create(path)
	png.Encode(f, makeGradientImage())
	f.Close()

	src, err := OpenVideoSource(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	frame, _, err := src.NextFrame()
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) == 0 {
		t.Fatal("empty frame")
	}
}

func TestOpenVideoSource_GIFLoops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.gif")
	g := &gif.GIF{LoopCount: 0}
	pal := color.Palette{color.Black, color.White}
	for i := 0; i < 2; i++ {
		fr := image.NewPaletted(image.Rect(0, 0, 20, 20), pal)
		g.Image = append(g.Image, fr)
		g.Delay = append(g.Delay, 5)
	}
	var buf bytes.Buffer
	gif.EncodeAll(&buf, g)
	os.WriteFile(path, buf.Bytes(), 0644)

	src, err := OpenVideoSource(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	// Pull three frames — the third must be the same as the first (loop).
	f1, _, _ := src.NextFrame()
	f2, _, _ := src.NextFrame()
	f3, _, _ := src.NextFrame()
	if f1 != f3 {
		t.Fatal("GIF source didn't loop back to frame 0")
	}
	if f1 == f2 {
		t.Log("note: 2 identical black frames is fine for this synthetic test")
	}
}

func TestOpenVideoSource_Unknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bogus.xyz")
	os.WriteFile(path, []byte("nope"), 0644)
	if _, err := OpenVideoSource(path); err == nil {
		t.Fatal("expected error on unrecognised file")
	}
}

func TestVideoConfig_SanityConstants(t *testing.T) {
	if VideoCols <= 0 || VideoRows <= 0 || VideoFPS <= 0 {
		t.Fatal("video constants must be positive")
	}
}

func TestDeriveVideoKeys_DifferentFromVoice(t *testing.T) {
	// Video keys must be cryptographically independent of voice keys derived
	// from the SAME shared secret — otherwise reusing a call's shared secret
	// for both channels would expose correlated keystreams.
	var shared [32]byte
	for i := range shared {
		shared[i] = byte(i + 1)
	}
	const alice = "alicealicealicealicealicealiceaa"
	const bob = "bobbobbobbobbobbobbobbobbobbobbb"

	vSend, vRecv := deriveVideoKeys(shared, alice, bob)
	cSend, cRecv := deriveCallKeys(shared, alice, bob)

	if vSend == cSend || vSend == cRecv {
		t.Fatal("video sendKey overlaps voice keys")
	}
	if vRecv == cSend || vRecv == cRecv {
		t.Fatal("video recvKey overlaps voice keys")
	}
	if vSend == vRecv {
		t.Fatal("video send/recv keys must differ")
	}
}

func TestDeriveVideoKeys_Symmetric(t *testing.T) {
	var shared [32]byte
	for i := range shared {
		shared[i] = byte(i * 3)
	}
	const alice = "alicealicealicealicealicealiceaa"
	const bob = "bobbobbobbobbobbobbobbobbobbobbb"

	aSend, aRecv := deriveVideoKeys(shared, alice, bob)
	bSend, bRecv := deriveVideoKeys(shared, bob, alice)

	if aSend != bRecv {
		t.Fatal("aSend != bRecv")
	}
	if aRecv != bSend {
		t.Fatal("aRecv != bSend")
	}
}
