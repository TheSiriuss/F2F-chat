package f2f

import (
	"errors"
	"fmt"
	"image"
	"image/gif"
	_ "image/jpeg" // register decoders via init
	_ "image/png"
	"os"
	"strings"
	"time"

	"golang.org/x/image/draw"
)

// -----------------------------------------------------------------------------
// ASCII frame rendering
// -----------------------------------------------------------------------------

// AsciiPalette maps perceived brightness 0..1 to a character. Dense-to-sparse
// ordering: left = dark pixels, right = bright pixels. This 16-step ramp is a
// classic choice balancing clarity and smoothness.
const AsciiPalette = " .`':,-~+=cox*%#@"

// Default ASCII video dimensions in characters. Terminal cells are roughly
// 2:1 tall-to-wide, so we double-sample vertically to keep the image's
// aspect ratio.
const (
	VideoCols    = 80
	VideoRows    = 24
	VideoFPS     = 10
	videoFrameMs = 1000 / VideoFPS
)

// AsciiFrame converts a single image into a WxH block of ASCII characters.
// Result is rows joined by '\n'. Uses bilinear resampling + luminance mapping.
func AsciiFrame(src image.Image, cols, rows int) string {
	if cols <= 0 || rows <= 0 {
		return ""
	}
	// Resize to the char grid. We account for non-square cells by requesting
	// exactly (cols x rows) pixels — each pixel becomes one cell.
	dst := image.NewRGBA(image.Rect(0, 0, cols, rows))
	draw.BiLinear.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)

	paletteRunes := []rune(AsciiPalette)
	maxIdx := len(paletteRunes) - 1

	var b strings.Builder
	b.Grow((cols + 1) * rows)
	for y := 0; y < rows; y++ {
		for x := 0; x < cols; x++ {
			r, g, bl, _ := dst.At(x, y).RGBA()
			// Rec. 601 luma approximation on 16-bit channels → normalised 0..1.
			lum := (0.299*float64(r) + 0.587*float64(g) + 0.114*float64(bl)) / 65535.0
			idx := int(lum * float64(maxIdx))
			if idx < 0 {
				idx = 0
			} else if idx > maxIdx {
				idx = maxIdx
			}
			b.WriteRune(paletteRunes[idx])
		}
		if y < rows-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// LoadImage decodes any image file that Go's stdlib recognises (PNG/JPEG)
// plus GIF (first frame only via this path — see LoadGIF for animation).
func LoadImage(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	return img, err
}

// GIFFrames holds an animated GIF's decoded frames plus per-frame delays.
type GIFFrames struct {
	Frames []image.Image
	Delays []time.Duration // delay before moving to the NEXT frame
}

// LoadGIF decodes every frame of an animated GIF.
// The gif package applies disposal semantics implicitly (we composite frames
// onto a persistent canvas in the order returned), so each returned image
// is the fully-rendered visible frame.
func LoadGIF(path string) (*GIFFrames, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	g, err := gif.DecodeAll(f)
	if err != nil {
		return nil, err
	}
	if len(g.Image) == 0 {
		return nil, errors.New("gif has no frames")
	}

	// Render each frame onto a persistent canvas, handling disposal.
	bounds := image.Rect(0, 0, g.Config.Width, g.Config.Height)
	canvas := image.NewRGBA(bounds)
	frames := make([]image.Image, 0, len(g.Image))
	delays := make([]time.Duration, 0, len(g.Image))
	for i, frame := range g.Image {
		draw.Draw(canvas, frame.Bounds(), frame, frame.Bounds().Min, draw.Over)
		// Copy current canvas state as this frame.
		snap := image.NewRGBA(bounds)
		draw.Copy(snap, image.Point{}, canvas, bounds, draw.Src, nil)
		frames = append(frames, snap)
		// GIF delay is in 1/100ths of a second; 0 means "use the sensible
		// default" — browsers typically clamp to >=20ms.
		d := time.Duration(g.Delay[i]) * 10 * time.Millisecond
		if d <= 0 {
			d = 100 * time.Millisecond
		}
		delays = append(delays, d)
	}
	return &GIFFrames{Frames: frames, Delays: delays}, nil
}

// -----------------------------------------------------------------------------
// VideoSource — anything that produces ASCII frames at a steady rate
// -----------------------------------------------------------------------------

type VideoSource interface {
	// NextFrame returns the next rendered ASCII string (WxH chars, rows
	// separated by '\n') and the time to wait before reading the frame
	// after this one. Returning io.EOF terminates the stream.
	NextFrame() (frame string, waitBefore time.Duration, err error)
	Close() error
}

// stillImageSource renders the same image forever at VideoFPS.
type stillImageSource struct {
	frame string
}

func (s *stillImageSource) NextFrame() (string, time.Duration, error) {
	return s.frame, videoFrameMs * time.Millisecond, nil
}
func (*stillImageSource) Close() error { return nil }

// gifSource loops over an animated GIF honouring each frame's delay.
type gifSource struct {
	frames []string
	delays []time.Duration
	i      int
}

func (g *gifSource) NextFrame() (string, time.Duration, error) {
	f := g.frames[g.i]
	d := g.delays[g.i]
	g.i = (g.i + 1) % len(g.frames)
	return f, d, nil
}
func (*gifSource) Close() error { return nil }

// OpenVideoSource picks a concrete VideoSource for the given path. Supports
// PNG, JPEG, BMP via single-frame; GIF as animated loop.
func OpenVideoSource(path string) (VideoSource, error) {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".gif"):
		g, err := LoadGIF(path)
		if err != nil {
			return nil, err
		}
		rendered := make([]string, len(g.Frames))
		for i, fr := range g.Frames {
			rendered[i] = AsciiFrame(fr, VideoCols, VideoRows)
		}
		return &gifSource{frames: rendered, delays: g.Delays}, nil
	default:
		img, err := LoadImage(path)
		if err != nil {
			return nil, fmt.Errorf("load image: %w", err)
		}
		return &stillImageSource{frame: AsciiFrame(img, VideoCols, VideoRows)}, nil
	}
}
