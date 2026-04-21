package f2f

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------
// Camera source via ffmpeg subprocess.
//
// Rationale: real camera capture on Windows without CGO requires either
// raw DirectShow/MediaFoundation COM (painful, 1000s of lines) or a fat
// dependency like OpenCV. ffmpeg is a single executable, trivially
// installable (choco/winget/apt/brew), and gives us uniform behaviour
// across Windows/Linux/macOS with a tiny wrapper.
//
// Flow:
//   ffmpeg captures webcam → rescales to CAMERA_W×CAMERA_H → emits rgb24
//   rawvideo to stdout → we io.ReadFull(width*height*3) each frame →
//   hand it to AsciiFrame → transmit.
// -----------------------------------------------------------------------------

const (
	cameraW    = 160
	cameraH    = 90
	cameraFPS  = 10
	frameBytes = cameraW * cameraH * 3
)

// CameraAvailable reports whether ffmpeg is reachable (either on PATH or in
// the per-user cache populated by EnsureFFmpeg).
func CameraAvailable() bool {
	return ResolveFFmpeg() != ""
}

// -----------------------------------------------------------------------------
// Device enumeration
// -----------------------------------------------------------------------------

// ListCameras returns the list of available camera device names suitable for
// passing to OpenCameraSource. An empty list with nil error means "ffmpeg
// found no cameras" — distinct from ffmpeg not being installed (returns err).
func ListCameras() ([]string, error) {
	devices, _, err := ListCamerasVerbose()
	return devices, err
}

// ListCamerasVerbose is the same as ListCameras but also returns the raw
// stderr output of ffmpeg. When enumeration yields zero devices, dumping
// this to the user is often the fastest way to diagnose why (access denied,
// driver problem, wrong backend for the OS, etc.).
func ListCamerasVerbose() (devices []string, rawOutput string, err error) {
	if !CameraAvailable() {
		return nil, "", errors.New("ffmpeg не найден — выберите «Камеру» в .settings для автоустановки")
	}

	switch runtime.GOOS {
	case "windows":
		return listDShowCameras()
	case "linux":
		matches, _ := filepath.Glob("/dev/video*")
		return matches, "scanned /dev/video*", nil
	case "darwin":
		return listAVFoundationCameras()
	default:
		return nil, "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// listDShowCameras runs ffmpeg with a hard timeout so a hung camera driver
// doesn't block the UI, and returns the raw ffmpeg stderr alongside the
// parsed device list.
func listDShowCameras() ([]string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	path := ResolveFFmpeg()
	if path == "" {
		return nil, "", errors.New("ffmpeg не найден")
	}
	cmd := exec.CommandContext(ctx, path,
		"-hide_banner",
		"-f", "dshow",
		"-list_devices", "true",
		"-i", "dummy",
	)
	var buf bytes.Buffer
	cmd.Stderr = &buf
	_ = cmd.Run() // ffmpeg exits 1 when listing — expected

	raw := buf.String()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, raw, errors.New("ffmpeg -list_devices завис (>8с) — перезапустите клиент, проверьте, не занята ли камера другой программой")
	}
	return parseDshowOutput(raw), raw, nil
}

// parseDshowOutput extracts quoted device names from ffmpeg's DirectShow
// enumeration output. Handles TWO format generations:
//
//  OLD (ffmpeg <= 6.x): section headers separate video and audio:
//    [dshow @ ...] DirectShow video devices (...)
//    [dshow @ ...]  "Integrated Webcam"
//    [dshow @ ...]     Alternative name "..."
//    [dshow @ ...] DirectShow audio devices
//    [dshow @ ...]  "Microphone"
//
//  NEW (ffmpeg >= 7.x): each device line is self-describing with a
//  (video)/(audio)/(none) tag, no section headers:
//    [in#0 @ ...] "Microsoft® LifeCam HD-3000" (video)
//    [in#0 @ ...]   Alternative name "..."
//    [in#0 @ ...] "Microphone (Realtek)" (audio)
//
// We detect per-line tags first; fall back to section tracking for the
// old format.
func parseDshowOutput(s string) []string {
	var devices []string
	inVideo := false
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "DirectShow video devices") {
			inVideo = true
			continue
		}
		if strings.Contains(line, "DirectShow audio devices") {
			inVideo = false
			continue
		}
		if strings.Contains(line, "Alternative name") {
			continue
		}

		// Extract the first quoted substring — that's the device name.
		idx := strings.Index(line, `"`)
		if idx == -1 {
			continue
		}
		rest := line[idx+1:]
		end := strings.Index(rest, `"`)
		if end == -1 {
			continue
		}
		name := rest[:end]
		after := rest[end+1:]

		// New-format tag check takes priority.
		if strings.Contains(after, "(video)") {
			devices = append(devices, name)
			continue
		}
		if strings.Contains(after, "(audio)") {
			continue
		}
		if strings.Contains(after, "(none)") {
			// Virtual-camera driver that ffmpeg can't classify — skip by
			// default; user can still type the name manually.
			continue
		}

		// No tag seen — must be old format where we rely on the section
		// header we saw earlier.
		if inVideo {
			devices = append(devices, name)
		}
	}
	return devices
}

var avfLineRe = regexp.MustCompile(`\[(\d+)\]\s+(.+)`)

func listAVFoundationCameras() ([]string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	path := ResolveFFmpeg()
	if path == "" {
		return nil, "", errors.New("ffmpeg не найден")
	}
	cmd := exec.CommandContext(ctx, path,
		"-hide_banner",
		"-f", "avfoundation",
		"-list_devices", "true",
		"-i", "",
	)
	var buf bytes.Buffer
	cmd.Stderr = &buf
	_ = cmd.Run()

	raw := buf.String()
	var devices []string
	inVideo := false
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, "AVFoundation video devices") {
			inVideo = true
			continue
		}
		if strings.Contains(line, "AVFoundation audio devices") {
			inVideo = false
			continue
		}
		if !inVideo {
			continue
		}
		if m := avfLineRe.FindStringSubmatch(line); m != nil {
			devices = append(devices, m[1]) // use the numeric ID for -i
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		return nil, raw, errors.New("ffmpeg -list_devices завис (>8с)")
	}
	return devices, raw, nil
}

// -----------------------------------------------------------------------------
// Camera capture source
// -----------------------------------------------------------------------------

type ffmpegCameraSource struct {
	cmd      *exec.Cmd
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	frameBuf []byte
	closedMu sync.Mutex
	closed   bool

	// stderrTail keeps the last N bytes of ffmpeg's stderr so we can
	// surface a useful error message when the camera fails to open or
	// dies mid-capture. Without this, ffmpeg failures are invisible and
	// look like "black screen".
	stderrTail   []byte
	stderrTailMu sync.Mutex
}

// OpenCameraSource starts an ffmpeg subprocess capturing the named camera and
// exposes it as a VideoSource producing ASCII frames at CameraFPS.
// deviceName can be:
//   Windows: DirectShow device name (e.g. "Integrated Webcam") — empty uses first
//   Linux:   path like "/dev/video0" — empty uses /dev/video0
//   macOS:   numeric index as string — empty uses "0"
func OpenCameraSource(deviceName string) (VideoSource, error) {
	if !CameraAvailable() {
		return nil, errors.New("ffmpeg не найден в PATH — установите ffmpeg (choco install ffmpeg / apt install ffmpeg / brew install ffmpeg)")
	}

	args := []string{
		"-hide_banner",
		"-loglevel", "error",
	}
	switch runtime.GOOS {
	case "windows":
		dn := deviceName
		if dn == "" {
			// Pick first available device.
			cams, _, _ := listDShowCameras()
			if len(cams) == 0 {
				return nil, errors.New("камер DirectShow не обнаружено")
			}
			dn = cams[0]
		}
		args = append(args,
			"-f", "dshow",
			"-framerate", fmt.Sprint(cameraFPS),
			"-i", fmt.Sprintf("video=%s", dn),
		)
	case "linux":
		dn := deviceName
		if dn == "" {
			dn = "/dev/video0"
		}
		args = append(args,
			"-f", "v4l2",
			"-framerate", fmt.Sprint(cameraFPS),
			"-i", dn,
		)
	case "darwin":
		dn := deviceName
		if dn == "" {
			dn = "0"
		}
		args = append(args,
			"-f", "avfoundation",
			"-framerate", fmt.Sprint(cameraFPS),
			"-i", dn,
		)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	// Common output options: scale to target, emit rgb24 rawvideo to stdout.
	args = append(args,
		"-vf", fmt.Sprintf("scale=%d:%d", cameraW, cameraH),
		"-pix_fmt", "rgb24",
		"-f", "rawvideo",
		"-",
	)

	cmd := ffmpegCommand( args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("запуск ffmpeg: %w", err)
	}

	src := &ffmpegCameraSource{
		cmd:      cmd,
		stdout:   stdout,
		stderr:   stderr,
		frameBuf: make([]byte, frameBytes),
	}
	// Drain stderr into a rolling tail buffer so we can report ffmpeg's
	// actual error message if something goes wrong.
	go src.drainStderr()
	return src, nil
}

// drainStderr pumps ffmpeg stderr into a capped ring (~4KB) so the most
// recent diagnostic lines are available when NextFrame fails.
func (c *ffmpegCameraSource) drainStderr() {
	const maxBytes = 4 * 1024
	buf := make([]byte, 512)
	for {
		n, err := c.stderr.Read(buf)
		if n > 0 {
			c.stderrTailMu.Lock()
			c.stderrTail = append(c.stderrTail, buf[:n]...)
			if over := len(c.stderrTail) - maxBytes; over > 0 {
				c.stderrTail = c.stderrTail[over:]
			}
			c.stderrTailMu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// recentStderr returns a cleaned-up copy of the tail buffer — safe for
// inclusion in user-visible error messages.
func (c *ffmpegCameraSource) recentStderr() string {
	c.stderrTailMu.Lock()
	defer c.stderrTailMu.Unlock()
	s := strings.TrimSpace(string(c.stderrTail))
	// Collapse duplicate whitespace for readability.
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > 500 {
		s = "..." + s[len(s)-500:]
	}
	return s
}

// NextFrame reads the next WxH RGB24 frame from ffmpeg's stdout and renders
// it to ASCII. It also applies a horizontal mirror — users expect a mirror
// image of themselves on a video call.
func (c *ffmpegCameraSource) NextFrame() (string, time.Duration, error) {
	c.closedMu.Lock()
	if c.closed {
		c.closedMu.Unlock()
		return "", 0, io.EOF
	}
	c.closedMu.Unlock()

	if _, err := io.ReadFull(c.stdout, c.frameBuf); err != nil {
		// If the source was Close()'d while we were reading, return EOF
		// so the capture loop treats it as normal shutdown (no scary
		// "file already closed" error log). This happens when the peer
		// hangs up mid-call.
		c.closedMu.Lock()
		closed := c.closed
		c.closedMu.Unlock()
		if closed {
			return "", 0, io.EOF
		}
		// Real error — enrich with ffmpeg's stderr so the user knows
		// WHY the camera failed (device busy, not found, bad format...).
		if tail := c.recentStderr(); tail != "" {
			return "", 0, fmt.Errorf("%w | ffmpeg: %s", err, tail)
		}
		return "", 0, err
	}

	// Reconstruct an RGBA image from the RGB24 buffer. Mirror horizontally
	// while we're at it — feels more natural when you're the subject.
	img := image.NewRGBA(image.Rect(0, 0, cameraW, cameraH))
	for y := 0; y < cameraH; y++ {
		for x := 0; x < cameraW; x++ {
			srcIdx := (y*cameraW + x) * 3
			dstX := cameraW - 1 - x
			dstIdx := (y*cameraW + dstX) * 4
			img.Pix[dstIdx+0] = c.frameBuf[srcIdx+0]
			img.Pix[dstIdx+1] = c.frameBuf[srcIdx+1]
			img.Pix[dstIdx+2] = c.frameBuf[srcIdx+2]
			img.Pix[dstIdx+3] = 255
		}
	}

	frame := AsciiFrame(img, VideoCols, VideoRows)
	// We return a tiny delay (1ms) because ffmpeg already paces the output
	// at the requested frame rate. A longer delay here would cause frames
	// to back up in the pipe.
	return frame, time.Millisecond, nil
}

func (c *ffmpegCameraSource) Close() error {
	c.closedMu.Lock()
	if c.closed {
		c.closedMu.Unlock()
		return nil
	}
	c.closed = true
	c.closedMu.Unlock()

	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	if c.stdout != nil {
		_ = c.stdout.Close()
	}
	if c.stderr != nil {
		_ = c.stderr.Close()
	}
	if c.cmd != nil {
		_ = c.cmd.Wait() // reap
	}
	return nil
}

// -----------------------------------------------------------------------------
// Source routing — respects Settings.VideoSourceType
// -----------------------------------------------------------------------------

// OpenDefaultVideoSource picks a source according to Settings:
//   - "camera": spawn ffmpeg on the selected device ID
//   - "file":   stub image/GIF from Settings.VideoSourcePath
//   - "":       prefer camera if device is configured, else fall back to file
func OpenDefaultVideoSource() (VideoSource, error) {
	s := LoadSettings()
	switch s.VideoSourceType {
	case "camera":
		return OpenCameraSource(s.VideoCameraID)
	case "file":
		if s.VideoSourcePath == "" {
			return nil, errors.New("источник-файл не задан в настройках")
		}
		return OpenVideoSource(s.VideoSourcePath)
	case "ascii":
		// Built-in placeholder — zero setup needed.
		return OpenAsciiAvatarSource()
	}
	// Auto-pick.
	if s.VideoCameraID != "" || (s.VideoSourcePath == "" && CameraAvailable()) {
		return OpenCameraSource(s.VideoCameraID)
	}
	if s.VideoSourcePath == "" {
		return nil, errors.New("источник видео не задан — настройте в .settings")
	}
	return OpenVideoSource(s.VideoSourcePath)
}
