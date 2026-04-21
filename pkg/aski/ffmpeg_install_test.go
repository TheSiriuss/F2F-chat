package f2f

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Path resolution + cache lookup
// -----------------------------------------------------------------------------

func TestFFmpegCacheDir_ReturnsSubpath(t *testing.T) {
	dir, err := ffmpegCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dir, "f2f-chat") {
		t.Fatalf("expected f2f-chat in cache dir, got %q", dir)
	}
	if !strings.Contains(dir, "ffmpeg") {
		t.Fatalf("expected ffmpeg in cache dir, got %q", dir)
	}
}

func TestFFmpegExecName_Platform(t *testing.T) {
	name := ffmpegExecName()
	if name != "ffmpeg" && name != "ffmpeg.exe" {
		t.Fatalf("unexpected name %q", name)
	}
}

func TestResolveFFmpeg_NoCrash(t *testing.T) {
	// Just make sure it doesn't panic regardless of environment.
	_ = ResolveFFmpeg()
}

// -----------------------------------------------------------------------------
// Zip extraction
// -----------------------------------------------------------------------------

// makeFakeFFmpegZip builds an in-memory zip file that mimics BtbN's directory
// layout (top-level folder → bin/ → executables + DLLs).
func makeFakeFFmpegZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	entries := []struct {
		name string
		body []byte
	}{
		{"ffmpeg-master-latest-win64-gpl-shared/bin/ffmpeg.exe", []byte("MZ\x00\x00fake ffmpeg exe")},
		{"ffmpeg-master-latest-win64-gpl-shared/bin/ffprobe.exe", []byte("fake ffprobe")},
		{"ffmpeg-master-latest-win64-gpl-shared/bin/avcodec-60.dll", []byte("fake avcodec dll")},
		{"ffmpeg-master-latest-win64-gpl-shared/bin/avformat-60.dll", []byte("fake avformat dll")},
		{"ffmpeg-master-latest-win64-gpl-shared/doc/README.txt", []byte("docs")},
		{"ffmpeg-master-latest-win64-gpl-shared/LICENSE", []byte("gpl")},
	}
	for _, e := range entries {
		f, err := w.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractFFmpegFromZip_FindsExe(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "ff.zip")
	if err := os.WriteFile(zipPath, makeFakeFFmpegZip(t), 0644); err != nil {
		t.Fatal(err)
	}

	target, err := extractFFmpegFromZip(zipPath, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(target) != "ffmpeg.exe" {
		t.Fatalf("target = %q", target)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("fake ffmpeg exe")) {
		t.Fatalf("extracted content doesn't match: %q", data)
	}
}

func TestExtractFFmpegFromZip_AlsoPullsDLLs(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "ff.zip")
	os.WriteFile(zipPath, makeFakeFFmpegZip(t), 0644)
	if _, err := extractFFmpegFromZip(zipPath, dir, nil); err != nil {
		t.Fatal(err)
	}
	// Shared builds need the DLLs alongside the exe.
	for _, want := range []string{"avcodec-60.dll", "avformat-60.dll"} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("%s not extracted: %v", want, err)
		}
	}
}

func TestExtractFFmpegFromZip_SkipsDocs(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "ff.zip")
	os.WriteFile(zipPath, makeFakeFFmpegZip(t), 0644)
	if _, err := extractFFmpegFromZip(zipPath, dir, nil); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"README.txt", "LICENSE"} {
		if _, err := os.Stat(filepath.Join(dir, bad)); err == nil {
			t.Errorf("should not extract %s", bad)
		}
	}
}

func TestExtractFFmpegFromZip_NoFFmpegInside(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("ffmpeg-build/doc/readme.txt")
	f.Write([]byte("no exe here"))
	w.Close()

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "empty.zip")
	os.WriteFile(zipPath, buf.Bytes(), 0644)

	if _, err := extractFFmpegFromZip(zipPath, dir, nil); err == nil {
		t.Fatal("expected error when archive has no ffmpeg.exe")
	}
}

func TestExtractFFmpegFromZip_EmitsProgress(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "ff.zip")
	os.WriteFile(zipPath, makeFakeFFmpegZip(t), 0644)

	var calls int
	progress := func(stage string, done, total int64) {
		if stage != "extract" {
			t.Errorf("unexpected stage %q", stage)
		}
		if done > total {
			t.Errorf("done(%d) > total(%d)", done, total)
		}
		calls++
	}
	if _, err := extractFFmpegFromZip(zipPath, dir, progress); err != nil {
		t.Fatal(err)
	}
	if calls == 0 {
		t.Fatal("progress callback never fired")
	}
}

// -----------------------------------------------------------------------------
// progressReader
// -----------------------------------------------------------------------------

func TestProgressReader_ReportsBytes(t *testing.T) {
	src := bytes.NewReader(bytes.Repeat([]byte("x"), 1000))
	var lastDone int64
	pr := &progressReader{
		r:     src,
		total: 1000,
		cb: func(stage string, done, total int64) {
			lastDone = done
		},
		stage: "test",
	}
	// Read small chunks to avoid the throttle skipping everything.
	buf := make([]byte, 10)
	for {
		_, err := pr.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if pr.done != 1000 {
		t.Fatalf("pr.done = %d, want 1000", pr.done)
	}
	_ = lastDone // may or may not have fired due to throttling
}

// -----------------------------------------------------------------------------
// ffmpegCommand routing
// -----------------------------------------------------------------------------

func TestFFmpegCommand_UsesResolvedPathIfSet(t *testing.T) {
	// Prime the resolved path.
	ffmpegResolvedMu.Lock()
	old := ffmpegResolved
	ffmpegResolved = "/fake/custom/ffmpeg"
	ffmpegResolvedMu.Unlock()
	t.Cleanup(func() {
		ffmpegResolvedMu.Lock()
		ffmpegResolved = old
		ffmpegResolvedMu.Unlock()
	})

	cmd := ffmpegCommand("-version")
	if cmd.Path != "/fake/custom/ffmpeg" {
		t.Fatalf("cmd.Path = %q, want /fake/custom/ffmpeg", cmd.Path)
	}
	if len(cmd.Args) < 1 || cmd.Args[0] != "/fake/custom/ffmpeg" {
		t.Fatalf("cmd.Args[0] = %q", cmd.Args)
	}
}

func TestEnsureFFmpeg_NonWindowsNoInstall(t *testing.T) {
	// Run is platform-dependent. Only meaningful assertions:
	// — if platform isn't Windows AND ffmpeg isn't present, we should get
	//   an error telling the user to install via package manager.
	if ResolveFFmpeg() != "" {
		t.Skip("ffmpeg already present — can't test missing path")
	}
	// Calling EnsureFFmpeg will block on download on Windows; skip there.
	// For non-Windows CI we at least want to assert non-nil error.
	// Guard with explicit GOOS check via ffmpegExecName.
	if ffmpegExecName() == "ffmpeg.exe" {
		t.Skip("Windows: would attempt real download")
	}
	_, err := EnsureFFmpeg(nil)
	if err == nil {
		t.Fatal("expected error when ffmpeg absent on non-Windows")
	}
}
