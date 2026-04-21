package f2f

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------
// Auto-install of ffmpeg.
//
// Strategy:
//   1) exec.LookPath("ffmpeg") — system-installed, use it as-is.
//   2) Look for a cached binary under $UserCacheDir/f2f-chat/ffmpeg/.
//   3) On Windows only, download a static build from BtbN's GitHub release
//      (actively maintained, signed GitHub-hosted artefacts), unzip the
//      ffmpeg.exe from the archive, cache it, and use it.
//   4) On Linux / macOS, tell the user to install via their package manager.
//
// All subsequent camera/ffmpeg calls go through ffmpegCommand() which
// reads the resolved path from a package-level sync.Once-guarded variable.
// -----------------------------------------------------------------------------

// BtbN's "latest" alias always points at the newest successful master build.
const ffmpegWindowsURL = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl-shared.zip"

// ffmpegHashFile is the name of the SHA-256 sidecar we write next to the
// installed ffmpeg binary. On every launch we recompute the hash of the
// cached exe and compare — this is Trust-On-First-Use:
//
//   1) First EnsureFFmpeg() download → record hash of the downloaded archive.
//   2) Subsequent ResolveFFmpeg() calls verify the cached exe still hashes
//      to the same value. If someone (malware, curious user) replaces
//      ffmpeg.exe after we downloaded it, we detect it and refuse to run.
//
// This doesn't protect against a malicious first download (we'd need a
// hardcoded pin for that), but it does protect the cached state from being
// tampered with between sessions.
const ffmpegHashFile = "ffmpeg.sha256"

var (
	ffmpegResolved   string
	ffmpegResolvedMu sync.RWMutex
)

// ffmpegCacheDir returns the per-user directory where we stash downloaded
// ffmpeg binaries. Shared across F2F runs.
func ffmpegCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "f2f-chat", "ffmpeg"), nil
}

// ffmpegExecName returns the platform-appropriate binary filename.
func ffmpegExecName() string {
	if runtime.GOOS == "windows" {
		return "ffmpeg.exe"
	}
	return "ffmpeg"
}

// ResolveFFmpeg returns the absolute path to an ffmpeg executable if one is
// available without downloading (PATH or cache). Empty string + nil error
// means "not found, caller should offer EnsureFFmpeg".
//
// Cached binaries (those we downloaded ourselves) are SHA-256 verified
// against the sidecar hash recorded at download time. If the hash doesn't
// match, we assume someone tampered with the cached exe and refuse to use
// it — the caller will then re-download.
func ResolveFFmpeg() string {
	ffmpegResolvedMu.RLock()
	if ffmpegResolved != "" {
		defer ffmpegResolvedMu.RUnlock()
		return ffmpegResolved
	}
	ffmpegResolvedMu.RUnlock()

	// PATH first — trust the system/package-manager install, no hash check.
	if p, err := exec.LookPath("ffmpeg"); err == nil {
		ffmpegResolvedMu.Lock()
		ffmpegResolved = p
		ffmpegResolvedMu.Unlock()
		return p
	}
	// Cache — must pass integrity check.
	if dir, err := ffmpegCacheDir(); err == nil {
		candidate := filepath.Join(dir, ffmpegExecName())
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			if verifyCachedFFmpeg(candidate, dir) {
				ffmpegResolvedMu.Lock()
				ffmpegResolved = candidate
				ffmpegResolvedMu.Unlock()
				return candidate
			}
			// Tampered — drop it so EnsureFFmpeg re-downloads cleanly.
			_ = os.Remove(candidate)
			_ = os.Remove(filepath.Join(dir, ffmpegHashFile))
		}
	}
	return ""
}

// hashFile computes SHA-256 of a file. Returns hex string.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyCachedFFmpeg compares the cached ffmpeg binary's current SHA-256
// against the value stored in the sidecar file. Returns false if the
// sidecar is missing, unreadable, or the hashes don't match.
func verifyCachedFFmpeg(exePath, cacheDir string) bool {
	hashBytes, err := os.ReadFile(filepath.Join(cacheDir, ffmpegHashFile))
	if err != nil {
		return false
	}
	expected := strings.TrimSpace(string(hashBytes))
	if len(expected) != 64 {
		return false
	}
	actual, err := hashFile(exePath)
	if err != nil {
		return false
	}
	return actual == expected
}

// writeFFmpegHash records the current SHA-256 of the given binary next to it,
// so future ResolveFFmpeg() invocations can verify it hasn't been tampered.
func writeFFmpegHash(exePath, cacheDir string) error {
	h, err := hashFile(exePath)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cacheDir, ffmpegHashFile), []byte(h), 0644)
}

// DownloadProgress gets called periodically during EnsureFFmpeg's download
// step. `stage` is a short human-readable phase ("download", "extract").
type DownloadProgress func(stage string, bytesDone, bytesTotal int64)

// EnsureFFmpeg returns a valid ffmpeg path, downloading if necessary.
// On non-Windows it only resolves existing installs — we don't ship
// replacements for apt/brew-managed ffmpegs.
func EnsureFFmpeg(progress DownloadProgress) (string, error) {
	if p := ResolveFFmpeg(); p != "" {
		return p, nil
	}
	if runtime.GOOS != "windows" {
		return "", errors.New("ffmpeg не найден — установите его через пакетный менеджер (apt install ffmpeg / brew install ffmpeg)")
	}
	return downloadFFmpegWindows(progress)
}

// -----------------------------------------------------------------------------
// Windows downloader
// -----------------------------------------------------------------------------

type progressReader struct {
	r        io.Reader
	total    int64
	done     int64
	cb       DownloadProgress
	stage    string
	lastEmit time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.done += int64(n)
		// Throttle callback to ~8Hz so we don't spam the UI.
		if p.cb != nil && time.Since(p.lastEmit) > 120*time.Millisecond {
			p.cb(p.stage, p.done, p.total)
			p.lastEmit = time.Now()
		}
	}
	return n, err
}

func downloadFFmpegWindows(progress DownloadProgress) (string, error) {
	dir, err := ffmpegCacheDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}

	zipPath := filepath.Join(dir, "ffmpeg-download.zip")
	// Clean up any stale partial file.
	os.Remove(zipPath)

	resp, err := http.Get(ffmpegWindowsURL)
	if err != nil {
		return "", fmt.Errorf("HTTP GET %s: %w", ffmpegWindowsURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP status %d for %s", resp.StatusCode, ffmpegWindowsURL)
	}

	out, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}

	pr := &progressReader{r: resp.Body, total: resp.ContentLength, cb: progress, stage: "download"}
	_, err = io.Copy(out, pr)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(zipPath)
		return "", fmt.Errorf("download: %w", err)
	}
	if progress != nil {
		progress("download", pr.done, pr.total)
	}

	// Extract just ffmpeg.exe.
	extracted, err := extractFFmpegFromZip(zipPath, dir, progress)
	// Regardless of success, remove the download archive to save disk.
	os.Remove(zipPath)
	if err != nil {
		return "", err
	}

	// Record the hash so later sessions can detect tampering of the cached
	// exe. This is TOFU — we trust THIS download (from an HTTPS-secured
	// GitHub release) and pin it going forward.
	if err := writeFFmpegHash(extracted, dir); err != nil {
		return "", fmt.Errorf("record sha256: %w", err)
	}

	ffmpegResolvedMu.Lock()
	ffmpegResolved = extracted
	ffmpegResolvedMu.Unlock()
	return extracted, nil
}

// extractFFmpegFromZip walks a ffmpeg-*-win64-gpl-*.zip and extracts its
// bin/ffmpeg.exe into dir. Also pulls bin/*.dll — the "shared" builds
// require matching DLLs alongside the exe (avcodec, avformat, etc.).
func extractFFmpegFromZip(zipPath, dir string, progress DownloadProgress) (string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()

	var ffmpegTarget string
	var written int64
	var totalExtract int64
	// First pass: size estimate for progress.
	for _, f := range zr.File {
		name := filepath.ToSlash(f.Name)
		if strings.Contains(name, "/bin/") &&
			(strings.HasSuffix(name, "/ffmpeg.exe") || strings.HasSuffix(name, ".dll")) {
			totalExtract += int64(f.UncompressedSize64)
		}
	}

	for _, f := range zr.File {
		name := filepath.ToSlash(f.Name)
		// Only want binaries from the bin/ directory.
		if !strings.Contains(name, "/bin/") {
			continue
		}
		base := filepath.Base(name)
		if base != "ffmpeg.exe" && !strings.HasSuffix(strings.ToLower(base), ".dll") {
			continue
		}

		dst := filepath.Join(dir, base)
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		out, err := os.Create(dst)
		if err != nil {
			rc.Close()
			return "", err
		}
		n, err := io.Copy(out, rc)
		rc.Close()
		closeErr := out.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
		written += n
		if progress != nil && totalExtract > 0 {
			progress("extract", written, totalExtract)
		}
		if base == "ffmpeg.exe" {
			ffmpegTarget = dst
		}
	}

	if ffmpegTarget == "" {
		return "", errors.New("ffmpeg.exe не найден в скачанном архиве")
	}
	return ffmpegTarget, nil
}

// -----------------------------------------------------------------------------
// Wrapped exec helpers — camera.go calls these instead of raw exec.Command
// so we pick up the cached binary transparently.
// -----------------------------------------------------------------------------

func ffmpegCommand(args ...string) *exec.Cmd {
	path := ResolveFFmpeg()
	if path == "" {
		// Let the command fail meaningfully ("file not found") at Start time.
		path = "ffmpeg"
	}
	return exec.Command(path, args...)
}
