package f2f

import (
	"reflect"
	"testing"
)

// -----------------------------------------------------------------------------
// parseDshowOutput — the string format is version-stable from ffmpeg 4.x→7.x
// -----------------------------------------------------------------------------

const sampleDshowOutput = `[dshow @ 0000000000000] DirectShow video devices (some may be both video and audio devices)
[dshow @ 0000000000000]  "Integrated Webcam"
[dshow @ 0000000000000]     Alternative name "@device_pnp_\\?\usb#vid_0c45&pid_6713..."
[dshow @ 0000000000000]  "OBS Virtual Camera"
[dshow @ 0000000000000]     Alternative name "@device_sw_{860BB310-5D01-11D0-BD3B-00A0C911CE86}\{A3FCE0F5-3493-419F-958A-ABA1250EC20B}"
[dshow @ 0000000000000] DirectShow audio devices
[dshow @ 0000000000000]  "Microphone (Realtek)"
[dshow @ 0000000000000]     Alternative name "@device_cm_{33D9A762-90C8-11D0-BD43-00A0C911CE86}\wave_{...}"
dummy: Immediate exit requested`

func TestParseDshowOutput_Normal(t *testing.T) {
	got := parseDshowOutput(sampleDshowOutput)
	want := []string{"Integrated Webcam", "OBS Virtual Camera"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseDshowOutput_NoVideoDevices(t *testing.T) {
	input := `[dshow @ ...] DirectShow audio devices
[dshow @ ...]  "Microphone"`
	got := parseDshowOutput(input)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestParseDshowOutput_SkipsAlternativeNames(t *testing.T) {
	input := `[dshow @ ...] DirectShow video devices
[dshow @ ...]  "Real Camera"
[dshow @ ...]     Alternative name "@device_pnp_this_should_not_appear"
[dshow @ ...] DirectShow audio devices`
	got := parseDshowOutput(input)
	if len(got) != 1 || got[0] != "Real Camera" {
		t.Fatalf("got %v, want [Real Camera]", got)
	}
}

func TestParseDshowOutput_Empty(t *testing.T) {
	got := parseDshowOutput("")
	if len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

// ffmpeg 7.x+ output: no section headers, per-line (video)/(audio)/(none) tags.
const sampleDshowNewFormat = `[in#0 @ 000fcc80] "Camo" (video)
[in#0 @ 000fcc80]   Alternative name "@device_pnp_..."
[in#0 @ 000fcc80] "Microsoft® LifeCam HD-3000" (video)
[in#0 @ 000fcc80]   Alternative name "@device_pnp_..."
[in#0 @ 000fcc80] "Camera (NVIDIA Broadcast)" (video)
[in#0 @ 000fcc80]   Alternative name "..."
[in#0 @ 000fcc80] "OBS Virtual Camera" (none)
[in#0 @ 000fcc80]   Alternative name "..."
[in#0 @ 000fcc80] "Microphone (fifine)" (audio)
[in#0 @ 000fcc80]   Alternative name "..."
Error opening input file dummy.`

func TestParseDshowOutput_NewFormat_Video(t *testing.T) {
	got := parseDshowOutput(sampleDshowNewFormat)
	want := []string{"Camo", "Microsoft® LifeCam HD-3000", "Camera (NVIDIA Broadcast)"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseDshowOutput_NewFormat_SkipsAudio(t *testing.T) {
	got := parseDshowOutput(sampleDshowNewFormat)
	for _, d := range got {
		if d == "Microphone (fifine)" {
			t.Fatalf("audio device leaked into video list: %v", got)
		}
	}
}

func TestParseDshowOutput_NewFormat_SkipsNoneTyped(t *testing.T) {
	// OBS Virtual Camera shows up as (none) — our auto-picker shouldn't
	// include it because ffmpeg can't classify it as video.
	got := parseDshowOutput(sampleDshowNewFormat)
	for _, d := range got {
		if d == "OBS Virtual Camera" {
			t.Fatalf("(none)-tagged device leaked: %v", got)
		}
	}
}

func TestParseDshowOutput_NewFormat_IgnoresNoiseLines(t *testing.T) {
	// Various NVIDIA / driver diagnostic spam intermixed with real devices.
	in := `I2026-04-18 03:32:21.655335 (27032) [INFO] [VCAMDS] ffmpeg.exe
E2026-04-18 03:32:21.655855 (27032)  [ERR] [VCAMDS] Failed to open NBX hive
[in#0 @ 000fcc80] "RealCam" (video)
[in#0 @ 000fcc80]   Alternative name "..."`
	got := parseDshowOutput(in)
	want := []string{"RealCam"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// -----------------------------------------------------------------------------
// CameraAvailable — just test it returns a bool without panicking.
// On our headless test machine ffmpeg is likely absent; that's fine.
// -----------------------------------------------------------------------------

func TestCameraAvailable_NoCrash(t *testing.T) {
	_ = CameraAvailable()
}

// -----------------------------------------------------------------------------
// OpenCameraSource without ffmpeg must fail gracefully.
// -----------------------------------------------------------------------------

func TestOpenCameraSource_NoFFmpeg_Error(t *testing.T) {
	if CameraAvailable() {
		t.Skip("ffmpeg is available on this machine — can't test missing-ffmpeg path")
	}
	if _, err := OpenCameraSource(""); err == nil {
		t.Fatal("expected error when ffmpeg is missing")
	}
}

// -----------------------------------------------------------------------------
// OpenDefaultVideoSource: routing logic without actually opening anything
// -----------------------------------------------------------------------------

func TestOpenDefaultVideoSource_EmptySettings_Error(t *testing.T) {
	chdirTemp(t)
	ResetSettingsCache()
	// No settings file → no camera, no stub file → should error clearly.
	if _, err := OpenDefaultVideoSource(); err == nil {
		if CameraAvailable() {
			// If ffmpeg exists on dev box, it might actually try to find a
			// camera; skip instead of failing.
			t.Skip("ffmpeg present — cannot robustly test empty-settings branch")
		}
		t.Fatal("expected error with no settings + no ffmpeg")
	}
}

// -----------------------------------------------------------------------------
// Constants sanity
// -----------------------------------------------------------------------------

func TestCameraConstants(t *testing.T) {
	if cameraW <= 0 || cameraH <= 0 || cameraFPS <= 0 {
		t.Fatal("camera constants must be positive")
	}
	if frameBytes != cameraW*cameraH*3 {
		t.Fatalf("frameBytes math wrong: %d vs %d*%d*3", frameBytes, cameraW, cameraH)
	}
}
