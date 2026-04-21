package f2f

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// WAV header write/parse roundtrip
// ---------------------------------------------------------------------------

func TestWriteWAV_ValidHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wav")
	pcm := []byte{0, 0, 1, 0, 2, 0, 3, 0, 4, 0}
	if err := WriteWAV(path, 16000, 1, pcm); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Minimum header = 44 bytes; our write produces exactly that + data.
	if len(data) != 44+len(pcm) {
		t.Fatalf("unexpected size %d, want %d", len(data), 44+len(pcm))
	}
	if string(data[0:4]) != "RIFF" {
		t.Fatalf("bad RIFF magic: %q", data[0:4])
	}
	if string(data[8:12]) != "WAVE" {
		t.Fatalf("bad WAVE magic: %q", data[8:12])
	}
	if string(data[12:16]) != "fmt " {
		t.Fatalf("bad fmt chunk id: %q", data[12:16])
	}
	if string(data[36:40]) != "data" {
		t.Fatalf("bad data chunk id: %q", data[36:40])
	}
}

func TestWriteWAV_ParseRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rt.wav")
	pcm := bytes.Repeat([]byte{0xAA, 0x55}, 8000) // 16000 bytes = 0.5s @ 16kHz mono 16-bit
	if err := WriteWAV(path, 16000, 1, pcm); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	info, err := ParseWAV(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if info.SampleRate != 16000 {
		t.Fatalf("sample rate %d", info.SampleRate)
	}
	if info.Channels != 1 {
		t.Fatalf("channels %d", info.Channels)
	}
	if info.BitDepth != 16 {
		t.Fatalf("bit depth %d", info.BitDepth)
	}
	if info.DataLen != uint32(len(pcm)) {
		t.Fatalf("data len %d want %d", info.DataLen, len(pcm))
	}

	readback := make([]byte, info.DataLen)
	if _, err := f.ReadAt(readback, info.DataOffset); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readback, pcm) {
		t.Fatal("data corrupted in roundtrip")
	}
}

func TestWriteWAV_Stereo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stereo.wav")
	pcm := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 100)
	if err := WriteWAV(path, 48000, 2, pcm); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(path)
	defer f.Close()
	info, err := ParseWAV(f)
	if err != nil {
		t.Fatal(err)
	}
	if info.Channels != 2 || info.SampleRate != 48000 {
		t.Fatalf("bad stereo roundtrip: %+v", info)
	}
}

func TestParseWAV_RejectsNonRIFF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-wav.bin")
	os.WriteFile(path, []byte("this is not a wav file at all"), 0644)
	f, _ := os.Open(path)
	defer f.Close()
	if _, err := ParseWAV(f); err == nil {
		t.Fatal("expected error for non-RIFF data")
	}
}

func TestParseWAV_RejectsNonPCM(t *testing.T) {
	// Build a WAV with format=3 (IEEE float) to confirm we reject it.
	pcm := []byte{0, 0, 1, 0}
	dir := t.TempDir()
	path := filepath.Join(dir, "float.wav")
	if err := WriteWAV(path, 16000, 1, pcm); err != nil {
		t.Fatal(err)
	}
	// Patch format field (offset 20) from 1 to 3.
	data, _ := os.ReadFile(path)
	data[20] = 3
	os.WriteFile(path, data, 0644)
	f, _ := os.Open(path)
	defer f.Close()
	if _, err := ParseWAV(f); err == nil {
		t.Fatal("expected error for non-PCM format")
	}
}

// ---------------------------------------------------------------------------
// IsVoiceMessage — strict "voicemail-N.wav" match
// ---------------------------------------------------------------------------

func TestIsVoiceMessage_Match(t *testing.T) {
	cases := []string{"voicemail-1.wav", "voicemail-42.wav", "VOICEMAIL-7.WAV"}
	for _, c := range cases {
		if !IsVoiceMessage(c) {
			t.Errorf("%q should match", c)
		}
	}
}

func TestIsVoiceMessage_Reject(t *testing.T) {
	cases := []string{
		"voicemail.wav",       // no number
		"voicemail-.wav",      // empty number
		"voicemail-abc.wav",   // non-numeric
		"voicemail-0.wav",     // zero (sequence starts at 1)
		"voicemail--1.wav",    // negative
		"photo.jpg",           // wrong type
		"recording.wav",       // wrong prefix
		"voice-20260417.wav",  // OLD timestamp-style name, no longer matches
		"RECORDING.WAV",       // wrong prefix
		"",                    //
	}
	for _, c := range cases {
		if IsVoiceMessage(c) {
			t.Errorf("%q should NOT match", c)
		}
	}
}

// ---------------------------------------------------------------------------
// NextVoicemailName sequence
// ---------------------------------------------------------------------------

func TestNextVoicemailName_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	got := NextVoicemailName(dir)
	if got != "voicemail-1.wav" {
		t.Fatalf("expected voicemail-1.wav, got %q", got)
	}
}

func TestNextVoicemailName_WithExisting(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []int{1, 2, 5} {
		path := fmt.Sprintf("%s/voicemail-%d.wav", dir, n)
		os.WriteFile(path, []byte("x"), 0644)
	}
	got := NextVoicemailName(dir)
	// Max existing is 5 → next is 6.
	if got != "voicemail-6.wav" {
		t.Fatalf("expected voicemail-6.wav, got %q", got)
	}
}

func TestNextVoicemailName_IgnoresNonMatching(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/voicemail-10.wav", []byte("x"), 0644)
	os.WriteFile(dir+"/photo.jpg", []byte("x"), 0644)
	os.WriteFile(dir+"/voicemail-abc.wav", []byte("x"), 0644)
	os.WriteFile(dir+"/recording.wav", []byte("x"), 0644)
	got := NextVoicemailName(dir)
	if got != "voicemail-11.wav" {
		t.Fatalf("expected voicemail-11.wav, got %q", got)
	}
}

func TestNextVoicemailName_NonExistentDirFallsBackToOne(t *testing.T) {
	got := NextVoicemailName("/definitely/does/not/exist/anywhere")
	if got != "voicemail-1.wav" {
		t.Fatalf("should start at 1 when dir missing, got %q", got)
	}
}

func TestNextVoicemailName_IgnoresSubdirs(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(dir+"/voicemail-99.wav", 0755) // directory, not file
	got := NextVoicemailName(dir)
	if got != "voicemail-1.wav" {
		t.Fatalf("should ignore directories, got %q", got)
	}
}

func TestParseVoicemailIndex(t *testing.T) {
	cases := map[string]int{
		"voicemail-1.wav":   1,
		"voicemail-42.wav":  42,
		"VOICEMAIL-7.WAV":   7,
		"voicemail-0.wav":   0,
		"voicemail-.wav":    0,
		"voicemail-abc.wav": 0,
		"photo.jpg":         0,
		"":                  0,
	}
	for in, want := range cases {
		if got := parseVoicemailIndex(in); got != want {
			t.Errorf("parseVoicemailIndex(%q) = %d, want %d", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Hex helpers (unit tests for the device-ID codec)
// ---------------------------------------------------------------------------

func TestHexDecode_Roundtrip(t *testing.T) {
	out, err := hexDecode("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("got %x", out)
	}
}

func TestHexDecode_OddLength(t *testing.T) {
	if _, err := hexDecode("abc"); err == nil {
		t.Fatal("odd-length should error")
	}
}

func TestHexDecode_BadChar(t *testing.T) {
	if _, err := hexDecode("zz"); err == nil {
		t.Fatal("bad hex char should error")
	}
}

func TestHexDecode_MixedCase(t *testing.T) {
	out, err := hexDecode("AaFf")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0xAA, 0xFF}) {
		t.Fatalf("got %x", out)
	}
}

// ---------------------------------------------------------------------------
// Recorder (we don't touch a real device — this just confirms the API returns
// sensible errors on bogus device IDs rather than panicking)
// ---------------------------------------------------------------------------

func TestNewRecorder_BadDeviceID(t *testing.T) {
	// Odd hex → decode failure, should not panic.
	if _, err := NewRecorder("zz"); err == nil {
		t.Fatal("expected error for invalid hex id")
	}
}

// ---------------------------------------------------------------------------
// ListAudioDevices doesn't need real hardware — miniaudio returns an empty
// list if no devices exist. Just make sure it doesn't crash.
// ---------------------------------------------------------------------------

func TestListAudioDevices_NoCrash(t *testing.T) {
	if _, err := ListAudioDevices(); err != nil {
		// On CI with no sound hardware this can still succeed (returns empty list).
		// An error isn't inherently wrong — we just want to ensure no panic.
		t.Logf("ListAudioDevices returned error (OK in headless env): %v", err)
	}
}
