package f2f

import (
	"os"
	"testing"
)

func TestSettings_LoadDefault_NoFile(t *testing.T) {
	chdirTemp(t)
	ResetSettingsCache()
	s := LoadSettings()
	if s == nil {
		t.Fatal("nil settings")
	}
	if s.AudioInputDeviceID != "" || s.AudioOutputDeviceID != "" {
		t.Fatal("defaults should be empty device IDs")
	}
	if s.VoiceAutoPlay {
		t.Fatal("auto-play default should be false")
	}
}

func TestSettings_SaveLoad_Roundtrip(t *testing.T) {
	chdirTemp(t)
	ResetSettingsCache()
	orig := &Settings{
		AudioInputDeviceID:    "aabbcc",
		AudioInputDeviceName:  "Микрофон (Realtek)",
		AudioOutputDeviceID:   "ddeeff",
		AudioOutputDeviceName: "Колонки",
		VoiceAutoPlay:         true,
	}
	if err := SaveSettings(orig); err != nil {
		t.Fatal(err)
	}

	ResetSettingsCache()
	got := LoadSettings()
	if got.AudioInputDeviceID != orig.AudioInputDeviceID ||
		got.AudioInputDeviceName != orig.AudioInputDeviceName ||
		got.AudioOutputDeviceID != orig.AudioOutputDeviceID ||
		got.AudioOutputDeviceName != orig.AudioOutputDeviceName ||
		got.VoiceAutoPlay != orig.VoiceAutoPlay {
		t.Fatalf("mismatch: %+v vs %+v", got, orig)
	}
}

func TestSettings_JSONIsPlaintext(t *testing.T) {
	chdirTemp(t)
	ResetSettingsCache()
	s := &Settings{AudioInputDeviceName: "MARKER-DEVICE-NAME"}
	if err := SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(SettingsFile)
	if err != nil {
		t.Fatal(err)
	}
	// Must be plaintext JSON (no encryption) — device names are not sensitive.
	if !bytesContains(data, []byte("MARKER-DEVICE-NAME")) {
		t.Fatal("device name not found in plaintext — settings unexpectedly encrypted?")
	}
}

func TestSettings_CorruptedFileFallsBackToDefaults(t *testing.T) {
	chdirTemp(t)
	ResetSettingsCache()
	if err := os.WriteFile(SettingsFile, []byte("this is not json {{{"), 0644); err != nil {
		t.Fatal(err)
	}
	s := LoadSettings()
	if s == nil {
		t.Fatal("should not return nil on corrupt file")
	}
	if s.AudioInputDeviceID != "" {
		t.Fatal("should have default values after corruption fallback")
	}
}

func TestSettings_NilSaveIsNoOp(t *testing.T) {
	chdirTemp(t)
	ResetSettingsCache()
	if err := SaveSettings(nil); err != nil {
		t.Fatalf("nil save should not error: %v", err)
	}
	if _, err := os.Stat(SettingsFile); !os.IsNotExist(err) {
		t.Fatal("nil save must not create file")
	}
}

func TestSettings_CacheIsolated(t *testing.T) {
	chdirTemp(t)
	ResetSettingsCache()
	s1 := LoadSettings()
	s1.AudioInputDeviceID = "mutate-in-caller"
	// Cache must not be mutated by caller-side edits.
	s2 := LoadSettings()
	if s2.AudioInputDeviceID == "mutate-in-caller" {
		t.Fatal("caller mutation leaked into cache")
	}
}

// small local substring helper so this file doesn't pull bytes.Contains.
func bytesContains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
