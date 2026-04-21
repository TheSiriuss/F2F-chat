package f2f

import (
	"encoding/json"
	"os"
	"sync"
)

// SettingsFile holds non-sensitive user preferences (audio device picks, etc.)
// Stored as plaintext JSON — there are no secrets here, and keeping it plain
// allows the user to edit the file by hand if they ever need to.
const SettingsFile = "settings.json"

// Settings is the user-level app configuration.
type Settings struct {
	// AudioInputDeviceID picks the microphone for .rec. Empty = OS default.
	AudioInputDeviceID string `json:"audio_input_device_id,omitempty"`
	// AudioOutputDeviceID picks the speaker for .play. Empty = OS default.
	AudioOutputDeviceID string `json:"audio_output_device_id,omitempty"`
	// Human-readable names, stored for display convenience.
	AudioInputDeviceName  string `json:"audio_input_device_name,omitempty"`
	AudioOutputDeviceName string `json:"audio_output_device_name,omitempty"`
	// VoiceAutoPlay auto-plays voice messages (.wav files named voice-*) on
	// receive. Off by default — receiver explicitly chooses via .play.
	VoiceAutoPlay bool `json:"voice_auto_play,omitempty"`
	// VideoSourcePath is a default stub file used by .video when no argument
	// is given and source type is "file". PNG/JPG/GIF.
	VideoSourcePath string `json:"video_source_path,omitempty"`
	// VideoSourceType selects between "camera" and "file" for the default
	// .video command. Empty means auto (camera if ffmpeg + device found).
	VideoSourceType string `json:"video_source_type,omitempty"`
	// VideoCameraID is the platform-specific device name passed to ffmpeg:
	//   Windows: DirectShow device name
	//   Linux:   /dev/videoN path
	//   macOS:   AVFoundation index as string
	VideoCameraID string `json:"video_camera_id,omitempty"`

	// Language is the UI locale code ("en", "ru", "de", "fr", "zh", "ja").
	// Empty == default, which is English.
	Language string `json:"language,omitempty"`
}

var (
	settingsCache   *Settings
	settingsCacheMu sync.Mutex
)

// LoadSettings reads settings.json. Returns zero-valued Settings if the file
// doesn't exist, so callers always get a usable struct.
func LoadSettings() *Settings {
	settingsCacheMu.Lock()
	defer settingsCacheMu.Unlock()
	if settingsCache != nil {
		cp := *settingsCache
		return &cp
	}
	s := &Settings{}
	data, err := os.ReadFile(SettingsFile)
	if err != nil {
		settingsCache = s
		cp := *s
		return &cp
	}
	if err := json.Unmarshal(data, s); err != nil {
		// Corrupted — ignore and return defaults rather than fail loudly.
		settingsCache = &Settings{}
		return &Settings{}
	}
	settingsCache = s
	cp := *s
	return &cp
}

// SaveSettings writes settings.json atomically.
func SaveSettings(s *Settings) error {
	if s == nil {
		return nil
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(SettingsFile, data); err != nil {
		return err
	}
	settingsCacheMu.Lock()
	cp := *s
	settingsCache = &cp
	settingsCacheMu.Unlock()
	return nil
}

// ResetSettingsCache clears the in-memory cache. Used in tests that chdir
// into a fresh tempdir.
func ResetSettingsCache() {
	settingsCacheMu.Lock()
	settingsCache = nil
	settingsCacheMu.Unlock()
}
