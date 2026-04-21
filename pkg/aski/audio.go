package f2f

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gen2brain/malgo"
)

// Voice message format: 16-bit PCM mono WAV @ 16 kHz.
// Size budget: 32 KB/sec, 2 MB/minute — fine for short voice messages sent
// over P2P without an extra codec dependency.
const (
	VoiceSampleRate uint32 = 16000
	VoiceChannels   uint32 = 1
	VoiceBitDepth          = 16
	voiceBytesPerSample    = 2 // bit-depth / 8

	// Default limits
	DefaultVoiceMaxDuration = 2 * time.Minute
	VoiceFileExt            = ".wav"
	// VoiceFilePrefix is the filename prefix used for voice messages.
	// Files matching "voicemail-N.wav" are numbered sequentially per directory.
	VoiceFilePrefix = "voicemail-"
)

// AudioDevice describes an audio endpoint for UI display / settings.
type AudioDevice struct {
	ID      string // malgo DeviceID as hex string
	Name    string
	IsInput bool
}

// -----------------------------------------------------------------------------
// Context management — malgo requires a single Context per process.
// -----------------------------------------------------------------------------

var (
	audioCtxOnce sync.Once
	audioCtx     *malgo.AllocatedContext
	audioCtxErr  error
)

func getAudioContext() (*malgo.AllocatedContext, error) {
	audioCtxOnce.Do(func() {
		audioCtx, audioCtxErr = malgo.InitContext(nil, malgo.ContextConfig{}, func(msg string) {
			// Silenced — miniaudio logs are noisy.
		})
	})
	return audioCtx, audioCtxErr
}

// ListAudioDevices enumerates input and output devices.
func ListAudioDevices() ([]AudioDevice, error) {
	ctx, err := getAudioContext()
	if err != nil {
		return nil, fmt.Errorf("init audio context: %w", err)
	}

	var out []AudioDevice

	inputs, err := ctx.Devices(malgo.Capture)
	if err != nil {
		return nil, fmt.Errorf("enumerate capture devices: %w", err)
	}
	for _, d := range inputs {
		out = append(out, AudioDevice{
			ID:      fmt.Sprintf("%x", d.ID[:]),
			Name:    d.Name(),
			IsInput: true,
		})
	}

	outputs, err := ctx.Devices(malgo.Playback)
	if err != nil {
		return nil, fmt.Errorf("enumerate playback devices: %w", err)
	}
	for _, d := range outputs {
		out = append(out, AudioDevice{
			ID:      fmt.Sprintf("%x", d.ID[:]),
			Name:    d.Name(),
			IsInput: false,
		})
	}

	return out, nil
}

// deviceIDFromHex converts our hex-string ID back to a malgo.DeviceID.
// Returns nil (= default device) if input is empty.
func deviceIDFromHex(s string) (*malgo.DeviceID, error) {
	if s == "" {
		return nil, nil
	}
	var id malgo.DeviceID
	raw, err := hexDecode(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != len(id) {
		return nil, fmt.Errorf("device id wrong length: got %d want %d", len(raw), len(id))
	}
	copy(id[:], raw)
	return &id, nil
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd hex length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		v, err := hexPair(s[i*2], s[i*2+1])
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

func hexPair(a, b byte) (byte, error) {
	hi, err := hexNibble(a)
	if err != nil {
		return 0, err
	}
	lo, err := hexNibble(b)
	if err != nil {
		return 0, err
	}
	return (hi << 4) | lo, nil
}

func hexNibble(b byte) (byte, error) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', nil
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, nil
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, nil
	}
	return 0, fmt.Errorf("bad hex byte %q", b)
}

// -----------------------------------------------------------------------------
// WAV file I/O — we write a minimal RIFF/WAVE PCM header by hand.
// Format: RIFF <size> WAVE fmt  <16> 1 <ch> <rate> <byterate> <block> <bits> data <size> <pcm...>
// -----------------------------------------------------------------------------

// WriteWAV writes raw 16-bit PCM little-endian samples as a proper WAV file.
func WriteWAV(path string, sampleRate, channels uint32, pcm []byte) error {
	dataLen := uint32(len(pcm))
	byteRate := sampleRate * channels * voiceBytesPerSample
	blockAlign := uint16(channels * voiceBytesPerSample)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := f
	// RIFF chunk
	w.WriteString("RIFF")
	binary.Write(w, binary.LittleEndian, uint32(36+dataLen)) // file size - 8
	w.WriteString("WAVE")
	// fmt subchunk
	w.WriteString("fmt ")
	binary.Write(w, binary.LittleEndian, uint32(16))                       // subchunk size
	binary.Write(w, binary.LittleEndian, uint16(1))                        // PCM format
	binary.Write(w, binary.LittleEndian, uint16(channels))                 //
	binary.Write(w, binary.LittleEndian, sampleRate)                       //
	binary.Write(w, binary.LittleEndian, byteRate)                         //
	binary.Write(w, binary.LittleEndian, blockAlign)                       //
	binary.Write(w, binary.LittleEndian, uint16(VoiceBitDepth))            //
	// data subchunk
	w.WriteString("data")
	binary.Write(w, binary.LittleEndian, dataLen)
	_, err = w.Write(pcm)
	return err
}

// WAVInfo describes the header of a parsed WAV file.
type WAVInfo struct {
	SampleRate uint32
	Channels   uint32
	BitDepth   uint16
	DataOffset int64
	DataLen    uint32
}

// ParseWAV reads the RIFF/WAVE header and returns the info needed to play it.
// Supports the common case: PCM, 16-bit, any sample rate / channels.
// Ignores unknown chunks between fmt and data.
func ParseWAV(r io.ReaderAt) (*WAVInfo, error) {
	hdr := make([]byte, 12)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if string(hdr[0:4]) != "RIFF" || string(hdr[8:12]) != "WAVE" {
		return nil, errors.New("not a RIFF/WAVE file")
	}

	info := &WAVInfo{}
	offset := int64(12)

	for {
		ch := make([]byte, 8)
		if _, err := r.ReadAt(ch, offset); err != nil {
			return nil, fmt.Errorf("read chunk header at %d: %w", offset, err)
		}
		id := string(ch[0:4])
		size := binary.LittleEndian.Uint32(ch[4:8])
		switch id {
		case "fmt ":
			body := make([]byte, size)
			if _, err := r.ReadAt(body, offset+8); err != nil {
				return nil, err
			}
			if len(body) < 16 {
				return nil, errors.New("fmt chunk truncated")
			}
			format := binary.LittleEndian.Uint16(body[0:2])
			if format != 1 {
				return nil, fmt.Errorf("only PCM (format=1) supported, got %d", format)
			}
			info.Channels = uint32(binary.LittleEndian.Uint16(body[2:4]))
			info.SampleRate = binary.LittleEndian.Uint32(body[4:8])
			info.BitDepth = binary.LittleEndian.Uint16(body[14:16])
		case "data":
			info.DataOffset = offset + 8
			info.DataLen = size
			if info.SampleRate == 0 {
				return nil, errors.New("data chunk before fmt chunk")
			}
			return info, nil
		}
		offset += 8 + int64(size)
		// pad byte for odd-sized chunks
		if size%2 == 1 {
			offset++
		}
	}
}

// -----------------------------------------------------------------------------
// Recording
// -----------------------------------------------------------------------------

// Recorder captures microphone audio to an in-memory PCM buffer until Stop().
type Recorder struct {
	device *malgo.Device
	buf    []byte
	bufMu  sync.Mutex
	cfg    malgo.DeviceConfig
}

// NewRecorder opens the given capture device (empty = default) and prepares
// to record 16-bit mono PCM at VoiceSampleRate.
func NewRecorder(inputDeviceID string) (*Recorder, error) {
	ctx, err := getAudioContext()
	if err != nil {
		return nil, err
	}

	cfg := malgo.DefaultDeviceConfig(malgo.Capture)
	cfg.Capture.Format = malgo.FormatS16
	cfg.Capture.Channels = VoiceChannels
	cfg.SampleRate = VoiceSampleRate
	cfg.Alsa.NoMMap = 1

	devID, err := deviceIDFromHex(inputDeviceID)
	if err != nil {
		return nil, fmt.Errorf("parse input device id: %w", err)
	}
	if devID != nil {
		cfg.Capture.DeviceID = devID.Pointer()
	}

	r := &Recorder{cfg: cfg}

	callbacks := malgo.DeviceCallbacks{
		Data: func(_, input []byte, _ uint32) {
			r.bufMu.Lock()
			r.buf = append(r.buf, input...)
			r.bufMu.Unlock()
		},
	}

	dev, err := malgo.InitDevice(ctx.Context, cfg, callbacks)
	if err != nil {
		return nil, fmt.Errorf("init capture device: %w", err)
	}
	r.device = dev
	return r, nil
}

// Start begins capturing audio.
func (r *Recorder) Start() error {
	return r.device.Start()
}

// Stop halts capture, releases the device, and returns the captured PCM.
func (r *Recorder) Stop() ([]byte, error) {
	if err := r.device.Stop(); err != nil {
		r.device.Uninit()
		return nil, err
	}
	r.device.Uninit()
	r.bufMu.Lock()
	out := make([]byte, len(r.buf))
	copy(out, r.buf)
	r.bufMu.Unlock()
	return out, nil
}

// Duration returns the length of audio captured so far.
func (r *Recorder) Duration() time.Duration {
	r.bufMu.Lock()
	n := len(r.buf)
	r.bufMu.Unlock()
	bytesPerSec := int(VoiceSampleRate) * int(VoiceChannels) * voiceBytesPerSample
	if bytesPerSec == 0 {
		return 0
	}
	return time.Duration(n) * time.Second / time.Duration(bytesPerSec)
}

// RecordToWAV is a convenience helper for one-shot recording: captures audio
// until either stopCh is closed, maxDuration elapses, or an error occurs,
// then writes the result to path as a WAV file.
func RecordToWAV(inputDeviceID, path string, maxDuration time.Duration, stopCh <-chan struct{}) error {
	rec, err := NewRecorder(inputDeviceID)
	if err != nil {
		return err
	}
	if err := rec.Start(); err != nil {
		rec.device.Uninit()
		return err
	}

	if maxDuration <= 0 {
		maxDuration = DefaultVoiceMaxDuration
	}
	timer := time.NewTimer(maxDuration)
	defer timer.Stop()

	select {
	case <-stopCh:
	case <-timer.C:
	}

	pcm, err := rec.Stop()
	if err != nil {
		return err
	}
	if len(pcm) == 0 {
		return errors.New("no audio captured")
	}
	return WriteWAV(path, VoiceSampleRate, VoiceChannels, pcm)
}

// -----------------------------------------------------------------------------
// Playback
// -----------------------------------------------------------------------------

// PlayWAV plays a WAV file to the given output device (empty = default),
// blocking until playback finishes or the file is drained.
func PlayWAV(outputDeviceID, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := ParseWAV(f)
	if err != nil {
		return err
	}
	if info.BitDepth != 16 {
		return fmt.Errorf("only 16-bit PCM supported, got %d-bit", info.BitDepth)
	}

	// Read full audio data into memory — keeps the callback simple.
	pcm := make([]byte, info.DataLen)
	if _, err := f.ReadAt(pcm, info.DataOffset); err != nil && err != io.EOF {
		return fmt.Errorf("read data: %w", err)
	}

	ctx, err := getAudioContext()
	if err != nil {
		return err
	}

	cfg := malgo.DefaultDeviceConfig(malgo.Playback)
	cfg.Playback.Format = malgo.FormatS16
	cfg.Playback.Channels = info.Channels
	cfg.SampleRate = info.SampleRate

	devID, err := deviceIDFromHex(outputDeviceID)
	if err != nil {
		return fmt.Errorf("parse output device id: %w", err)
	}
	if devID != nil {
		cfg.Playback.DeviceID = devID.Pointer()
	}

	done := make(chan struct{})
	var closeOnce sync.Once
	finish := func() { closeOnce.Do(func() { close(done) }) }

	pos := 0
	var posMu sync.Mutex
	callbacks := malgo.DeviceCallbacks{
		Data: func(output, _ []byte, _ uint32) {
			posMu.Lock()
			defer posMu.Unlock()
			if pos >= len(pcm) {
				// Zero-fill trailing frames then signal completion.
				for i := range output {
					output[i] = 0
				}
				finish()
				return
			}
			n := copy(output, pcm[pos:])
			pos += n
			// Zero-fill if buffer bigger than remaining.
			for i := n; i < len(output); i++ {
				output[i] = 0
			}
		},
	}

	dev, err := malgo.InitDevice(ctx.Context, cfg, callbacks)
	if err != nil {
		return fmt.Errorf("init playback device: %w", err)
	}
	defer dev.Uninit()

	if err := dev.Start(); err != nil {
		return err
	}
	defer dev.Stop()

	// Wait until all samples have been copied to the output buffer.
	<-done
	// Small drain delay so the hardware actually plays the last frames
	// before we stop the device.
	drainMs := (int(info.DataLen) * 1000) / int(info.SampleRate*info.Channels*voiceBytesPerSample)
	// Cap the drain so huge files don't block abusively if callback got ahead.
	if drainMs > 300 {
		drainMs = 300
	}
	time.Sleep(time.Duration(drainMs) * time.Millisecond)
	return nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// IsVoiceMessage reports whether a filename follows the voicemail-N.wav
// convention. Strict match (prefix + numeric index + .wav) so arbitrary WAV
// files sent through file transfer aren't auto-renamed.
func IsVoiceMessage(name string) bool {
	return parseVoicemailIndex(name) > 0
}

// parseVoicemailIndex returns N for "voicemail-N.wav" or 0 if the filename
// doesn't match. Case-insensitive on the extension.
func parseVoicemailIndex(name string) int {
	lower := strings.ToLower(name)
	if !strings.HasPrefix(lower, VoiceFilePrefix) {
		return 0
	}
	if !strings.HasSuffix(lower, VoiceFileExt) {
		return 0
	}
	numPart := lower[len(VoiceFilePrefix) : len(lower)-len(VoiceFileExt)]
	if numPart == "" {
		return 0
	}
	n, err := strconv.Atoi(numPart)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// NextVoicemailName returns the next unused "voicemail-N.wav" filename in
// the given directory (use "." for the current working directory). Scans
// existing entries, finds the maximum N in the voicemail-*.wav set, and
// returns N+1. Independent sequences on sender and receiver sides.
func NextVoicemailName(dir string) string {
	if dir == "" {
		dir = "."
	}
	maxN := 0
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if n := parseVoicemailIndex(e.Name()); n > maxN {
				maxN = n
			}
		}
	}
	return fmt.Sprintf("%s%d%s", VoiceFilePrefix, maxN+1, VoiceFileExt)
}
