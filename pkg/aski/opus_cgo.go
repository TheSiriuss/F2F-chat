// Package-local thin Opus CGO wrapper.
//
// We avoid depending on gopkg.in/hraban/opus.v2 because it uses a
// `#cgo pkg-config: opus` directive, which requires pkg-config on the build
// machine — a frequent headache on Windows. Here we call libopus directly
// via CGO, with explicit paths for MinGW on Windows and the system include
// path elsewhere.
//
// Only the subset of the API that the voice-call implementation needs:
//   - encoder create / destroy / encode
//   - decoder create / destroy / decode
//   - set-bitrate helper
package f2f

/*
#cgo windows CFLAGS: -IC:/mingw/mingw64/include
// Force static linking of libopus so the final exe doesn't require
// libopus-0.dll alongside it. The -Bstatic / -Bdynamic pair scopes the
// static mode to just -lopus, keeping system libs (m, kernel) dynamic.
#cgo windows LDFLAGS: -LC:/mingw/mingw64/lib -Wl,-Bstatic -lopus -Wl,-Bdynamic
#cgo !windows pkg-config: opus

#include <opus/opus.h>
#include <stdlib.h>

// Wrappers around the variadic opus_encoder_ctl that CGO can call cleanly.
static int f2f_opus_set_bitrate(OpusEncoder *enc, int bitrate) {
    return opus_encoder_ctl(enc, OPUS_SET_BITRATE(bitrate));
}
static int f2f_opus_set_complexity(OpusEncoder *enc, int c) {
    return opus_encoder_ctl(enc, OPUS_SET_COMPLEXITY(c));
}
static int f2f_opus_set_inband_fec(OpusEncoder *enc, int on) {
    return opus_encoder_ctl(enc, OPUS_SET_INBAND_FEC(on));
}
static int f2f_opus_set_packet_loss_perc(OpusEncoder *enc, int perc) {
    return opus_encoder_ctl(enc, OPUS_SET_PACKET_LOSS_PERC(perc));
}
static int f2f_opus_set_signal_voice(OpusEncoder *enc) {
    return opus_encoder_ctl(enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// -----------------------------------------------------------------------------
// Encoder
// -----------------------------------------------------------------------------

type opusEncoder struct {
	enc *C.OpusEncoder
}

func newOpusEncoder(sampleRate, channels int) (*opusEncoder, error) {
	var errCode C.int
	enc := C.opus_encoder_create(
		C.opus_int32(sampleRate),
		C.int(channels),
		C.OPUS_APPLICATION_VOIP,
		&errCode,
	)
	if errCode != C.OPUS_OK || enc == nil {
		return nil, fmt.Errorf("opus_encoder_create failed (code %d)", int(errCode))
	}
	e := &opusEncoder{enc: enc}
	// Safety net: if callers forget Close(), the GC will eventually reclaim
	// the C-side state instead of leaking it for the lifetime of the process.
	runtime.SetFinalizer(e, func(x *opusEncoder) {
		if x.enc != nil {
			C.opus_encoder_destroy(x.enc)
			x.enc = nil
		}
	})
	return e, nil
}

func (e *opusEncoder) SetBitrate(bitsPerSec int) error {
	ret := C.f2f_opus_set_bitrate(e.enc, C.int(bitsPerSec))
	if ret != C.OPUS_OK {
		return fmt.Errorf("opus_encoder_ctl(set_bitrate) failed (%d)", int(ret))
	}
	return nil
}

// SetComplexity sets the encoder complexity 0..10. 10 = best quality.
// On a modern CPU the cost is negligible for one voice call.
func (e *opusEncoder) SetComplexity(c int) error {
	ret := C.f2f_opus_set_complexity(e.enc, C.int(c))
	if ret != C.OPUS_OK {
		return fmt.Errorf("opus_encoder_ctl(set_complexity) failed (%d)", int(ret))
	}
	return nil
}

// SetInbandFEC toggles forward error correction. When enabled and the
// decoder requests FEC on a subsequent decode call, Opus can recover a
// lost frame using redundant data embedded in the next one.
func (e *opusEncoder) SetInbandFEC(on bool) error {
	v := 0
	if on {
		v = 1
	}
	ret := C.f2f_opus_set_inband_fec(e.enc, C.int(v))
	if ret != C.OPUS_OK {
		return fmt.Errorf("opus_encoder_ctl(set_inband_fec) failed (%d)", int(ret))
	}
	return nil
}

// SetPacketLossPercentage hints the encoder about expected packet loss,
// biasing FEC / redundancy decisions.
func (e *opusEncoder) SetPacketLossPercentage(perc int) error {
	ret := C.f2f_opus_set_packet_loss_perc(e.enc, C.int(perc))
	if ret != C.OPUS_OK {
		return fmt.Errorf("opus_encoder_ctl(set_packet_loss_perc) failed (%d)", int(ret))
	}
	return nil
}

// SetSignalVoice tells Opus we're encoding voice (vs music). It already
// infers this from AppVoIP, but the explicit hint helps at lower bitrates.
func (e *opusEncoder) SetSignalVoice() error {
	ret := C.f2f_opus_set_signal_voice(e.enc)
	if ret != C.OPUS_OK {
		return fmt.Errorf("opus_encoder_ctl(set_signal) failed (%d)", int(ret))
	}
	return nil
}

// Encode compresses one frame of PCM samples (mono int16, native-endian).
// Returns the number of bytes written to output.
func (e *opusEncoder) Encode(pcm []int16, output []byte) (int, error) {
	if len(pcm) == 0 {
		return 0, errors.New("opus encode: empty pcm")
	}
	if len(output) == 0 {
		return 0, errors.New("opus encode: empty output buffer")
	}
	n := C.opus_encode(
		e.enc,
		(*C.opus_int16)(unsafe.Pointer(&pcm[0])),
		C.int(len(pcm)),
		(*C.uchar)(unsafe.Pointer(&output[0])),
		C.opus_int32(len(output)),
	)
	if n < 0 {
		return 0, fmt.Errorf("opus_encode failed (%d)", int(n))
	}
	return int(n), nil
}

func (e *opusEncoder) Close() {
	if e.enc != nil {
		C.opus_encoder_destroy(e.enc)
		e.enc = nil
	}
	runtime.SetFinalizer(e, nil)
}

// -----------------------------------------------------------------------------
// Decoder
// -----------------------------------------------------------------------------

type opusDecoder struct {
	dec *C.OpusDecoder
}

func newOpusDecoder(sampleRate, channels int) (*opusDecoder, error) {
	var errCode C.int
	dec := C.opus_decoder_create(
		C.opus_int32(sampleRate),
		C.int(channels),
		&errCode,
	)
	if errCode != C.OPUS_OK || dec == nil {
		return nil, fmt.Errorf("opus_decoder_create failed (code %d)", int(errCode))
	}
	d := &opusDecoder{dec: dec}
	runtime.SetFinalizer(d, func(x *opusDecoder) {
		if x.dec != nil {
			C.opus_decoder_destroy(x.dec)
			x.dec = nil
		}
	})
	return d, nil
}

// Decode expands one Opus packet into pcm. Returns the number of samples
// per channel (so for mono, total samples; for stereo, half of len(pcm)).
// Pass nil / empty data to request Packet Loss Concealment — Opus fills the
// frame with smoothed silence based on the previous frame's spectrum.
func (d *opusDecoder) Decode(data []byte, pcm []int16) (int, error) {
	if len(pcm) == 0 {
		return 0, errors.New("opus decode: empty pcm buffer")
	}
	var dataPtr *C.uchar
	var dataLen C.opus_int32
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
		dataLen = C.opus_int32(len(data))
	}
	n := C.opus_decode(
		d.dec,
		dataPtr,
		dataLen,
		(*C.opus_int16)(unsafe.Pointer(&pcm[0])),
		C.int(len(pcm)),
		C.int(0), // decode_fec = 0
	)
	if n < 0 {
		return 0, fmt.Errorf("opus_decode failed (%d)", int(n))
	}
	return int(n), nil
}

func (d *opusDecoder) Close() {
	if d.dec != nil {
		C.opus_decoder_destroy(d.dec)
		d.dec = nil
	}
	runtime.SetFinalizer(d, nil)
}
