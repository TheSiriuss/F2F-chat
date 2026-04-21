package f2f

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

// -----------------------------------------------------------------------------
// Opus encoder / decoder roundtrip
// -----------------------------------------------------------------------------

func TestOpus_Encode_Decode_Roundtrip(t *testing.T) {
	enc, err := newOpusEncoder(CallSampleRate, CallChannels)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	if err := enc.SetBitrate(CallOpusBitrate); err != nil {
		t.Fatal(err)
	}

	dec, err := newOpusDecoder(CallSampleRate, CallChannels)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	// Generate a simple ramp signal for one frame.
	pcm := make([]int16, CallSamplesPerFrame)
	for i := range pcm {
		pcm[i] = int16((i * 100) % 32767)
	}

	out := make([]byte, 4000)
	n, err := enc.Encode(pcm, out)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || n > len(out) {
		t.Fatalf("bad encoded length %d", n)
	}

	decoded := make([]int16, CallSamplesPerFrame)
	got, err := dec.Decode(out[:n], decoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != CallSamplesPerFrame {
		t.Fatalf("decoded samples %d, want %d", got, CallSamplesPerFrame)
	}
	// We don't check byte-exactness — Opus is lossy. Just that decode succeeded
	// and yielded the expected sample count, plus reasonable energy.
	var energy int64
	for _, s := range decoded {
		energy += int64(s) * int64(s)
	}
	if energy == 0 {
		t.Fatal("decoded frame is all zero — encode/decode roundtrip broken")
	}
}

func TestOpus_Encoder_QualityTuning(t *testing.T) {
	enc, err := newOpusEncoder(CallSampleRate, CallChannels)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	if err := enc.SetBitrate(32000); err != nil {
		t.Fatal(err)
	}
	if err := enc.SetComplexity(10); err != nil {
		t.Fatal(err)
	}
	if err := enc.SetInbandFEC(true); err != nil {
		t.Fatal(err)
	}
	if err := enc.SetPacketLossPercentage(5); err != nil {
		t.Fatal(err)
	}
	if err := enc.SetSignalVoice(); err != nil {
		t.Fatal(err)
	}
	// Encode after tuning — make sure options didn't break anything.
	pcm := make([]int16, CallSamplesPerFrame)
	out := make([]byte, 4000)
	if _, err := enc.Encode(pcm, out); err != nil {
		t.Fatal(err)
	}
}

func TestOpus_Encoder_SetBitrate_Variants(t *testing.T) {
	enc, err := newOpusEncoder(CallSampleRate, CallChannels)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	for _, br := range []int{8000, 16000, 24000, 32000, 64000} {
		if err := enc.SetBitrate(br); err != nil {
			t.Errorf("bitrate %d: %v", br, err)
		}
	}
}

func TestOpus_Decoder_PLC(t *testing.T) {
	// Passing nil data to Decode asks Opus for packet-loss concealment —
	// it should succeed and fill pcm with a synthesized frame.
	dec, err := newOpusDecoder(CallSampleRate, CallChannels)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	pcm := make([]int16, CallSamplesPerFrame)
	n, err := dec.Decode(nil, pcm)
	if err != nil {
		t.Fatal(err)
	}
	if n != CallSamplesPerFrame {
		t.Fatalf("PLC returned %d samples, want %d", n, CallSamplesPerFrame)
	}
}

func TestOpus_Encode_EmptyPCM(t *testing.T) {
	enc, err := newOpusEncoder(CallSampleRate, CallChannels)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	if _, err := enc.Encode(nil, make([]byte, 100)); err == nil {
		t.Fatal("expected error on empty pcm")
	}
}

// -----------------------------------------------------------------------------
// Key derivation — both sides compute matching key pairs
// -----------------------------------------------------------------------------

func TestDeriveCallKeys_Symmetric(t *testing.T) {
	// Simulate two peer IDs (raw bytes, not real libp2p IDs).
	a := peer.ID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := peer.ID("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	var shared [32]byte
	for i := range shared {
		shared[i] = byte(i + 1)
	}

	aSend, aRecv := deriveCallKeys(shared, a, b)
	bSend, bRecv := deriveCallKeys(shared, b, a)

	// A's sendKey must equal B's recvKey, and vice versa.
	if aSend != bRecv {
		t.Fatal("aSend != bRecv — directional keys misaligned")
	}
	if aRecv != bSend {
		t.Fatal("aRecv != bSend — directional keys misaligned")
	}
	if aSend == aRecv {
		t.Fatal("send and recv keys must differ")
	}
}

func TestDeriveCallKeys_DifferentSharedSecrets(t *testing.T) {
	a := peer.ID("alice")
	b := peer.ID("bob")
	var s1, s2 [32]byte
	s1[0] = 1
	s2[0] = 2
	k1, _ := deriveCallKeys(s1, a, b)
	k2, _ := deriveCallKeys(s2, a, b)
	if k1 == k2 {
		t.Fatal("different shared secrets must yield different keys")
	}
}

// -----------------------------------------------------------------------------
// Call frame codec (length-prefixed + counter)
// -----------------------------------------------------------------------------

func TestCallFrame_Roundtrip(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
	var buf bytes.Buffer
	if err := writeCallFrame(&buf, 42, payload); err != nil {
		t.Fatal(err)
	}
	ctr, got, err := readCallFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if ctr != 42 {
		t.Fatalf("ctr = %d, want 42", ctr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %x vs %x", got, payload)
	}
}

func TestCallFrame_RejectsOversized(t *testing.T) {
	// Length field says 5000 bytes — exceeds the 4096 guard.
	var buf bytes.Buffer
	// Manually craft the 4-byte length header.
	buf.Write([]byte{0, 0, 0x13, 0x88}) // 5000 in BE
	buf.Write(make([]byte, 5000))
	if _, _, err := readCallFrame(&buf); err == nil {
		t.Fatal("expected error for oversized frame")
	}
}

func TestCallFrame_RejectsTooSmall(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0x01}) // total=1, less than counter size (8)
	buf.Write([]byte{0})
	if _, _, err := readCallFrame(&buf); err == nil {
		t.Fatal("expected error for undersized frame")
	}
}

func TestCallFrame_TruncatedHeader(t *testing.T) {
	if _, _, err := readCallFrame(bytes.NewReader([]byte{0, 0})); err == nil {
		t.Fatal("expected EOF on truncated header")
	}
}

func TestMakeCallNonce_Deterministic(t *testing.T) {
	n1 := makeCallNonce(42)
	n2 := makeCallNonce(42)
	if n1 != n2 {
		t.Fatal("same counter must yield same nonce")
	}
	n3 := makeCallNonce(43)
	if n1 == n3 {
		t.Fatal("different counters must yield different nonces")
	}
}

func TestMakeCallNonce_Size(t *testing.T) {
	n := makeCallNonce(1)
	if len(n) != 24 {
		t.Fatalf("nonce len %d, want 24", len(n))
	}
}

// -----------------------------------------------------------------------------
// Message types are registered and distinct
// -----------------------------------------------------------------------------

func TestCallMessageTypes_Distinct(t *testing.T) {
	seen := map[MessageType]bool{}
	for _, m := range []MessageType{MsgTypeCallOffer, MsgTypeCallAccept, MsgTypeCallDecline, MsgTypeCallEnd} {
		if seen[m] {
			t.Fatalf("duplicate message type %d", m)
		}
		seen[m] = true
	}
}

func TestCallMessageTypes_DontClashWithFiles(t *testing.T) {
	for _, m := range []MessageType{MsgTypeCallOffer, MsgTypeCallAccept, MsgTypeCallDecline, MsgTypeCallEnd} {
		for _, f := range []MessageType{MsgTypeFileOffer, MsgTypeFileAccept, MsgTypeFileDecline, MsgTypeFileCancel, MsgTypeFileDone} {
			if m == f {
				t.Fatalf("call msg %d clashes with file msg %d", m, f)
			}
		}
	}
}
