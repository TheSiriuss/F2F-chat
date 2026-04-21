package f2f

import (
	"os"
	"path/filepath"
	"testing"
)

// -----------------------------------------------------------------------------
// #1 Key rotation — advanceCallKey / keyForCounter
// -----------------------------------------------------------------------------

func TestAdvanceCallKey_DifferentFromInput(t *testing.T) {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	next := advanceCallKey(k)
	if next == k {
		t.Fatal("advance produced the same key — KDF broken")
	}
}

func TestAdvanceCallKey_Deterministic(t *testing.T) {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	a := advanceCallKey(k)
	b := advanceCallKey(k)
	if a != b {
		t.Fatal("advance must be deterministic for same input")
	}
}

func TestAdvanceCallKey_OneWay(t *testing.T) {
	// Advance 10 times. Check that no two generations accidentally coincide.
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	seen := map[[32]byte]bool{k: true}
	cur := k
	for i := 0; i < 10; i++ {
		cur = advanceCallKey(cur)
		if seen[cur] {
			t.Fatalf("key collision at generation %d — broken", i)
		}
		seen[cur] = true
	}
}

func TestKeyForCounter_AdvancesGenerations(t *testing.T) {
	var base [32]byte
	for i := range base {
		base[i] = byte(i + 1)
	}
	orig := base
	var gen uint64

	// Counter below first rotation boundary → no change.
	k1 := keyForCounter(&base, &gen, CallKeyRotateInterval-1)
	if k1 != orig || gen != 0 {
		t.Fatal("no rotation expected below threshold")
	}

	// Counter crosses first boundary → gen becomes 1.
	k2 := keyForCounter(&base, &gen, CallKeyRotateInterval)
	if k2 == orig {
		t.Fatal("expected rotated key")
	}
	if gen != 1 {
		t.Fatalf("gen = %d, want 1", gen)
	}

	// Counter at generation 3 directly → should advance twice more.
	k3 := keyForCounter(&base, &gen, 3*CallKeyRotateInterval)
	if gen != 3 {
		t.Fatalf("gen = %d, want 3", gen)
	}
	if k3 == k2 {
		t.Fatal("key should have advanced again")
	}
}

func TestKeyForCounter_OldKeyZeroed(t *testing.T) {
	// The implementation promises to zero the old key material before
	// replacing it. Since we use *[32]byte in-place, test that after
	// rotation the buffer contains the NEW key, not the OLD one.
	var key [32]byte
	for i := range key {
		key[i] = 0xAB
	}
	orig := key
	var gen uint64
	_ = keyForCounter(&key, &gen, CallKeyRotateInterval)
	if key == orig {
		t.Fatal("key array should have been mutated to new generation")
	}
}

// -----------------------------------------------------------------------------
// #2 ffmpeg TOFU hash verification
// -----------------------------------------------------------------------------

func TestHashFile_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}
	h, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Known SHA-256 of "hello world".
	want := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if h != want {
		t.Fatalf("hash = %q, want %q", h, want)
	}
}

func TestVerifyCachedFFmpeg_MatchingHash(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ffmpeg.exe")
	os.WriteFile(exe, []byte("pretend ffmpeg"), 0644)
	if err := writeFFmpegHash(exe, dir); err != nil {
		t.Fatal(err)
	}
	if !verifyCachedFFmpeg(exe, dir) {
		t.Fatal("just-written hash should verify")
	}
}

func TestVerifyCachedFFmpeg_TamperedExe(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ffmpeg.exe")
	os.WriteFile(exe, []byte("original ffmpeg content"), 0644)
	if err := writeFFmpegHash(exe, dir); err != nil {
		t.Fatal(err)
	}
	// Simulate tampering: replace exe with different content.
	os.WriteFile(exe, []byte("malicious content"), 0644)
	if verifyCachedFFmpeg(exe, dir) {
		t.Fatal("tampered exe should FAIL verification")
	}
}

func TestVerifyCachedFFmpeg_NoSidecar(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ffmpeg.exe")
	os.WriteFile(exe, []byte("content"), 0644)
	// No sidecar written.
	if verifyCachedFFmpeg(exe, dir) {
		t.Fatal("missing sidecar should FAIL verification")
	}
}

func TestVerifyCachedFFmpeg_CorruptSidecar(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ffmpeg.exe")
	os.WriteFile(exe, []byte("content"), 0644)
	os.WriteFile(filepath.Join(dir, ffmpegHashFile), []byte("not a valid hex hash"), 0644)
	if verifyCachedFFmpeg(exe, dir) {
		t.Fatal("corrupt sidecar should FAIL")
	}
}

// -----------------------------------------------------------------------------
// #3 / #4 — CallIncoming timeout + offer rate-limit integration tested in
// the main integration suite where possible. Here we just test the config
// constants exist and are sane.
// -----------------------------------------------------------------------------

func TestCallSecurityConstants(t *testing.T) {
	if CallOfferTimeout <= 0 {
		t.Fatal("CallOfferTimeout must be > 0")
	}
	if CallOfferMinInterval <= 0 {
		t.Fatal("CallOfferMinInterval must be > 0")
	}
	if CallKeyRotateInterval <= 0 {
		t.Fatal("CallKeyRotateInterval must be > 0")
	}
	// Sanity: rotate shouldn't be so frequent it eats CPU, nor so rare
	// it defeats the purpose.
	if CallKeyRotateInterval < 10 || CallKeyRotateInterval > 10000 {
		t.Fatalf("CallKeyRotateInterval = %d is out of sane range", CallKeyRotateInterval)
	}
}

// -----------------------------------------------------------------------------
// #5 Opus finalizer — just verify Close is idempotent and the finalizer
// path doesn't panic.
// -----------------------------------------------------------------------------

func TestOpusEncoder_DoubleClose(t *testing.T) {
	e, err := newOpusEncoder(CallSampleRate, CallChannels)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	e.Close() // second close must be a no-op, not a crash
}

func TestOpusDecoder_DoubleClose(t *testing.T) {
	d, err := newOpusDecoder(CallSampleRate, CallChannels)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	d.Close()
}
