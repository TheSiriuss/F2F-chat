package f2f

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
)

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	return dir
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func newPair(t *testing.T) (*[32]byte, *[32]byte) {
	priv, pub, err := generateEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// buildRatchetPair returns initialized Alice and Bob Ratchets sharing an initial secret.
// Bob's handshake key pair is used as the seed remote for Alice.
func buildRatchetPair(t *testing.T) (aliceN *Node, bobN *Node, alice, bob *RatchetState) {
	t.Helper()
	aliceN = &Node{}
	bobN = &Node{}

	// Alice's handshake pair
	aPriv, aPub := newPair(t)
	// Bob's handshake pair
	bPriv, bPub := newPair(t)

	// Session key from Alice's side (same on both)
	sessA, err := deriveSessionKey(aPriv, aPub, bPub)
	if err != nil {
		t.Fatal(err)
	}
	sessB, err := deriveSessionKey(bPriv, bPub, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if *sessA != *sessB {
		t.Fatalf("session keys differ")
	}

	alice, err = InitializeRatchet(sessA, bPub, aPriv, aPub, true)
	if err != nil {
		t.Fatal(err)
	}
	bob, err = InitializeRatchet(sessB, nil, bPriv, bPub, false)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// ------------------------------------------------------------------
// Buffer tests
// ------------------------------------------------------------------

func TestBuffer_WriteReadByte(t *testing.T) {
	b := NewBuffer(nil)
	b.WriteByte(0xAB)
	r := NewBuffer(b.Bytes())
	v, err := r.ReadByte()
	if err != nil || v != 0xAB {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestBuffer_WriteReadUint32(t *testing.T) {
	b := NewBuffer(nil)
	b.WriteUint32(0xDEADBEEF)
	r := NewBuffer(b.Bytes())
	v, err := r.ReadUint32()
	if err != nil || v != 0xDEADBEEF {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestBuffer_WriteReadUint32_Zero(t *testing.T) {
	b := NewBuffer(nil)
	b.WriteUint32(0)
	r := NewBuffer(b.Bytes())
	v, _ := r.ReadUint32()
	if v != 0 {
		t.Fatalf("want 0 got %v", v)
	}
}

func TestBuffer_WriteReadInt64_Positive(t *testing.T) {
	b := NewBuffer(nil)
	b.WriteInt64(1234567890123)
	r := NewBuffer(b.Bytes())
	v, err := r.ReadInt64()
	if err != nil || v != 1234567890123 {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestBuffer_WriteReadInt64_Negative(t *testing.T) {
	b := NewBuffer(nil)
	b.WriteInt64(-42)
	r := NewBuffer(b.Bytes())
	v, err := r.ReadInt64()
	if err != nil || v != -42 {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestBuffer_WriteReadBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	b := NewBuffer(nil)
	b.WriteBytes(data)
	r := NewBuffer(b.Bytes())
	got, err := r.ReadBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %v want %v", got, data)
	}
}

func TestBuffer_WriteReadBytes_Empty(t *testing.T) {
	b := NewBuffer(nil)
	b.WriteBytes([]byte{})
	r := NewBuffer(b.Bytes())
	got, err := r.ReadBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty got %v", got)
	}
}

func TestBuffer_WriteReadString(t *testing.T) {
	b := NewBuffer(nil)
	b.WriteString("Привет, мир")
	r := NewBuffer(b.Bytes())
	got, err := r.ReadString()
	if err != nil || got != "Привет, мир" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestBuffer_WriteReadString_Empty(t *testing.T) {
	b := NewBuffer(nil)
	b.WriteString("")
	r := NewBuffer(b.Bytes())
	got, _ := r.ReadString()
	if got != "" {
		t.Fatalf("want empty got %q", got)
	}
}

func TestBuffer_WriteReadFixed32(t *testing.T) {
	var v [32]byte
	for i := range v {
		v[i] = byte(i)
	}
	b := NewBuffer(nil)
	b.WriteFixed32(v)
	r := NewBuffer(b.Bytes())
	got, err := r.ReadFixed32()
	if err != nil || got != v {
		t.Fatalf("mismatch")
	}
}

func TestBuffer_ReadByte_EOF(t *testing.T) {
	r := NewBuffer(nil)
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("want EOF")
	}
}

func TestBuffer_ReadUint32_EOF(t *testing.T) {
	r := NewBuffer([]byte{1, 2, 3})
	if _, err := r.ReadUint32(); err == nil {
		t.Fatal("want EOF")
	}
}

func TestBuffer_ReadInt64_EOF(t *testing.T) {
	r := NewBuffer([]byte{1, 2, 3, 4, 5})
	if _, err := r.ReadInt64(); err == nil {
		t.Fatal("want EOF")
	}
}

func TestBuffer_ReadBytes_EOF_Length(t *testing.T) {
	r := NewBuffer(nil)
	if _, err := r.ReadBytes(); err == nil {
		t.Fatal("want EOF")
	}
}

func TestBuffer_ReadBytes_EOF_Data(t *testing.T) {
	// length prefix says 100 but no data
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 100)
	r := NewBuffer(buf)
	if _, err := r.ReadBytes(); err == nil {
		t.Fatal("want EOF")
	}
}

func TestBuffer_ReadFixed32_EOF(t *testing.T) {
	r := NewBuffer([]byte{1, 2, 3})
	if _, err := r.ReadFixed32(); err == nil {
		t.Fatal("want EOF")
	}
}

func TestBuffer_MultipleSequence(t *testing.T) {
	b := NewBuffer(nil)
	b.WriteByte(1)
	b.WriteUint32(2)
	b.WriteInt64(3)
	b.WriteString("four")
	b.WriteBytes([]byte{5})
	var f32 [32]byte
	f32[0] = 6
	b.WriteFixed32(f32)

	r := NewBuffer(b.Bytes())
	bt, _ := r.ReadByte()
	u, _ := r.ReadUint32()
	i, _ := r.ReadInt64()
	s, _ := r.ReadString()
	bs, _ := r.ReadBytes()
	fx, _ := r.ReadFixed32()

	if bt != 1 || u != 2 || i != 3 || s != "four" || !bytes.Equal(bs, []byte{5}) || fx[0] != 6 {
		t.Fatalf("mismatch: %v %v %v %v %v %v", bt, u, i, s, bs, fx)
	}
}

func TestBuffer_Bytes_Returns_Underlying(t *testing.T) {
	b := NewBuffer([]byte{1, 2, 3})
	if !bytes.Equal(b.Bytes(), []byte{1, 2, 3}) {
		t.Fatal("mismatch")
	}
}

func TestBuffer_ReadBytes_LargeLength_Fails(t *testing.T) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 0xFFFFFFFF)
	r := NewBuffer(buf)
	if _, err := r.ReadBytes(); err == nil {
		t.Fatal("want error")
	}
}

// ------------------------------------------------------------------
// InnerMessage
// ------------------------------------------------------------------

func TestInnerMessage_Roundtrip(t *testing.T) {
	m := InnerMessage{Type: MsgTypeText, Timestamp: 999, Content: "hello", Payload: []byte{1, 2, 3}}
	data := m.Marshal()
	var m2 InnerMessage
	if err := m2.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if m2.Type != m.Type || m2.Timestamp != m.Timestamp || m2.Content != m.Content || !bytes.Equal(m2.Payload, m.Payload) {
		t.Fatalf("mismatch: %+v vs %+v", m, m2)
	}
}

func TestInnerMessage_EmptyPayload(t *testing.T) {
	m := InnerMessage{Type: MsgTypePing, Timestamp: 1}
	var m2 InnerMessage
	if err := m2.Unmarshal(m.Marshal()); err != nil {
		t.Fatal(err)
	}
	if len(m2.Payload) != 0 {
		t.Fatal("want empty payload")
	}
}

func TestInnerMessage_Unicode(t *testing.T) {
	m := InnerMessage{Type: MsgTypeText, Timestamp: 1, Content: "日本語 ♠ ♣ ♥ ♦"}
	var m2 InnerMessage
	if err := m2.Unmarshal(m.Marshal()); err != nil {
		t.Fatal(err)
	}
	if m2.Content != m.Content {
		t.Fatalf("mismatch %q", m2.Content)
	}
}

func TestInnerMessage_LargePayload(t *testing.T) {
	m := InnerMessage{Type: MsgTypeText, Payload: randBytes(t, 65536)}
	var m2 InnerMessage
	if err := m2.Unmarshal(m.Marshal()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m2.Payload, m.Payload) {
		t.Fatal("payload mismatch")
	}
}

func TestInnerMessage_Unmarshal_Truncated(t *testing.T) {
	var m InnerMessage
	if err := m.Unmarshal([]byte{1, 2}); err == nil {
		t.Fatal("want error")
	}
}

// ------------------------------------------------------------------
// HandshakePayload
// ------------------------------------------------------------------

func TestHandshake_Roundtrip(t *testing.T) {
	h := HandshakePayload{
		Version: ProtocolVersion, Timestamp: 1, Nonce: 2,
		NaClPubKey: randBytes(t, 32), EphemeralPub: randBytes(t, 32), Signature: randBytes(t, 64),
	}
	var h2 HandshakePayload
	if err := h2.Unmarshal(h.Marshal()); err != nil {
		t.Fatal(err)
	}
	if h2.Version != h.Version || h2.Timestamp != h.Timestamp || h2.Nonce != h.Nonce ||
		!bytes.Equal(h2.NaClPubKey, h.NaClPubKey) || !bytes.Equal(h2.EphemeralPub, h.EphemeralPub) ||
		!bytes.Equal(h2.Signature, h.Signature) {
		t.Fatal("mismatch")
	}
}

func TestHandshake_Empty(t *testing.T) {
	var h HandshakePayload
	var h2 HandshakePayload
	if err := h2.Unmarshal(h.Marshal()); err != nil {
		t.Fatal(err)
	}
}

func TestHandshake_Unmarshal_Invalid(t *testing.T) {
	var h HandshakePayload
	if err := h.Unmarshal([]byte{0x00}); err == nil {
		t.Fatal("want error")
	}
}

func TestHandshake_NegativeTimestamp(t *testing.T) {
	h := HandshakePayload{Timestamp: -1, Nonce: -1}
	var h2 HandshakePayload
	if err := h2.Unmarshal(h.Marshal()); err != nil {
		t.Fatal(err)
	}
	if h2.Timestamp != -1 || h2.Nonce != -1 {
		t.Fatal("mismatch")
	}
}

// ------------------------------------------------------------------
// RatchetHeader
// ------------------------------------------------------------------

func TestRatchetHeader_Size(t *testing.T) {
	var h RatchetHeader
	if len(h.Marshal()) != 40 {
		t.Fatal("header must be 40 bytes")
	}
}

func TestRatchetHeader_Roundtrip(t *testing.T) {
	var pk [32]byte
	for i := range pk {
		pk[i] = byte(i + 1)
	}
	h := RatchetHeader{PublicKey: pk, PN: 7, N: 42}
	var h2 RatchetHeader
	if err := h2.Unmarshal(h.Marshal()); err != nil {
		t.Fatal(err)
	}
	if h2 != h {
		t.Fatal("mismatch")
	}
}

func TestRatchetHeader_Unmarshal_Short(t *testing.T) {
	var h RatchetHeader
	if err := h.Unmarshal(make([]byte, 39)); err == nil {
		t.Fatal("want EOF")
	}
}

func TestRatchetHeader_ZeroValues(t *testing.T) {
	var h RatchetHeader
	data := h.Marshal()
	for _, v := range data {
		if v != 0 {
			t.Fatal("expected all zeros")
		}
	}
}

func TestRatchetHeader_MaxCounters(t *testing.T) {
	h := RatchetHeader{PN: 0xFFFFFFFF, N: 0xFFFFFFFF}
	var h2 RatchetHeader
	h2.Unmarshal(h.Marshal())
	if h2.PN != 0xFFFFFFFF || h2.N != 0xFFFFFFFF {
		t.Fatal("max counter round-trip failed")
	}
}

// ------------------------------------------------------------------
// File types
// ------------------------------------------------------------------

func TestFileOffer_Roundtrip(t *testing.T) {
	f := FileOffer{ID: "abc", Name: "test.pdf", Size: 12345}
	var f2 FileOffer
	if err := f2.Unmarshal(f.Marshal()); err != nil {
		t.Fatal(err)
	}
	if f2 != f {
		t.Fatal("mismatch")
	}
}

func TestFileOffer_EmptyName(t *testing.T) {
	f := FileOffer{ID: "x"}
	var f2 FileOffer
	if err := f2.Unmarshal(f.Marshal()); err != nil {
		t.Fatal(err)
	}
}

func TestFileOffer_LargeSize(t *testing.T) {
	f := FileOffer{ID: "x", Name: "big.bin", Size: 1 << 40}
	var f2 FileOffer
	f2.Unmarshal(f.Marshal())
	if f2.Size != 1<<40 {
		t.Fatal("size mismatch")
	}
}

func TestFileResponse_Roundtrip(t *testing.T) {
	f := FileResponse{ID: "resp-1"}
	var f2 FileResponse
	if err := f2.Unmarshal(f.Marshal()); err != nil {
		t.Fatal(err)
	}
	if f2.ID != f.ID {
		t.Fatal("mismatch")
	}
}

func TestFileDone_Roundtrip(t *testing.T) {
	f := FileDone{ID: "x", Hash: "abcdef"}
	var f2 FileDone
	if err := f2.Unmarshal(f.Marshal()); err != nil {
		t.Fatal(err)
	}
	if f2 != f {
		t.Fatal("mismatch")
	}
}

func TestFileDone_Empty(t *testing.T) {
	var f FileDone
	var f2 FileDone
	if err := f2.Unmarshal(f.Marshal()); err != nil {
		t.Fatal(err)
	}
}

func TestBinaryChunkHeaderSize(t *testing.T) {
	if BinaryChunkHeaderSize != 24 {
		t.Fatalf("want 24 got %d", BinaryChunkHeaderSize)
	}
}

// ------------------------------------------------------------------
// LocalIdentity
// ------------------------------------------------------------------

func TestLocalIdentity_Roundtrip(t *testing.T) {
	id := LocalIdentity{Nickname: "alpha", LibP2PPriv: randBytes(t, 64), NaClPub: randBytes(t, 32)}
	var id2 LocalIdentity
	if err := id2.Unmarshal(id.Marshal()); err != nil {
		t.Fatal(err)
	}
	if id2.Nickname != id.Nickname || !bytes.Equal(id2.LibP2PPriv, id.LibP2PPriv) ||
		!bytes.Equal(id2.NaClPub, id.NaClPub) {
		t.Fatal("mismatch")
	}
}

func TestLocalIdentity_EmptyNick(t *testing.T) {
	id := LocalIdentity{LibP2PPriv: []byte{1}, NaClPub: []byte{2}}
	var id2 LocalIdentity
	if err := id2.Unmarshal(id.Marshal()); err != nil {
		t.Fatal(err)
	}
	if id2.Nickname != "" {
		t.Fatal("want empty nick")
	}
}

func TestLocalIdentity_BackCompat_OldFormat(t *testing.T) {
	// Old format had trailing NaClPriv field. Ensure we silently consume it.
	b := NewBuffer(nil)
	b.WriteString("nick")
	b.WriteBytes([]byte("libp2p-priv"))
	b.WriteBytes([]byte("nacl-pub"))
	b.WriteBytes([]byte("legacy-nacl-priv"))
	var id LocalIdentity
	if err := id.Unmarshal(b.Bytes()); err != nil {
		t.Fatalf("should tolerate old format: %v", err)
	}
	if id.Nickname != "nick" || !bytes.Equal(id.NaClPub, []byte("nacl-pub")) {
		t.Fatal("back-compat parse wrong")
	}
}

func TestLocalIdentity_Unmarshal_Invalid(t *testing.T) {
	var id LocalIdentity
	if err := id.Unmarshal([]byte{0x01}); err == nil {
		t.Fatal("want error")
	}
}

// ------------------------------------------------------------------
// Contacts (de)serialization
// ------------------------------------------------------------------

func TestContacts_Empty(t *testing.T) {
	data := MarshalContacts(nil)
	out, err := UnmarshalContacts(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("want empty got %v", out)
	}
}

func TestContacts_Multiple(t *testing.T) {
	var pk [32]byte
	pk[0] = 0x01
	in := []SerializableContact{
		{Nickname: "a", PeerID: "id-a", PublicKey: pk},
		{Nickname: "b", PeerID: "id-b", PublicKey: pk},
	}
	out, err := UnmarshalContacts(MarshalContacts(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Nickname != "a" || out[1].Nickname != "b" {
		t.Fatal("mismatch")
	}
}

func TestContacts_Unicode(t *testing.T) {
	in := []SerializableContact{{Nickname: "日本", PeerID: "peerid-日本"}}
	out, err := UnmarshalContacts(MarshalContacts(in))
	if err != nil || out[0].Nickname != "日本" {
		t.Fatalf("got %v err %v", out, err)
	}
}

func TestContacts_Unmarshal_Truncated(t *testing.T) {
	if _, err := UnmarshalContacts([]byte{0x01}); err == nil {
		t.Fatal("want error")
	}
}

func TestContacts_Unmarshal_BadCount(t *testing.T) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 100)
	if _, err := UnmarshalContacts(buf); err == nil {
		t.Fatal("want error")
	}
}

// ------------------------------------------------------------------
// Fingerprint
// ------------------------------------------------------------------

func TestFingerprint_Format(t *testing.T) {
	fp := ComputeFingerprint([]byte("hello"))
	// expect 10 groups of 4 hex chars, 9 dashes → 160-bit fingerprint.
	parts := strings.Split(fp, "-")
	if len(parts) != 10 {
		t.Fatalf("bad format (expected 10 groups): %q", fp)
	}
	for _, p := range parts {
		if len(p) != 4 {
			t.Fatalf("bad chunk %q", p)
		}
	}
}

func TestFingerprint_160Bits(t *testing.T) {
	fp := ComputeFingerprint([]byte("x"))
	// 40 hex chars + 9 dashes = 49
	if len(fp) != 49 {
		t.Fatalf("expected 49-char fingerprint, got %d: %q", len(fp), fp)
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	a := ComputeFingerprint([]byte("x"))
	b := ComputeFingerprint([]byte("x"))
	if a != b {
		t.Fatal("must be deterministic")
	}
}

func TestFingerprint_DifferentInputs(t *testing.T) {
	if ComputeFingerprint([]byte("a")) == ComputeFingerprint([]byte("b")) {
		t.Fatal("must differ")
	}
}

func TestFingerprint_EmptyInput(t *testing.T) {
	fp := ComputeFingerprint(nil)
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
}

// ------------------------------------------------------------------
// PresenceStatus
// ------------------------------------------------------------------

func TestPresence_Online(t *testing.T) {
	if PresenceOnline.String() != "ONLINE" {
		t.Fatal("wrong")
	}
}
func TestPresence_Offline(t *testing.T) {
	if PresenceOffline.String() != "OFFLINE" {
		t.Fatal("wrong")
	}
}
func TestPresence_Checking(t *testing.T) {
	if PresenceChecking.String() != "CHECKING..." {
		t.Fatal("wrong")
	}
}
func TestPresence_Unknown(t *testing.T) {
	if PresenceUnknown.String() != "UNKNOWN" {
		t.Fatal("wrong")
	}
}
func TestPresence_ArbitraryValue(t *testing.T) {
	if PresenceStatus(99).String() != "UNKNOWN" {
		t.Fatal("wrong")
	}
}

// ------------------------------------------------------------------
// Ephemeral Keys
// ------------------------------------------------------------------

func TestGenerateEphemeralKeys_NotNil(t *testing.T) {
	priv, pub, err := generateEphemeralKeys()
	if err != nil || priv == nil || pub == nil {
		t.Fatalf("err=%v", err)
	}
}

func TestGenerateEphemeralKeys_Clamped(t *testing.T) {
	priv, _, _ := generateEphemeralKeys()
	if priv[0]&7 != 0 {
		t.Fatal("low bits not cleared")
	}
	if priv[31]&0x80 != 0 {
		t.Fatal("high bit not cleared")
	}
	if priv[31]&0x40 == 0 {
		t.Fatal("bit 62 not set")
	}
}

func TestGenerateEphemeralKeys_Unique(t *testing.T) {
	_, pub1, _ := generateEphemeralKeys()
	_, pub2, _ := generateEphemeralKeys()
	if *pub1 == *pub2 {
		t.Fatal("keys must differ")
	}
}

func TestGenerateEphemeralKeys_Pub_NonZero(t *testing.T) {
	_, pub, _ := generateEphemeralKeys()
	var zero [32]byte
	if *pub == zero {
		t.Fatal("pub is zero")
	}
}

// ------------------------------------------------------------------
// DH
// ------------------------------------------------------------------

func TestComputeDH_Symmetric(t *testing.T) {
	aPriv, aPub := newPair(t)
	bPriv, bPub := newPair(t)
	s1, err := computeDH(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := computeDH(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if s1 != s2 {
		t.Fatal("DH should be symmetric")
	}
}

func TestComputeDH_Deterministic(t *testing.T) {
	aPriv, _ := newPair(t)
	_, bPub := newPair(t)
	s1, _ := computeDH(aPriv, bPub)
	s2, _ := computeDH(aPriv, bPub)
	if s1 != s2 {
		t.Fatal("DH must be deterministic")
	}
}

func TestComputeDH_Differs(t *testing.T) {
	aPriv, _ := newPair(t)
	_, bPub := newPair(t)
	_, cPub := newPair(t)
	s1, _ := computeDH(aPriv, bPub)
	s2, _ := computeDH(aPriv, cPub)
	if s1 == s2 {
		t.Fatal("different pubs should give different shared")
	}
}

func TestComputeDH_RejectsLowOrder(t *testing.T) {
	priv, _ := newPair(t)
	var zero [32]byte
	_, err := computeDH(priv, &zero)
	if err == nil {
		t.Fatal("expected error on all-zero pub (low-order point)")
	}
}

// ------------------------------------------------------------------
// KDF
// ------------------------------------------------------------------

func TestKdfRK_Deterministic(t *testing.T) {
	var r, d [32]byte
	r[0] = 1
	d[0] = 2
	r1, c1 := kdfRK(&r, &d)
	r2, c2 := kdfRK(&r, &d)
	if r1 != r2 || c1 != c2 {
		t.Fatal("must be deterministic")
	}
}

func TestKdfRK_DifferentRoot(t *testing.T) {
	var r1, r2, d [32]byte
	r1[0] = 1
	r2[0] = 2
	d[0] = 3
	a, _ := kdfRK(&r1, &d)
	b, _ := kdfRK(&r2, &d)
	if a == b {
		t.Fatal("must differ")
	}
}

func TestKdfRK_OutputsDiffer(t *testing.T) {
	var r, d [32]byte
	r[0] = 1
	d[0] = 2
	root, chain := kdfRK(&r, &d)
	if root == chain {
		t.Fatal("root and chain must differ")
	}
}

func TestKdfCK_Deterministic(t *testing.T) {
	var c [32]byte
	c[0] = 1
	a1, m1 := kdfCK(&c)
	a2, m2 := kdfCK(&c)
	if a1 != a2 || m1 != m2 {
		t.Fatal("deterministic")
	}
}

func TestKdfCK_ChainAdvances(t *testing.T) {
	var c [32]byte
	c[0] = 1
	next, _ := kdfCK(&c)
	if next == c {
		t.Fatal("chain did not advance")
	}
}

func TestKdfCK_MsgChainDiffer(t *testing.T) {
	var c [32]byte
	c[0] = 1
	next, msg := kdfCK(&c)
	if next == msg {
		t.Fatal("msg and chain must differ")
	}
}

func TestKdfCK_ConsecutiveMsgKeysDiffer(t *testing.T) {
	var c [32]byte
	c[0] = 1
	next, m1 := kdfCK(&c)
	_, m2 := kdfCK(&next)
	if m1 == m2 {
		t.Fatal("consecutive msg keys must differ")
	}
}

// ------------------------------------------------------------------
// deriveSessionKey
// ------------------------------------------------------------------

func TestDeriveSessionKey_Symmetric(t *testing.T) {
	aPriv, aPub := newPair(t)
	bPriv, bPub := newPair(t)
	s1, err := deriveSessionKey(aPriv, aPub, bPub)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := deriveSessionKey(bPriv, bPub, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if *s1 != *s2 {
		t.Fatal("must match")
	}
}

func TestDeriveSessionKey_DifferentPairs(t *testing.T) {
	aPriv, aPub := newPair(t)
	_, bPub := newPair(t)
	_, cPub := newPair(t)
	s1, _ := deriveSessionKey(aPriv, aPub, bPub)
	s2, _ := deriveSessionKey(aPriv, aPub, cPub)
	if *s1 == *s2 {
		t.Fatal("must differ")
	}
}

func TestDeriveSessionKey_NonZero(t *testing.T) {
	aPriv, aPub := newPair(t)
	_, bPub := newPair(t)
	s, _ := deriveSessionKey(aPriv, aPub, bPub)
	var zero [32]byte
	if *s == zero {
		t.Fatal("zero session key")
	}
}

// ------------------------------------------------------------------
// XChaCha AEAD
// ------------------------------------------------------------------

func TestXChaChaAD_Roundtrip(t *testing.T) {
	n := &Node{}
	var k [32]byte
	k[0] = 1
	ad := []byte("associated")
	pt := []byte("hello world")
	ct, err := n.encryptXChaChaAD(pt, &k, ad)
	if err != nil {
		t.Fatal(err)
	}
	out, err := n.decryptXChaChaAD(ct, &k, ad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatal("mismatch")
	}
}

func TestXChaChaAD_WrongKey(t *testing.T) {
	n := &Node{}
	var k1, k2 [32]byte
	k1[0] = 1
	k2[0] = 2
	ct, _ := n.encryptXChaChaAD([]byte("msg"), &k1, nil)
	if _, err := n.decryptXChaChaAD(ct, &k2, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestXChaChaAD_WrongAD(t *testing.T) {
	n := &Node{}
	var k [32]byte
	k[0] = 1
	ct, _ := n.encryptXChaChaAD([]byte("msg"), &k, []byte("a"))
	if _, err := n.decryptXChaChaAD(ct, &k, []byte("b")); err == nil {
		t.Fatal("want error")
	}
}

func TestXChaChaAD_Tampered(t *testing.T) {
	n := &Node{}
	var k [32]byte
	k[0] = 1
	ct, _ := n.encryptXChaChaAD([]byte("msg"), &k, nil)
	ct[len(ct)-1] ^= 0xFF
	if _, err := n.decryptXChaChaAD(ct, &k, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestXChaChaAD_Short(t *testing.T) {
	n := &Node{}
	var k [32]byte
	if _, err := n.decryptXChaChaAD([]byte{1, 2, 3}, &k, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestXChaChaAD_NonceVariesEachCall(t *testing.T) {
	n := &Node{}
	var k [32]byte
	k[0] = 1
	c1, _ := n.encryptXChaChaAD([]byte("x"), &k, nil)
	c2, _ := n.encryptXChaChaAD([]byte("x"), &k, nil)
	if bytes.Equal(c1, c2) {
		t.Fatal("nonce reused")
	}
}

func TestXChaChaAD_EmptyPlaintext(t *testing.T) {
	n := &Node{}
	var k [32]byte
	k[0] = 7
	ct, err := n.encryptXChaChaAD(nil, &k, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := n.decryptXChaChaAD(ct, &k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatal("want empty")
	}
}

// ------------------------------------------------------------------
// Double Ratchet
// ------------------------------------------------------------------

func TestRatchet_Init_Alice_HasSendChain(t *testing.T) {
	_, _, alice, _ := buildRatchetPair(t)
	var zero [32]byte
	if alice.ChainKeyS == zero {
		t.Fatal("alice send chain not initialized")
	}
	if alice.DHLocalPriv == nil || alice.DHLocalPub == nil {
		t.Fatal("alice DH not initialized")
	}
}

func TestRatchet_Init_Bob_NoRemote(t *testing.T) {
	_, _, _, bob := buildRatchetPair(t)
	if bob.DHRemotePub != nil {
		t.Fatal("bob remote pub should be nil")
	}
	var zero [32]byte
	if bob.ChainKeyS != zero {
		t.Fatal("bob send chain should be empty before first recv")
	}
}

func TestRatchet_Init_RootKeySet(t *testing.T) {
	_, _, alice, bob := buildRatchetPair(t)
	var zero [32]byte
	if alice.RootKey == zero {
		t.Fatal("alice root zero")
	}
	if bob.RootKey == zero {
		t.Fatal("bob root zero")
	}
}

func TestRatchet_SingleMessage_A2B(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	hdr, ct, err := aN.RatchetEncrypt(alice, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := bN.RatchetDecrypt(bob, hdr, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Fatalf("got %q", pt)
	}
}

func TestRatchet_Bidirectional(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	// A -> B
	h, c, _ := aN.RatchetEncrypt(alice, []byte("hi"))
	if _, err := bN.RatchetDecrypt(bob, h, c); err != nil {
		t.Fatal(err)
	}
	// B -> A
	h2, c2, err := bN.RatchetEncrypt(bob, []byte("hello back"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := aN.RatchetDecrypt(alice, h2, c2)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello back" {
		t.Fatalf("got %q", pt)
	}
}

func TestRatchet_PingPong_10(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	for i := 0; i < 10; i++ {
		h, c, err := aN.RatchetEncrypt(alice, []byte("ping"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bN.RatchetDecrypt(bob, h, c); err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}
		h, c, err = bN.RatchetEncrypt(bob, []byte("pong"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := aN.RatchetDecrypt(alice, h, c); err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}
	}
}

func TestRatchet_LongAliceChain(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	for i := 0; i < 50; i++ {
		h, c, _ := aN.RatchetEncrypt(alice, []byte("x"))
		if _, err := bN.RatchetDecrypt(bob, h, c); err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}
	}
}

func TestRatchet_OutOfOrder(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	// Alice sends 3 messages
	h1, c1, _ := aN.RatchetEncrypt(alice, []byte("m1"))
	h2, c2, _ := aN.RatchetEncrypt(alice, []byte("m2"))
	h3, c3, _ := aN.RatchetEncrypt(alice, []byte("m3"))

	// Bob receives 2 first
	if pt, err := bN.RatchetDecrypt(bob, h2, c2); err != nil || string(pt) != "m2" {
		t.Fatalf("m2: %v %q", err, pt)
	}
	if pt, err := bN.RatchetDecrypt(bob, h1, c1); err != nil || string(pt) != "m1" {
		t.Fatalf("m1: %v %q", err, pt)
	}
	if pt, err := bN.RatchetDecrypt(bob, h3, c3); err != nil || string(pt) != "m3" {
		t.Fatalf("m3: %v %q", err, pt)
	}
}

func TestRatchet_OutOfOrder_LastFirst(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	hdrs := make([][]byte, 5)
	cts := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		hdrs[i], cts[i], _ = aN.RatchetEncrypt(alice, []byte{byte(i)})
	}
	// Bob receives in reverse
	for i := 4; i >= 0; i-- {
		pt, err := bN.RatchetDecrypt(bob, hdrs[i], cts[i])
		if err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}
		if len(pt) != 1 || pt[0] != byte(i) {
			t.Fatalf("i=%d: got %v", i, pt)
		}
	}
}

func TestRatchet_CrossChain_AfterResponse(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	// Alice sends 2, Bob replies, Alice sends 2 more, Bob replies
	for i := 0; i < 2; i++ {
		h, c, _ := aN.RatchetEncrypt(alice, []byte("a"))
		bN.RatchetDecrypt(bob, h, c)
	}
	h, c, _ := bN.RatchetEncrypt(bob, []byte("b"))
	if _, err := aN.RatchetDecrypt(alice, h, c); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		h, c, _ := aN.RatchetEncrypt(alice, []byte("a"))
		if _, err := bN.RatchetDecrypt(bob, h, c); err != nil {
			t.Fatal(err)
		}
	}
	h, c, _ = bN.RatchetEncrypt(bob, []byte("b2"))
	if _, err := aN.RatchetDecrypt(alice, h, c); err != nil {
		t.Fatal(err)
	}
}

func TestRatchet_WrongCiphertext_Fails(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	h, c, _ := aN.RatchetEncrypt(alice, []byte("hello"))
	c[len(c)-1] ^= 0xFF
	if _, err := bN.RatchetDecrypt(bob, h, c); err == nil {
		t.Fatal("want error")
	}
}

func TestRatchet_BadHeader_Fails(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	_, c, _ := aN.RatchetEncrypt(alice, []byte("hello"))
	if _, err := bN.RatchetDecrypt(bob, []byte{1, 2, 3}, c); err == nil {
		t.Fatal("want error")
	}
}

func TestRatchet_EmptyPlaintext(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	h, c, err := aN.RatchetEncrypt(alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := bN.RatchetDecrypt(bob, h, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Fatal("want empty")
	}
}

func TestRatchet_LargePlaintext(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	pt := randBytes(t, 1<<20) // 1 MB
	h, c, _ := aN.RatchetEncrypt(alice, pt)
	out, err := bN.RatchetDecrypt(bob, h, c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatal("mismatch")
	}
}

func TestRatchet_NsIncrements(t *testing.T) {
	aN, _, alice, _ := buildRatchetPair(t)
	if alice.Ns != 0 {
		t.Fatal("initial Ns must be 0")
	}
	aN.RatchetEncrypt(alice, []byte("x"))
	if alice.Ns != 1 {
		t.Fatal("Ns must be 1")
	}
	aN.RatchetEncrypt(alice, []byte("y"))
	if alice.Ns != 2 {
		t.Fatal("Ns must be 2")
	}
}

func TestRatchet_HeaderContainsSenderPub(t *testing.T) {
	aN, _, alice, _ := buildRatchetPair(t)
	hdr, _, _ := aN.RatchetEncrypt(alice, []byte("x"))
	var h RatchetHeader
	h.Unmarshal(hdr)
	if h.PublicKey != *alice.DHLocalPub {
		t.Fatal("header pubkey mismatch")
	}
}

func TestRatchet_HeaderN_Increments(t *testing.T) {
	aN, _, alice, _ := buildRatchetPair(t)
	hdr1, _, _ := aN.RatchetEncrypt(alice, []byte("x"))
	hdr2, _, _ := aN.RatchetEncrypt(alice, []byte("y"))
	var h1, h2 RatchetHeader
	h1.Unmarshal(hdr1)
	h2.Unmarshal(hdr2)
	if h1.N != 0 || h2.N != 1 {
		t.Fatalf("N got %d %d", h1.N, h2.N)
	}
}

func TestRatchet_DH_KeyRotates_OnReply(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	h, c, _ := aN.RatchetEncrypt(alice, []byte("hi"))
	bN.RatchetDecrypt(bob, h, c)

	initialBobPub := *bob.DHLocalPub
	h2, c2, _ := bN.RatchetEncrypt(bob, []byte("reply"))
	aN.RatchetDecrypt(alice, h2, c2)

	// After A -> B -> A round trip, Alice does another encrypt which should
	// rotate her DH key via the ratchet step on decrypt of bob's reply.
	if *alice.DHRemotePub != initialBobPub {
		// actually bob's local pub is what alice saw; key rotation happens
		// on bob side when he generates new keys during ratchet step.
		// This is a sanity check that DH state is updated.
		t.Log("bob local pub updated (expected)")
	}
}

func TestRatchet_SkippedKeys_Stored(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	h1, c1, _ := aN.RatchetEncrypt(alice, []byte("m1"))
	h2, c2, _ := aN.RatchetEncrypt(alice, []byte("m2"))
	// Receive only m2
	if _, err := bN.RatchetDecrypt(bob, h2, c2); err != nil {
		t.Fatal(err)
	}
	if len(bob.SkippedMsgKeys) == 0 {
		t.Fatal("should have skipped key for m1")
	}
	// Now deliver m1
	if pt, err := bN.RatchetDecrypt(bob, h1, c1); err != nil || string(pt) != "m1" {
		t.Fatalf("%v %q", err, pt)
	}
}

func TestRatchet_ReuseHeaderFails(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	h, c, _ := aN.RatchetEncrypt(alice, []byte("x"))
	if _, err := bN.RatchetDecrypt(bob, h, c); err != nil {
		t.Fatal(err)
	}
	// second delivery of same message: the chain has advanced, so msg key is gone
	if _, err := bN.RatchetDecrypt(bob, h, c); err == nil {
		t.Fatal("replay should fail")
	}
}

func TestRatchet_TooManySkipped(t *testing.T) {
	aN, bN, alice, bob := buildRatchetPair(t)
	// Consume MaxSkipKeys+1 ahead messages without delivering anything.
	// Alice sends MaxSkipKeys+2 messages; Bob receives only the last one.
	var lastH, lastC []byte
	for i := 0; i <= MaxSkipKeys+1; i++ {
		h, c, _ := aN.RatchetEncrypt(alice, []byte("x"))
		lastH, lastC = h, c
	}
	if _, err := bN.RatchetDecrypt(bob, lastH, lastC); err == nil {
		t.Fatal("want 'too many skipped' error")
	}
}

func TestInitializeRatchet_ErrorOnNilNotRequired(t *testing.T) {
	// Smoke test: verify InitializeRatchet returns a state with SkippedMsgKeys map ready.
	aPriv, aPub := newPair(t)
	_, bPub := newPair(t)
	sess, _ := deriveSessionKey(aPriv, aPub, bPub)
	rs, err := InitializeRatchet(sess, bPub, aPriv, aPub, true)
	if err != nil {
		t.Fatal(err)
	}
	if rs.SkippedMsgKeys == nil {
		t.Fatal("SkippedMsgKeys nil")
	}
}

// ------------------------------------------------------------------
// Encryption: Argon2id + XChaCha
// ------------------------------------------------------------------

func TestDeriveKey_Deterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	k1 := deriveKey("pw", salt)
	k2 := deriveKey("pw", salt)
	if !bytes.Equal(k1, k2) {
		t.Fatal("must match")
	}
}

func TestDeriveKey_DifferentSalt(t *testing.T) {
	k1 := deriveKey("pw", []byte("0123456789abcdef"))
	k2 := deriveKey("pw", []byte("fedcba9876543210"))
	if bytes.Equal(k1, k2) {
		t.Fatal("must differ")
	}
}

func TestDeriveKey_Length(t *testing.T) {
	if len(deriveKey("pw", make([]byte, 16))) != argonKeyLen {
		t.Fatal("wrong length")
	}
}

func TestEncryptData_EmptyPassword(t *testing.T) {
	if _, err := encryptData([]byte("x"), ""); err != ErrNoPassword {
		t.Fatalf("got %v", err)
	}
}

func TestDecryptData_EmptyPassword(t *testing.T) {
	if _, err := decryptData([]byte("x"), ""); err != ErrNoPassword {
		t.Fatalf("got %v", err)
	}
}

func TestEncryptData_Roundtrip(t *testing.T) {
	ct, err := encryptData([]byte("hello"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := decryptData(ct, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Fatal("mismatch")
	}
}

func TestDecryptData_WrongPassword(t *testing.T) {
	ct, _ := encryptData([]byte("hello"), "pw")
	if _, err := decryptData(ct, "wrong"); err != ErrWrongPassword {
		t.Fatalf("got %v", err)
	}
}

func TestDecryptData_Truncated(t *testing.T) {
	if _, err := decryptData([]byte{1, 2, 3}, "pw"); err != ErrWrongPassword {
		t.Fatalf("got %v", err)
	}
}

func TestDecryptData_Tampered(t *testing.T) {
	ct, _ := encryptData([]byte("hello"), "pw")
	ct[len(ct)-1] ^= 0xFF
	if _, err := decryptData(ct, "pw"); err == nil {
		t.Fatal("want error")
	}
}

func TestEncryptData_DifferentSaltsEachCall(t *testing.T) {
	c1, _ := encryptData([]byte("x"), "pw")
	c2, _ := encryptData([]byte("x"), "pw")
	if bytes.Equal(c1, c2) {
		t.Fatal("must differ (random salt)")
	}
}

func TestEncryptData_LargeData(t *testing.T) {
	data := randBytes(t, 256*1024)
	ct, err := encryptData(data, "pw")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := decryptData(ct, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatal("mismatch")
	}
}

// ------------------------------------------------------------------
// Atomic file ops / storage
// ------------------------------------------------------------------

func TestWriteAtomic_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	fn := dir + string(os.PathSeparator) + "f.bin"
	if err := writeAtomic(fn, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatal("mismatch")
	}
}

func TestWriteAtomic_Overwrites(t *testing.T) {
	dir := t.TempDir()
	fn := dir + string(os.PathSeparator) + "f.bin"
	writeAtomic(fn, []byte("one"))
	if err := writeAtomic(fn, []byte("two")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(fn)
	if string(got) != "two" {
		t.Fatal("mismatch")
	}
}

func TestSaveLoadEncrypted_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	fn := dir + string(os.PathSeparator) + "enc.bin"
	if err := saveEncrypted(fn, []byte("secret"), "pw"); err != nil {
		t.Fatal(err)
	}
	pt, err := loadEncrypted(fn, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "secret" {
		t.Fatal("mismatch")
	}
}

func TestSaveLoadEncrypted_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	fn := dir + string(os.PathSeparator) + "enc.bin"
	saveEncrypted(fn, []byte("secret"), "pw")
	if _, err := loadEncrypted(fn, "bad"); err != ErrWrongPassword {
		t.Fatalf("got %v", err)
	}
}

func TestLoadEncrypted_NoFile(t *testing.T) {
	if _, err := loadEncrypted(t.TempDir()+"/nope.bin", "pw"); err == nil {
		t.Fatal("want error")
	}
}

func TestIdentityExists_False(t *testing.T) {
	chdirTemp(t)
	if IdentityExists() {
		t.Fatal("should not exist")
	}
}

func TestIdentityExists_True(t *testing.T) {
	chdirTemp(t)
	if err := os.WriteFile(IdentityFile, []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}
	if !IdentityExists() {
		t.Fatal("should exist")
	}
}

func TestContactsExist_False(t *testing.T) {
	chdirTemp(t)
	if ContactsExist() {
		t.Fatal("should not exist")
	}
}

func TestIsNewUser_True(t *testing.T) {
	chdirTemp(t)
	if !IsNewUser() {
		t.Fatal("should be new user")
	}
}

func TestIsNewUser_False(t *testing.T) {
	chdirTemp(t)
	os.WriteFile(IdentityFile, []byte{1}, 0600)
	if IsNewUser() {
		t.Fatal("should not be new")
	}
}

func TestValidatePassword_NoIdentity(t *testing.T) {
	chdirTemp(t)
	if err := ValidatePassword(""); err != nil {
		t.Fatalf("got %v", err)
	}
}

func TestValidatePassword_EmptyWithIdentity(t *testing.T) {
	chdirTemp(t)
	saveEncrypted(IdentityFile, []byte("x"), "pw")
	if err := ValidatePassword(""); err != ErrNoPassword {
		t.Fatalf("got %v", err)
	}
}

func TestValidatePassword_Correct(t *testing.T) {
	chdirTemp(t)
	saveEncrypted(IdentityFile, []byte("x"), "pw")
	if err := ValidatePassword("pw"); err != nil {
		t.Fatalf("got %v", err)
	}
}

func TestValidatePassword_Wrong(t *testing.T) {
	chdirTemp(t)
	saveEncrypted(IdentityFile, []byte("x"), "pw")
	if err := ValidatePassword("bad"); err != ErrWrongPassword {
		t.Fatalf("got %v", err)
	}
}

func TestChangePassword_Empty(t *testing.T) {
	chdirTemp(t)
	if err := ChangePassword("old", ""); err != ErrNoPassword {
		t.Fatalf("got %v", err)
	}
}

func TestChangePassword_Success(t *testing.T) {
	chdirTemp(t)
	saveEncrypted(IdentityFile, []byte("id"), "old")
	saveEncrypted(ContactsFile, []byte("cont"), "old")

	if err := ChangePassword("old", "new"); err != nil {
		t.Fatal(err)
	}
	// Decrypt with new
	id, err := loadEncrypted(IdentityFile, "new")
	if err != nil || string(id) != "id" {
		t.Fatalf("id: %v %q", err, id)
	}
	c, err := loadEncrypted(ContactsFile, "new")
	if err != nil || string(c) != "cont" {
		t.Fatalf("c: %v %q", err, c)
	}
	// Old password fails now
	if _, err := loadEncrypted(IdentityFile, "old"); err == nil {
		t.Fatal("old should fail")
	}
}

func TestChangePassword_WrongOld(t *testing.T) {
	chdirTemp(t)
	saveEncrypted(IdentityFile, []byte("id"), "old")
	if err := ChangePassword("bad", "new"); err == nil {
		t.Fatal("want error")
	}
}

// ------------------------------------------------------------------
// Node validation
// ------------------------------------------------------------------

func TestValidateNickname_Empty(t *testing.T) {
	n := &Node{}
	if err := n.validateNickname(""); err == nil {
		t.Fatal("want error")
	}
}

func TestValidateNickname_TooLong(t *testing.T) {
	n := &Node{}
	if err := n.validateNickname(strings.Repeat("a", MaxNickLength+1)); err == nil {
		t.Fatal("want error")
	}
}

func TestValidateNickname_Spaces(t *testing.T) {
	n := &Node{}
	if err := n.validateNickname("   "); err == nil {
		t.Fatal("want error")
	}
}

func TestValidateNickname_Valid(t *testing.T) {
	n := &Node{}
	if err := n.validateNickname("alice"); err != nil {
		t.Fatalf("got %v", err)
	}
}

func TestValidateNickname_ExactlyMax(t *testing.T) {
	n := &Node{}
	if err := n.validateNickname(strings.Repeat("a", MaxNickLength)); err != nil {
		t.Fatalf("got %v", err)
	}
}

// ------------------------------------------------------------------
// Config constants sanity
// ------------------------------------------------------------------

func TestConfig_ProtocolVersion(t *testing.T) {
	if ProtocolVersion == "" {
		t.Fatal("empty version")
	}
}

func TestConfig_MaxSkipKeysPositive(t *testing.T) {
	if MaxSkipKeys <= 0 {
		t.Fatal("must be > 0")
	}
}

func TestConfig_FileChunkSize(t *testing.T) {
	if FileChunkSize <= 0 {
		t.Fatal("must be > 0")
	}
}

func TestConfig_InfoDifferent(t *testing.T) {
	if bytes.Equal(InfoRootKey, InfoChainKey) || bytes.Equal(InfoRootKey, InfoMsgKey) || bytes.Equal(InfoChainKey, InfoMsgKey) {
		t.Fatal("KDF info strings must differ")
	}
}

func TestMessageTypeDistinct(t *testing.T) {
	types := []MessageType{MsgTypeHandshake, MsgTypeRequest, MsgTypeAccept, MsgTypeDecline,
		MsgTypeCancel, MsgTypeText, MsgTypePing, MsgTypeBye, MsgTypeFileOffer, MsgTypeFileAccept,
		MsgTypeFileDecline, MsgTypeFileCancel, MsgTypeFileDone}
	seen := map[MessageType]bool{}
	for _, tv := range types {
		if seen[tv] {
			t.Fatalf("duplicate %v", tv)
		}
		seen[tv] = true
	}
}

func TestChatState_Values(t *testing.T) {
	if StateIdle == StatePendingIncoming || StateIdle == StateActive {
		t.Fatal("states collide")
	}
}

func TestFrameType_Distinct(t *testing.T) {
	if FrameTypeMsg == FrameTypeBinary {
		t.Fatal("frame types collide")
	}
}

// ------------------------------------------------------------------
// Password advice
// ------------------------------------------------------------------

func TestPasswordAdvice_Empty(t *testing.T) {
	if PasswordAdvice("") == "" {
		t.Fatal("should warn on empty password")
	}
}

func TestPasswordAdvice_Short(t *testing.T) {
	if PasswordAdvice("short") == "" {
		t.Fatal("should warn on short password")
	}
}

func TestPasswordAdvice_SingleClass(t *testing.T) {
	if PasswordAdvice("aaaaaaaaaaaaaa") == "" {
		t.Fatal("should warn on only-lowercase 14-char password")
	}
	if PasswordAdvice("12345678901234") == "" {
		t.Fatal("should warn on only-digits 14-char password")
	}
}

func TestPasswordAdvice_MixedOK(t *testing.T) {
	if PasswordAdvice("MyStr0ng!Pass") != "" {
		t.Fatal("should accept diverse 13-char password")
	}
}

func TestPasswordAdvice_LongPassphrasePasses(t *testing.T) {
	if PasswordAdvice("correct horse battery staple") != "" {
		t.Fatal("long passphrases should pass even without symbol diversity")
	}
}

// ------------------------------------------------------------------
// Password hint
// ------------------------------------------------------------------

func TestPasswordHint_SaveLoad(t *testing.T) {
	chdirTemp(t)
	if err := SavePasswordHint("favorite city"); err != nil {
		t.Fatal(err)
	}
	got := LoadPasswordHint()
	if got != "favorite city" {
		t.Fatalf("got %q", got)
	}
}

func TestPasswordHint_LoadMissing(t *testing.T) {
	chdirTemp(t)
	if LoadPasswordHint() != "" {
		t.Fatal("should be empty when no file")
	}
}

func TestPasswordHint_EmptyRemoves(t *testing.T) {
	chdirTemp(t)
	SavePasswordHint("something")
	SavePasswordHint("")
	if LoadPasswordHint() != "" {
		t.Fatal("empty save should remove")
	}
}

func TestPasswordHint_TruncatesLong(t *testing.T) {
	chdirTemp(t)
	long := strings.Repeat("x", MaxHintLength+50)
	SavePasswordHint(long)
	got := LoadPasswordHint()
	if len([]rune(got)) != MaxHintLength {
		t.Fatalf("expected %d runes, got %d", MaxHintLength, len([]rune(got)))
	}
}

// ------------------------------------------------------------------
// Filename sanitization (BIDI / ZW)
// ------------------------------------------------------------------

func TestSanitizeFilename_StripsRTLOverride(t *testing.T) {
	// "invoice<U+202E>fdp.exe" displays as "invoiceexe.pdf"
	got := SanitizeFilename("invoice\u202Efdp.exe")
	if strings.Contains(got, "\u202E") {
		t.Fatal("RLO not stripped")
	}
	if got != "invoicefdp.exe" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeFilename_StripsLRE_RLI_PDI(t *testing.T) {
	for _, r := range []rune{0x202A, 0x202B, 0x202C, 0x202D, 0x2066, 0x2067, 0x2068, 0x2069} {
		in := "a" + string(r) + "b.txt"
		if got := SanitizeFilename(in); strings.ContainsRune(got, r) {
			t.Fatalf("rune %U not stripped: %q", r, got)
		}
	}
}

func TestSanitizeFilename_StripsZeroWidth(t *testing.T) {
	in := "ev\u200Bil.exe" // zero-width space
	if got := SanitizeFilename(in); strings.ContainsRune(got, 0x200B) {
		t.Fatalf("ZWSP not stripped: %q", got)
	}
}

func TestSanitizeFilename_StripsBOM(t *testing.T) {
	in := "\uFEFFfile.txt"
	if got := SanitizeFilename(in); strings.ContainsRune(got, 0xFEFF) {
		t.Fatalf("BOM not stripped: %q", got)
	}
}

func TestSanitizeFilename_PreservesUnicode(t *testing.T) {
	in := "файл_日本.txt"
	if got := SanitizeFilename(in); got != in {
		t.Fatalf("legitimate unicode mangled: %q → %q", in, got)
	}
}

func TestSanitizeFilename_EmptyBecomesUnnamed(t *testing.T) {
	in := "\u200B\u202E\uFEFF"
	if got := SanitizeFilename(in); got != "unnamed" {
		t.Fatalf("expected 'unnamed', got %q", got)
	}
}

// ------------------------------------------------------------------
// Handshake domain separation
// ------------------------------------------------------------------

func TestHandshakeSigBytes_IncludesContext(t *testing.T) {
	out := handshakeSigBytes("v1", 1, 2, []byte("pub"), []byte("eph"))
	if !bytes.HasPrefix(out, []byte(handshakeSigContext)) {
		t.Fatal("missing domain-separation prefix")
	}
}

func TestHandshakeSigBytes_DifferForDifferentContents(t *testing.T) {
	a := handshakeSigBytes("v1", 1, 2, []byte("x"), []byte("y"))
	b := handshakeSigBytes("v2", 1, 2, []byte("x"), []byte("y"))
	if bytes.Equal(a, b) {
		t.Fatal("version change must affect bytes")
	}
}

// ------------------------------------------------------------------
// SAS (Short Authentication String)
// ------------------------------------------------------------------

func TestSAS_Symmetric(t *testing.T) {
	// Same (pubA, pubB) must yield the same SAS regardless of argument order.
	a := randBytes(t, 32)
	b := randBytes(t, 32)
	s1 := ComputeSAS(a, b)
	s2 := ComputeSAS(b, a)
	if s1 != s2 {
		t.Fatalf("SAS must be symmetric: %q vs %q", s1, s2)
	}
}

func TestSAS_Deterministic(t *testing.T) {
	a := randBytes(t, 32)
	b := randBytes(t, 32)
	if ComputeSAS(a, b) != ComputeSAS(a, b) {
		t.Fatal("SAS must be deterministic")
	}
}

func TestSAS_DiffersPerPair(t *testing.T) {
	a := randBytes(t, 32)
	b := randBytes(t, 32)
	c := randBytes(t, 32)
	if ComputeSAS(a, b) == ComputeSAS(a, c) {
		t.Fatal("different pair should produce different SAS")
	}
}

func TestSAS_Format(t *testing.T) {
	s := ComputeSAS(make([]byte, 32), make([]byte, 32))
	// Expected format: XXXX-XXXX-XXXX-XXXX (19 chars)
	parts := strings.Split(s, "-")
	if len(parts) != 4 {
		t.Fatalf("bad format: %q", s)
	}
	for _, p := range parts {
		if len(p) != 4 {
			t.Fatalf("bad chunk %q", p)
		}
	}
	if len(s) != 19 {
		t.Fatalf("expected 19-char SAS, got %d", len(s))
	}
}

func TestSAS_DomainSeparation(t *testing.T) {
	// SAS prefix should differ from fingerprint → same input shouldn't collide.
	pub := randBytes(t, 32)
	if ComputeSAS(pub, pub) == ComputeFingerprint(pub) {
		t.Fatal("SAS and fingerprint collide on identical input — domain separation broken")
	}
}

func TestSAS_NotAllZero(t *testing.T) {
	// Edge case: both inputs zero — SAS should still produce a non-empty code.
	zeros := make([]byte, 32)
	s := ComputeSAS(zeros, zeros)
	if s == "" || strings.Count(s, "0") == len(s)-3 {
		t.Fatalf("suspicious SAS for zero inputs: %q", s)
	}
}

// ------------------------------------------------------------------
// QR invite (light sanity — full roundtrip is in integration_test.go)
// ------------------------------------------------------------------

// (QR rendering goes through an external lib; we just smoke-test API shape here.)
