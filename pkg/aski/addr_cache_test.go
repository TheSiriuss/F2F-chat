package f2f

import (
	"reflect"
	"testing"
)

// -----------------------------------------------------------------------------
// mergeAddrCache
// -----------------------------------------------------------------------------

func TestMergeAddrCache_FreshFirst(t *testing.T) {
	existing := []string{"/ip4/1.1.1.1/tcp/1", "/ip4/2.2.2.2/tcp/2"}
	fresh := []string{"/ip4/3.3.3.3/tcp/3"}
	got := mergeAddrCache(existing, fresh, 10)
	want := []string{"/ip4/3.3.3.3/tcp/3", "/ip4/1.1.1.1/tcp/1", "/ip4/2.2.2.2/tcp/2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestMergeAddrCache_Dedupe_FreshWins(t *testing.T) {
	existing := []string{"/ip4/1.1.1.1/tcp/1", "/ip4/2.2.2.2/tcp/2"}
	fresh := []string{"/ip4/1.1.1.1/tcp/1"} // same as existing[0]
	got := mergeAddrCache(existing, fresh, 10)
	want := []string{"/ip4/1.1.1.1/tcp/1", "/ip4/2.2.2.2/tcp/2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestMergeAddrCache_CapsAtLimit(t *testing.T) {
	existing := []string{"/ip4/1.1.1.1/tcp/1", "/ip4/2.2.2.2/tcp/2", "/ip4/3.3.3.3/tcp/3"}
	fresh := []string{"/ip4/4.4.4.4/tcp/4", "/ip4/5.5.5.5/tcp/5"}
	got := mergeAddrCache(existing, fresh, 3)
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(got), got)
	}
	// Fresh entries should be at the front.
	if got[0] != "/ip4/4.4.4.4/tcp/4" || got[1] != "/ip4/5.5.5.5/tcp/5" {
		t.Fatalf("fresh should be at front: %v", got)
	}
}

func TestMergeAddrCache_FreshOverlapsItself(t *testing.T) {
	fresh := []string{"/ip4/1.1.1.1/tcp/1", "/ip4/1.1.1.1/tcp/1", "/ip4/2.2.2.2/tcp/2"}
	got := mergeAddrCache(nil, fresh, 10)
	want := []string{"/ip4/1.1.1.1/tcp/1", "/ip4/2.2.2.2/tcp/2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestMergeAddrCache_EmptyFreshPreservesExisting(t *testing.T) {
	existing := []string{"/ip4/1.1.1.1/tcp/1"}
	got := mergeAddrCache(existing, nil, 10)
	if !reflect.DeepEqual(got, existing) {
		t.Fatalf("got %v, want %v", got, existing)
	}
}

func TestMergeAddrCache_BothEmpty(t *testing.T) {
	got := mergeAddrCache(nil, nil, 10)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestMergeAddrCache_LimitZero(t *testing.T) {
	got := mergeAddrCache([]string{"/a"}, []string{"/b"}, 0)
	if len(got) != 0 {
		t.Fatalf("expected empty on limit=0, got %v", got)
	}
}

// -----------------------------------------------------------------------------
// SerializableContact roundtrip with KnownAddrs
// -----------------------------------------------------------------------------

func TestContacts_KnownAddrs_Roundtrip(t *testing.T) {
	var pk [32]byte
	pk[0] = 0xAA
	in := []SerializableContact{
		{
			Nickname:   "alice",
			PeerID:     "12D3KooWAlice",
			PublicKey:  pk,
			KnownAddrs: []string{"/ip4/1.2.3.4/tcp/5678", "/ip4/10.0.0.1/udp/9999/quic-v1"},
		},
		{
			Nickname:   "bob",
			PeerID:     "12D3KooWBob",
			PublicKey:  pk,
			KnownAddrs: nil, // explicitly no cached addrs
		},
	}
	data := MarshalContacts(in)
	out, err := UnmarshalContacts(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d contacts", len(out))
	}
	if !reflect.DeepEqual(out[0].KnownAddrs, in[0].KnownAddrs) {
		t.Fatalf("alice addrs: got %v, want %v", out[0].KnownAddrs, in[0].KnownAddrs)
	}
	if len(out[1].KnownAddrs) != 0 {
		t.Fatalf("bob should have no addrs, got %v", out[1].KnownAddrs)
	}
}

func TestContacts_BackwardCompat_OldFormatNoAddrs(t *testing.T) {
	// Simulate an OLD contacts.dat (pre-KnownAddrs) by manually encoding
	// without the addr-count suffix.
	var pk [32]byte
	pk[0] = 0x11
	b := NewBuffer(nil)
	b.WriteUint32(1)
	b.WriteString("oldnick")
	b.WriteString("12D3KooWOld")
	b.WriteFixed32(pk)
	// Note: no KnownAddrs count field — old format truncated here.

	out, err := UnmarshalContacts(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(out))
	}
	if out[0].Nickname != "oldnick" {
		t.Fatalf("nickname = %q", out[0].Nickname)
	}
	if len(out[0].KnownAddrs) != 0 {
		t.Fatalf("old format should load with empty addrs, got %v", out[0].KnownAddrs)
	}
}

// -----------------------------------------------------------------------------
// slicesEqual
// -----------------------------------------------------------------------------

func TestSlicesEqual(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{}, nil, true},
		{[]string{"x"}, []string{"x"}, true},
		{[]string{"x"}, []string{"y"}, false},
		{[]string{"x", "y"}, []string{"y", "x"}, false},
		{[]string{"x"}, []string{"x", "y"}, false},
	}
	for i, c := range cases {
		if got := slicesEqual(c.a, c.b); got != c.want {
			t.Errorf("case %d: slicesEqual(%v,%v)=%v want %v", i, c.a, c.b, got, c.want)
		}
	}
}
