package f2f

import (
	"github.com/libp2p/go-libp2p/core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
)

// parseMultiaddr wraps multiaddr.NewMultiaddr with the error returned
// directly — saves a block of three-line boilerplate at every caller.
func parseMultiaddr(s string) (ma.Multiaddr, error) {
	return ma.NewMultiaddr(s)
}

// rememberSuccessfulAddrs is called after a handshake completes. It walks
// every current libp2p connection to the peer and saves each RemoteMultiaddr
// into the contact's persistent KnownAddrs list. Duplicates are moved to
// front (LRU-ish), oldest entries are evicted when exceeding
// MaxKnownAddrsPerContact. Returns true if anything changed — caller can
// then trigger SaveContacts().
func (n *Node) rememberSuccessfulAddrs(c *Contact) (changed bool) {
	conns := n.host.Network().ConnsToPeer(c.PeerID)
	if len(conns) == 0 {
		return false
	}

	fresh := make([]string, 0, len(conns))
	for _, conn := range conns {
		a := conn.RemoteMultiaddr().String()
		if a != "" {
			fresh = append(fresh, a)
		}
	}
	if len(fresh) == 0 {
		return false
	}

	c.mu.Lock()
	merged := mergeAddrCache(c.KnownAddrs, fresh, MaxKnownAddrsPerContact)
	if !slicesEqual(merged, c.KnownAddrs) {
		c.KnownAddrs = merged
		changed = true
	}
	c.mu.Unlock()

	// Also refresh peerstore TTL so these addrs survive the current session.
	for _, s := range fresh {
		if m, err := parseMultiaddr(s); err == nil {
			n.host.Peerstore().AddAddr(c.PeerID, m, peerstore.AddressTTL)
		}
	}
	return changed
}

// mergeAddrCache combines `existing` and `fresh` multiaddr strings.
//   - duplicates from `fresh` are moved to the front (most-recent wins)
//   - result is capped at `limit` entries, oldest dropped
//   - relative order of `existing` is preserved for non-duplicated entries
func mergeAddrCache(existing, fresh []string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	seen := make(map[string]bool, len(fresh))
	out := make([]string, 0, limit)

	// Fresh goes first, deduped among itself.
	for _, a := range fresh {
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
		if len(out) == limit {
			return out
		}
	}

	// Then existing in order, skipping any duplicates already added.
	for _, a := range existing {
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
		if len(out) == limit {
			return out
		}
	}
	return out
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
