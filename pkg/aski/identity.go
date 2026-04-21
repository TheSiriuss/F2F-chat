package f2f

import (
	"context"
	"crypto/rand"
	"io"
	"time"

	"net"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	manet "github.com/multiformats/go-multiaddr/net"
	ma "github.com/multiformats/go-multiaddr"
)

// globalOnlyAddrsFactory filters the host's advertised address set down
// to globally-routable addresses only. Stripped: loopback (127.0.0.1,
// ::1), link-local (169.254.x.x, fe80::/10), private LAN (10/8,
// 172.16/12, 192.168/16, fc00::/7). Circuit/relay addrs are kept so
// unreachable peers can still be contacted via relay as a last resort.
//
// Result: two instances of F2F on the same machine / same LAN never
// find a direct path to each other — all P2P traffic must go through
// the public internet, matching the "global-only connectivity" design.
func globalOnlyAddrsFactory(addrs []ma.Multiaddr) []ma.Multiaddr {
	out := make([]ma.Multiaddr, 0, len(addrs))
	for _, a := range addrs {
		// Circuit addrs are relays — keep them.
		if _, err := a.ValueForProtocol(ma.P_CIRCUIT); err == nil {
			out = append(out, a)
			continue
		}
		if !isGlobalAddr(a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func isGlobalAddr(a ma.Multiaddr) bool {
	ipStr, err := a.ValueForProtocol(ma.P_IP4)
	if err != nil {
		ipStr, err = a.ValueForProtocol(ma.P_IP6)
		if err != nil {
			// No IP — e.g. DNS multiaddr. Let libp2p decide.
			return manet.IsPublicAddr(a)
		}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	return true
}

func loadOrInitIdentity(password string) (crypto.PrivKey, *[32]byte, string, error) {
	if IdentityExists() {
		if password == "" {
			return nil, nil, "", ErrNoPassword
		}

		rawBytes, err := loadEncrypted(IdentityFile, password)
		if err != nil {
			return nil, nil, "", err
		}

		var id LocalIdentity
		if err := id.Unmarshal(rawBytes); err != nil {
			return nil, nil, "", err
		}

		privKey, err := crypto.UnmarshalPrivateKey(id.LibP2PPriv)
		if err != nil {
			return nil, nil, "", err
		}

		var naclPub [32]byte
		copy(naclPub[:], id.NaClPub)

		return privKey, &naclPub, id.Nickname, nil
	}

	if password == "" {
		return nil, nil, "", ErrNoPassword
	}

	privKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, nil, "", err
	}

	privBytes, err := crypto.MarshalPrivateKey(privKey)
	if err != nil {
		return nil, nil, "", err
	}

	// Long-term identity tag: 32 random bytes exchanged via .addfriend.
	// Not used for signing or DH — acts purely as an opaque invariant
	// bound to (nickname, peerID) in contacts. The cryptographic identity
	// binding is provided by the libp2p Ed25519 key (peerID).
	var pub [32]byte
	if _, err := io.ReadFull(rand.Reader, pub[:]); err != nil {
		return nil, nil, "", err
	}

	newId := LocalIdentity{
		LibP2PPriv: privBytes,
		NaClPub:    pub[:],
	}

	if err := saveEncrypted(IdentityFile, newId.Marshal(), password); err != nil {
		return nil, nil, "", err
	}

	return privKey, &pub, "", nil
}

func (n *Node) saveIdentity() error {
	n.mu.RLock()
	password := n.password
	nickname := n.nickname
	n.mu.RUnlock()

	if password == "" {
		return ErrNoPassword
	}

	privBytes, err := crypto.MarshalPrivateKey(n.host.Peerstore().PrivKey(n.host.ID()))
	if err != nil {
		return err
	}

	id := LocalIdentity{
		Nickname:   nickname,
		LibP2PPriv: privBytes,
		NaClPub:    n.naclPublic[:],
	}

	return saveEncrypted(IdentityFile, id.Marshal(), password)
}

func NewNode(ctx context.Context, listener UIListener, password string) (*Node, error) {
	if password == "" {
		return nil, ErrNoPassword
	}

	privKey, naclPub, savedNick, err := loadOrInitIdentity(password)
	if err != nil {
		return nil, err
	}

	var bootstrapPeers []peer.AddrInfo
	for _, addr := range dht.DefaultBootstrapPeers {
		ai, err := peer.AddrInfoFromP2pAddr(addr)
		if err == nil && ai != nil {
			bootstrapPeers = append(bootstrapPeers, *ai)
		}
	}

	// Custom connection manager with high watermarks and a long grace
	// period. libp2p default (160/192, 1 min) can prune our contact
	// connections when DHT/autorelay activity spikes above the high
	// water — leading to a sudden "direct conn dropped → fall back to
	// relay" visible as "online → via relay" a minute after startup.
	// We also explicitly Protect() each contact in libp2pKeepAliveLoop
	// so they can never be evicted regardless of count.
	cmgr, err := connmgr.NewConnManager(
		400, 500, // low/high watermark — plenty of headroom for DHT churn
		connmgr.WithGracePeriod(3*time.Minute),
	)
	if err != nil {
		return nil, err
	}

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/0",
			"/ip4/0.0.0.0/udp/0/quic-v1",
		),
		// Global-only ADVERTISING: strip loopback, LAN, link-local from
		// anything we push through identify. Peers on the wire never
		// see "connect to me at 127.0.0.1 / 192.168.x.x / ...".
		libp2p.AddrsFactory(globalOnlyAddrsFactory),
		libp2p.ConnectionManager(cmgr),
		libp2p.EnableRelay(),
		libp2p.EnableAutoRelay(autorelay.WithStaticRelays(bootstrapPeers)),
		libp2p.EnableNATService(),
		libp2p.EnableHolePunching(),
	)
	if err != nil {
		return nil, err
	}

	kadDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeAuto), dht.BootstrapPeers(bootstrapPeers...))
	if err != nil {
		return nil, err
	}
	kadDHT.Bootstrap(ctx)

	ctxNode, cancel := context.WithCancel(ctx)
	node := &Node{
		host:         h,
		dht:          kadDHT,
		discovery:    routing.NewRoutingDiscovery(kadDHT),
		nickname:     savedNick,
		password:     password,
		naclPublic:   *naclPub,
		contacts:     make(map[peer.ID]*Contact),
		nickMap:      make(map[string]peer.ID),
		ctx:          ctxNode,
		cancel:       cancel,
		presenceChan: make(chan peer.ID, 100),
		listener:     listener,
	}

	h.SetStreamHandler(ProtocolID, node.handleStream)
	h.SetStreamHandler(AudioProtocolID, node.handleAudioStream)
	h.SetStreamHandler(VideoProtocolID, node.handleVideoStream)

	node.wg.Add(5)
	go node.keepAliveLoop()
	go node.backgroundAdvertise()
	go node.presenceLoop()
	go node.presenceWorkerPool()
	go node.libp2pKeepAliveLoop()

	return node, nil
}

func (n *Node) LoadContacts() error {
	if !ContactsExist() {
		return nil
	}

	n.mu.RLock()
	password := n.password
	n.mu.RUnlock()

	if password == "" {
		return ErrNoPassword
	}

	rawBytes, err := loadEncrypted(ContactsFile, password)
	if err != nil {
		return err
	}

	saved, err := UnmarshalContacts(rawBytes)
	if err != nil {
		return err
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	for _, c := range saved {
		pid, err := peer.Decode(c.PeerID)
		if err != nil {
			continue
		}
		contact := &Contact{
			Nickname:   c.Nickname,
			PeerID:     pid,
			PublicKey:  c.PublicKey,
			KnownAddrs: c.KnownAddrs,
			SeenNonces: make(map[int64]time.Time),
			State:      StateIdle,
			Presence:   PresenceUnknown,
		}
		n.contacts[contact.PeerID] = contact
		n.nickMap[contact.Nickname] = contact.PeerID

		// Pre-populate peerstore from persisted cache so next connect can
		// skip DHT entirely. Short TTL so genuinely dead addrs expire.
		for _, a := range c.KnownAddrs {
			if ma, err := parseMultiaddr(a); err == nil {
				n.host.Peerstore().AddAddr(pid, ma, peerstore.AddressTTL)
			}
		}
	}

	return nil
}

func (n *Node) SaveContacts() {
	n.mu.RLock()
	password := n.password
	list := make([]SerializableContact, 0, len(n.contacts))
	for _, c := range n.contacts {
		c.mu.Lock()
		addrsCopy := append([]string(nil), c.KnownAddrs...)
		list = append(list, SerializableContact{
			Nickname:   c.Nickname,
			PeerID:     c.PeerID.String(),
			PublicKey:  c.PublicKey,
			KnownAddrs: addrsCopy,
		})
		c.mu.Unlock()
	}
	n.mu.RUnlock()

	if password == "" {
		return
	}

	data := MarshalContacts(list)
	if err := saveEncrypted(ContactsFile, data, password); err != nil {
		n.Log(LogLevelError, "Ошибка сохранения контактов: %v", err)
	}
}
