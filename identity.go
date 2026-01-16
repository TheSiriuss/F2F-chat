package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"golang.org/x/crypto/nacl/box"
)

// loadOrInitIdentity loads existing identity or creates new one
func loadOrInitIdentity() (crypto.PrivKey, *[32]byte, *[32]byte, string, error) {
	data, err := os.ReadFile(IdentityFile)
	if err == nil {
		var id LocalIdentity
		if err := json.Unmarshal(data, &id); err == nil {
			privKey, err := crypto.UnmarshalPrivateKey(id.LibP2PPriv)
			if err != nil {
				return nil, nil, nil, "", err
			}
			var naclPub, naclPriv [32]byte
			copy(naclPub[:], id.NaClPub)
			copy(naclPriv[:], id.NaClPriv)
			return privKey, &naclPub, &naclPriv, id.Nickname, nil
		}
	}

	// Generate new identity
	privKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, nil, nil, "", err
	}
	privBytes, err := crypto.MarshalPrivateKey(privKey)
	if err != nil {
		return nil, nil, nil, "", err
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, "", err
	}

	newId := LocalIdentity{
		LibP2PPriv: privBytes,
		NaClPub:    pub[:],
		NaClPriv:   priv[:],
	}
	saveData, _ := json.MarshalIndent(newId, "", "  ")
	os.WriteFile(IdentityFile, saveData, 0600)

	return privKey, pub, priv, "", nil
}

// saveIdentity saves current identity to file
func (n *Node) saveIdentity() error {
	privBytes, err := crypto.MarshalPrivateKey(n.host.Peerstore().PrivKey(n.host.ID()))
	if err != nil {
		return err
	}
	id := LocalIdentity{
		Nickname:   n.nickname,
		LibP2PPriv: privBytes,
		NaClPub:    n.naclPublic[:],
		NaClPriv:   n.naclPrivate[:],
	}
	data, _ := json.MarshalIndent(id, "", "  ")
	return os.WriteFile(IdentityFile, data, 0600)
}

// NewNode creates and initializes a new P2P node
func NewNode(ctx context.Context) (*Node, error) {
	privKey, naclPub, naclPriv, savedNick, err := loadOrInitIdentity()
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

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0", "/ip4/0.0.0.0/udp/0/quic-v1"),
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
		naclPublic:   *naclPub,
		naclPrivate:  *naclPriv,
		contacts:     make(map[peer.ID]*Contact),
		nickMap:      make(map[string]peer.ID),
		ctx:          ctxNode,
		cancel:       cancel,
		presenceChan: make(chan peer.ID, 100),
	}

	h.SetStreamHandler(ProtocolID, node.handleStream)

	// Start background goroutines
	node.wg.Add(4)
	go node.keepAliveLoop()
	go node.backgroundAdvertise()
	go node.presenceLoop()
	go node.presenceWorkerPool()

	return node, nil
}

// LoadContacts loads contacts from file
func (n *Node) LoadContacts() error {
	data, err := os.ReadFile(ContactsFile)
	if err != nil {
		return err
	}
	var saved []Contact
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range saved {
		contact := &Contact{
			Nickname:   c.Nickname,
			PeerID:     c.PeerID,
			PublicKey:  c.PublicKey,
			SeenNonces: make(map[int64]time.Time),
			State:      StateIdle,
			Presence:   PresenceUnknown,
		}
		n.contacts[contact.PeerID] = contact
		n.nickMap[contact.Nickname] = contact.PeerID
	}
	return nil
}

// SaveContacts saves contacts to file
func (n *Node) SaveContacts() {
	n.mu.RLock()
	list := make([]Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		c.mu.Lock()
		list = append(list, Contact{
			Nickname:  c.Nickname,
			PeerID:    c.PeerID,
			PublicKey: c.PublicKey,
		})
		c.mu.Unlock()
	}
	n.mu.RUnlock()
	data, _ := json.MarshalIndent(list, "", "  ")
	os.WriteFile(ContactsFile, data, 0600)
}
