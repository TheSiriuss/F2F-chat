package f2f

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"golang.org/x/crypto/nacl/box"
)

func loadOrInitIdentity(password string) (crypto.PrivKey, *[32]byte, *[32]byte, string, error) {
	if IdentityExists() {
		if password == "" {
			return nil, nil, nil, "", ErrNoPassword
		}

		rawBytes, err := loadEncrypted(IdentityFile, password)
		if err != nil {
			return nil, nil, nil, "", err
		}

		var id LocalIdentity
		if err := id.Unmarshal(rawBytes); err != nil {
			return nil, nil, nil, "", err
		}

		privKey, err := crypto.UnmarshalPrivateKey(id.LibP2PPriv)
		if err != nil {
			return nil, nil, nil, "", err
		}

		var naclPub, naclPriv [32]byte
		copy(naclPub[:], id.NaClPub)
		copy(naclPriv[:], id.NaClPriv)

		return privKey, &naclPub, &naclPriv, id.Nickname, nil
	}

	if password == "" {
		return nil, nil, nil, "", ErrNoPassword
	}

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

	if err := saveEncrypted(IdentityFile, newId.Marshal(), password); err != nil {
		return nil, nil, nil, "", err
	}

	return privKey, pub, priv, "", nil
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
		NaClPriv:   n.naclPrivate[:],
	}

	return saveEncrypted(IdentityFile, id.Marshal(), password)
}

func NewNode(ctx context.Context, listener UIListener, password string) (*Node, error) {
	if password == "" {
		return nil, ErrNoPassword
	}

	privKey, naclPub, naclPriv, savedNick, err := loadOrInitIdentity(password)
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
		password:     password,
		naclPublic:   *naclPub,
		naclPrivate:  *naclPriv,
		contacts:     make(map[peer.ID]*Contact),
		nickMap:      make(map[string]peer.ID),
		ctx:          ctxNode,
		cancel:       cancel,
		presenceChan: make(chan peer.ID, 100),
		listener:     listener,
	}

	h.SetStreamHandler(ProtocolID, node.handleStream)

	node.wg.Add(4)
	go node.keepAliveLoop()
	go node.backgroundAdvertise()
	go node.presenceLoop()
	go node.presenceWorkerPool()

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
			SeenNonces: make(map[int64]time.Time),
			State:      StateIdle,
			Presence:   PresenceUnknown,
		}
		n.contacts[contact.PeerID] = contact
		n.nickMap[contact.Nickname] = contact.PeerID
	}

	return nil
}

func (n *Node) SaveContacts() {
	n.mu.RLock()
	password := n.password
	list := make([]SerializableContact, 0, len(n.contacts))
	for _, c := range n.contacts {
		c.mu.Lock()
		list = append(list, SerializableContact{
			Nickname:  c.Nickname,
			PeerID:    c.PeerID.String(),
			PublicKey: c.PublicKey,
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
