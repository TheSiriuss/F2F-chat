package f2f

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

// loadOrInitIdentity загружает или создаёт identity
// Если password пустой и файл существует - возвращает ошибку
func loadOrInitIdentity(password string) (crypto.PrivKey, *[32]byte, *[32]byte, string, error) {
	// Проверяем существование файла
	if IdentityExists() {
		// Файл существует - нужно расшифровать
		if password == "" {
			return nil, nil, nil, "", ErrNoPassword
		}

		var id LocalIdentity
		if err := loadEncrypted(IdentityFile, &id, password); err != nil {
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

	// Файл не существует - создаём новый identity
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

	// Сохраняем зашифрованный identity
	if err := saveEncrypted(IdentityFile, newId, password); err != nil {
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

	return saveEncrypted(IdentityFile, id, password)
}

// NewNode создаёт ноду с шифрованием
// password - обязателен для шифрования/дешифрования данных
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
		password:     password, // <-- Сохраняем пароль
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

// LoadContacts загружает зашифрованные контакты
func (n *Node) LoadContacts() error {
	if !ContactsExist() {
		return nil // Нет файла - нет контактов, это норма
	}

	n.mu.RLock()
	password := n.password
	n.mu.RUnlock()

	if password == "" {
		return ErrNoPassword
	}

	var saved []Contact
	if err := loadEncrypted(ContactsFile, &saved, password); err != nil {
		// Если ошибка дешифровки - возможно старый формат или повреждён
		// Пробуем загрузить как незашифрованный (миграция)
		data, readErr := os.ReadFile(ContactsFile)
		if readErr != nil {
			return err
		}
		if jsonErr := json.Unmarshal(data, &saved); jsonErr != nil {
			return err // Возвращаем оригинальную ошибку
		}
		// Успешно прочитали незашифрованный - мигрируем
		n.Log(LogLevelInfo, "Миграция контактов в зашифрованный формат...")
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

	// После успешной загрузки - пересохраняем в зашифрованном виде
	go n.SaveContacts()

	return nil
}

// SaveContacts сохраняет контакты в зашифрованном виде
func (n *Node) SaveContacts() {
	n.mu.RLock()
	password := n.password
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

	if password == "" {
		return // Нет пароля - не сохраняем
	}

	if err := saveEncrypted(ContactsFile, list, password); err != nil {
		n.Log(LogLevelError, "Ошибка сохранения контактов: %v", err)
	}
}
