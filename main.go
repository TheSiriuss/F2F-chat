package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/chzyer/readline"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// --- Configuration & Constants ---

const (
	ProtocolVersion  = "1.1.0-alpha"
	ProtocolID       = "/f2f-chat/1.1.0"
	RendezvousString = "f2f-chat-alpha-v1"
	ContactsFile     = "contacts.json"
	IdentityFile     = "identity.json"

	HandshakeLimit = 4096
	MaxNickLength  = 32
	MaxMsgLength   = 1000
	MaxMessageSize = 64 * 1024

	PeerLookupTimeout   = 45 * time.Second
	PresenceTimeout     = 15 * time.Second
	PresenceInterval    = 30 * time.Second
	AdvertiseDelay      = 5 * time.Second
	KeepAliveInterval   = 30 * time.Second
	AdvertiseInterval   = 1 * time.Minute
	StreamReadTimeout   = 10 * time.Minute
	HandshakeTimeout    = 10 * time.Second
	WriteTimeout        = 5 * time.Second
	BootstrapTimeout    = 15 * time.Second
	MaxTimeSkew         = 2 * time.Minute
	NewStreamTimeout    = 30 * time.Second
	ReconnectCooldown   = 3 * time.Second
	PresenceMaxWorkers  = 3
	MaxNoncesPerContact = 100
	ShutdownTimeout     = 3 * time.Second

	MaxPresenceBackoff = 15 * time.Minute
)

var DebugMode = false

// --- UI Style ---

type UIStyle struct {
	TopLeft, TopRight, BottomLeft, BottomRight string
	Horizontal, Vertical, TeeLeft, TeeRight    string
	Online, Offline, InChat, Connected         string
	Pending, Global, Searching, Unknown        string
	OK, Fail, Warning, Info, Arrow, Bell, Mail string
}

var Style UIStyle

func initStyle() {
	useUnicode := runtime.GOOS != "windows"
	if os.Getenv("F2F_ASCII") == "1" {
		useUnicode = false
	}
	if os.Getenv("F2F_UNICODE") == "1" {
		useUnicode = true
	}

	if useUnicode {
		Style = UIStyle{
			TopLeft: "┌", TopRight: "┐", BottomLeft: "└", BottomRight: "┘",
			Horizontal: "─", Vertical: "│", TeeLeft: "├", TeeRight: "┤",
			Online: "[*]", Offline: "[-]", InChat: "[#]", Connected: "[+]",
			Pending: "[~]", Global: "[G]", Searching: "[?]", Unknown: "[.]",
			OK: "[+]", Fail: "[!]", Warning: "[!]", Info: "[i]",
			Arrow: "->", Bell: "[!]", Mail: "[>]",
		}
	} else {
		Style = UIStyle{
			TopLeft: "+", TopRight: "+", BottomLeft: "+", BottomRight: "+",
			Horizontal: "-", Vertical: "|", TeeLeft: "+", TeeRight: "+",
			Online: "[*]", Offline: "[-]", InChat: "[#]", Connected: "[+]",
			Pending: "[~]", Global: "[G]", Searching: "[?]", Unknown: "[.]",
			OK: "[+]", Fail: "[X]", Warning: "[!]", Info: "[i]",
			Arrow: "->", Bell: "[!]", Mail: "[>]",
		}
	}
}

// --- Structures ---

type ChatState int

const (
	StateIdle ChatState = iota
	StatePending
	StateActive
)

type PresenceStatus int

const (
	PresenceUnknown PresenceStatus = iota
	PresenceOnline
	PresenceOffline
	PresenceChecking
)

func (p PresenceStatus) String() string {
	switch p {
	case PresenceOnline:
		return "ONLINE"
	case PresenceOffline:
		return "OFFLINE"
	case PresenceChecking:
		return "CHECKING..."
	default:
		return "UNKNOWN"
	}
}

const (
	MsgTypeHandshake = "hs"
	MsgTypeRequest   = "req"
	MsgTypeAccept    = "acc"
	MsgTypeDecline   = "dec"
	MsgTypeText      = "txt"
	MsgTypePing      = "png"
	MsgTypeBye       = "bye"
)

type InnerMessage struct {
	Type      string `json:"t"`
	Timestamp int64  `json:"ts"`
	Content   string `json:"c,omitempty"`
}

type HandshakePayload struct {
	Version      string `json:"v"`
	Timestamp    int64  `json:"ts"`
	Nonce        int64  `json:"n"`
	NaClPubKey   []byte `json:"key"`
	EphemeralPub []byte `json:"eph"`
	Signature    []byte `json:"sig"`
}

type Contact struct {
	Nickname    string   `json:"nick"`
	PeerID      peer.ID  `json:"pid"`
	PublicKey   [32]byte `json:"pub"`
	LastMsgTime int64    `json:"-"`

	SeenNonces map[int64]time.Time `json:"-"`

	State           ChatState      `json:"-"`
	Stream          network.Stream `json:"-"`
	Connecting      bool           `json:"-"`
	LastConnectTime time.Time      `json:"-"`

	Presence      PresenceStatus `json:"-"`
	LastSeen      time.Time      `json:"-"`
	LastChecked   time.Time      `json:"-"`
	AddressCount  int            `json:"-"`
	FailCount     int            `json:"-"`
	NextCheckTime time.Time      `json:"-"`

	localEphPriv *[32]byte `json:"-"`
	localEphPub  *[32]byte `json:"-"`
	remoteEphPub *[32]byte `json:"-"`
	sessionKey   *[32]byte `json:"-"`
	sessionEstab bool      `json:"-"`

	mu      sync.Mutex `json:"-"`
	writeMu sync.Mutex `json:"-"`
}

type LocalIdentity struct {
	Nickname   string `json:"nick"`
	LibP2PPriv []byte `json:"libp2p_priv"`
	NaClPub    []byte `json:"nacl_pub"`
	NaClPriv   []byte `json:"nacl_priv"`
}

type Node struct {
	host        host.Host
	dht         *dht.IpfsDHT
	discovery   *routing.RoutingDiscovery
	nickname    string
	naclPublic  [32]byte
	naclPrivate [32]byte

	contacts map[peer.ID]*Contact
	nickMap  map[string]peer.ID

	activeChat peer.ID
	mu         sync.RWMutex
	uiMu       sync.Mutex
	wg         sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc

	presenceChan chan peer.ID

	rl          *readline.Instance
	useReadline bool
	shutdownMu  sync.Mutex
	isShutdown  bool
}

// --- Main ---

func main() {
	initStyle()

	for _, arg := range os.Args[1:] {
		switch arg {
		case "--debug":
			DebugMode = true
			fmt.Println("[SYS] Debug mode ENABLED")
		case "--ascii":
			os.Setenv("F2F_ASCII", "1")
			initStyle()
		case "--help":
			fmt.Println("F2F Messenger Alpha")
			return
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("Запуск F2F Alpha...")
	node, err := NewNode(ctx)
	if err != nil {
		fmt.Println("Критическая ошибка:", err)
		os.Exit(1)
	}

	// Обработка сигналов Ctrl+C, kill
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println() // Новая строка после ^C
		node.Shutdown()
		os.Exit(0)
	}()

	if err := node.LoadContacts(); err != nil {
		node.Debug("Контакты не найдены: %v", err)
	}

	// Пробуем readline
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "> ",
		InterruptPrompt: "^C",
		EOFPrompt:       ".exit",
	})
	if err == nil {
		node.rl = rl
		node.useReadline = true
	} else {
		node.useReadline = false
		fmt.Printf("[SYS] Readline недоступен, простой режим\n")
	}

	fmt.Print("\033[H\033[2J")
	node.printBanner()

	if node.nickname != "" {
		node.SafePrintf("%s Авто-вход: %s\n", Style.OK, node.nickname)
		go func() {
			time.Sleep(200 * time.Millisecond)
			node.ShowInfo()
		}()
	} else {
		node.SafePrintf("%s Введите .login <ник> для создания профиля\n", Style.Info)
	}

	// Основной цикл
	if node.useReadline {
		node.runWithReadline()
	} else {
		node.runWithScanner()
	}

	// Корректное завершение
	node.Shutdown()
}

// runWithReadline — readline режим
func (n *Node) runWithReadline() {
	defer func() {
		if n.rl != nil {
			n.rl.Close()
		}
	}()

	for {
		n.updatePrompt()
		line, err := n.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				// Ctrl+C — выходим
				fmt.Println()
				return
			}
			// EOF — выходим
			return
		}

		if !n.processInputLine(line) {
			return
		}
	}
}

// runWithScanner — fallback режим
func (n *Node) runWithScanner() {
	scanner := bufio.NewScanner(os.Stdin)
	n.printPrompt()

	for scanner.Scan() {
		line := scanner.Text()
		if !n.processInputLine(line) {
			return
		}
		n.printPrompt()
	}
}

// processInputLine — обработка строки, false = выход
func (n *Node) processInputLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}

	n.mu.RLock()
	currentChatID := n.activeChat
	n.mu.RUnlock()

	if currentChatID != "" && !strings.HasPrefix(line, ".") {
		cleanMsg := SanitizeInput(line, MaxMsgLength)
		if cleanMsg != "" {
			n.SendChatMessage(currentChatID, cleanMsg)
		}
		return true
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return true
	}
	cmd := strings.ToLower(parts[0])

	switch cmd {
	case ".login":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .login <nickname>\n")
		} else {
			cleanNick := SanitizeInput(parts[1], MaxNickLength)
			n.Login(cleanNick)
		}

	case ".logout":
		n.SafePrintf("%s Сброс личности...\n", Style.Warning)
		if err := os.Remove(IdentityFile); err != nil {
			n.SafePrintf("%s Ошибка: %v\n", Style.Fail, err)
		} else {
			n.SafePrintf("%s Удалено. Перезапустите программу.\n", Style.OK)
			return false
		}

	case ".bootstrap":
		n.ConnectToBootstrap()

	case ".info":
		n.ShowInfo()

	case ".fingerprint":
		if len(parts) < 2 {
			n.ShowFingerprint("")
		} else {
			n.ShowFingerprint(parts[1])
		}

	case ".addfriend":
		if len(parts) >= 4 {
			n.AddFriend(parts[1], parts[2], parts[3])
		} else {
			n.SafePrintf("Использование: .addfriend <nick> <peerID> <pubkey>\n")
		}

	case ".connect":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .connect <nickname>\n")
		} else {
			go n.InitConnect(parts[1])
		}

	case ".accept":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .accept <nickname>\n")
		} else {
			n.HandleDecision(parts[1], true)
		}

	case ".decline":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .decline <nickname>\n")
		} else {
			n.HandleDecision(parts[1], false)
		}

	case ".leave":
		n.LeaveChat()

	case ".list":
		n.ListContacts()

	case ".check":
		n.SafePrintf("%s Проверка контактов...\n", Style.Info)
		n.ForceCheckAll()

	case ".find":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .find <nickname>\n")
		} else {
			go n.FindContact(parts[1])
		}

	case ".help":
		n.printHelp()

	case ".exit", ".quit", ".q":
		n.SafePrintf("%s Выход...\n", Style.Info)
		return false

	default:
		n.SafePrintf("%s Неизвестная команда. .help\n", Style.Warning)
	}

	return true
}

// --- UI Helpers ---

func visibleLen(s string) int {
	return utf8.RuneCountInString(s)
}

func (n *Node) updatePrompt() {
	if !n.useReadline || n.rl == nil {
		return
	}

	n.mu.RLock()
	activeID := n.activeChat
	var activeNick string
	if activeID != "" {
		if c, ok := n.contacts[activeID]; ok {
			activeNick = c.Nickname
		}
	}
	n.mu.RUnlock()

	if activeNick != "" {
		n.rl.SetPrompt(fmt.Sprintf("[%s] > ", activeNick))
	} else {
		n.rl.SetPrompt("> ")
	}
}

func (n *Node) printPrompt() {
	n.mu.RLock()
	activeID := n.activeChat
	var activeNick string
	if activeID != "" {
		if c, ok := n.contacts[activeID]; ok {
			activeNick = c.Nickname
		}
	}
	n.mu.RUnlock()

	if activeNick != "" {
		fmt.Printf("[%s] > ", activeNick)
	} else {
		fmt.Print("> ")
	}
}

func (n *Node) drawBox(title string, lines []string) {
	n.uiMu.Lock()
	defer n.uiMu.Unlock()

	if n.useReadline && n.rl != nil {
		n.rl.Clean()
	}

	contentWidth := 0
	if title != "" {
		contentWidth = visibleLen(title)
	}
	for _, line := range lines {
		l := visibleLen(line)
		if l > contentWidth {
			contentWidth = l
		}
	}
	if contentWidth < 40 {
		contentWidth = 40
	}

	fmt.Print("\n" + Style.TopLeft)
	fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
	fmt.Println(Style.TopRight)

	if title != "" {
		tLen := visibleLen(title)
		padding := (contentWidth - tLen) / 2
		rightPadding := contentWidth - tLen - padding

		fmt.Print(Style.Vertical + " ")
		fmt.Print(strings.Repeat(" ", padding))
		fmt.Print(title)
		fmt.Print(strings.Repeat(" ", rightPadding))
		fmt.Println(" " + Style.Vertical)

		fmt.Print(Style.TeeLeft)
		fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
		fmt.Println(Style.TeeRight)
	}

	for _, line := range lines {
		lLen := visibleLen(line)
		rightPadding := contentWidth - lLen

		fmt.Print(Style.Vertical + " ")
		fmt.Print(line)
		fmt.Print(strings.Repeat(" ", rightPadding))
		fmt.Println(" " + Style.Vertical)
	}

	fmt.Print(Style.BottomLeft)
	fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
	fmt.Println(Style.BottomRight)

	if n.useReadline && n.rl != nil {
		n.rl.Refresh()
	}
}

func (n *Node) printBanner() {
	n.drawBox(fmt.Sprintf("F2F MESSENGER %s", ProtocolVersion), []string{
		"Forward Secrecy ENABLED",
		".help - справка | Ctrl+C - выход",
	})
}

func (n *Node) printHelp() {
	n.drawBox("КОМАНДЫ", []string{
		".login <nick>          - создать профиль",
		".logout                - сбросить профиль",
		".bootstrap             - подключиться к DHT",
		".info                  - мои данные",
		".fingerprint [nick]    - fingerprint ключа",
		".addfriend <n> <p> <k> - добавить контакт",
		".connect <nick>        - начать чат",
		".accept / .decline     - ответ на запрос",
		".leave                 - выйти из чата",
		".list                  - контакты",
		".check                 - обновить статусы",
		".find <nick>           - найти в DHT",
		".exit или Ctrl+C       - выход",
	})
}

func (n *Node) SafePrintf(format string, a ...any) {
	n.uiMu.Lock()
	defer n.uiMu.Unlock()

	if n.useReadline && n.rl != nil {
		n.rl.Clean()
	}

	fmt.Printf(format, a...)

	if n.useReadline && n.rl != nil {
		n.rl.Refresh()
	}
}

func SanitizeInput(input string, maxLen int) string {
	runes := []rune(strings.TrimSpace(input))
	safeRunes := make([]rune, 0, len(runes))
	for _, r := range runes {
		if unicode.IsPrint(r) {
			safeRunes = append(safeRunes, r)
		}
	}
	if len(safeRunes) > maxLen {
		return string(safeRunes[:maxLen])
	}
	return string(safeRunes)
}

// --- Fingerprint ---

func (n *Node) ShowFingerprint(nick string) {
	if nick == "" {
		fp := computeFingerprint(n.naclPublic[:])
		n.drawBox("ВАШ FINGERPRINT", []string{
			"Сравните по телефону/лично:",
			"",
			fp,
		})
		return
	}

	c := n.getContactByNick(nick)
	if c == nil {
		n.SafePrintf("%s Контакт '%s' не найден\n", Style.Fail, nick)
		return
	}

	fp := computeFingerprint(c.PublicKey[:])
	n.drawBox(fmt.Sprintf("FINGERPRINT: %s", nick), []string{
		"Должно совпасть с .fingerprint у друга:",
		"",
		fp,
	})
}

func computeFingerprint(pubKey []byte) string {
	hash := sha256.Sum256(pubKey)
	hex := fmt.Sprintf("%X", hash[:8])
	return fmt.Sprintf("%s-%s-%s-%s", hex[0:4], hex[4:8], hex[8:12], hex[12:16])
}

// --- Identity & Node Setup ---

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

	node.wg.Add(4)
	go node.keepAliveLoop()
	go node.backgroundAdvertise()
	go node.presenceLoop()
	go node.presenceWorkerPool()

	return node, nil
}

// --- Forward Secrecy ---

func generateEphemeralKeys() (*[32]byte, *[32]byte, error) {
	var priv, pub [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)
	return &priv, &pub, nil
}

func deriveSessionKey(localPriv, localPub, remotePub *[32]byte) (*[32]byte, error) {
	var shared [32]byte
	curve25519.ScalarMult(&shared, localPriv, remotePub)

	var saltBuf bytes.Buffer
	saltBuf.WriteString("f2f-session-v1:")
	if bytes.Compare(localPub[:], remotePub[:]) < 0 {
		saltBuf.Write(localPub[:])
		saltBuf.Write(remotePub[:])
	} else {
		saltBuf.Write(remotePub[:])
		saltBuf.Write(localPub[:])
	}

	hkdfReader := hkdf.New(sha256.New, shared[:], saltBuf.Bytes(), []byte("session-key"))
	var sessionKey [32]byte
	if _, err := io.ReadFull(hkdfReader, sessionKey[:]); err != nil {
		return nil, err
	}

	for i := range shared {
		shared[i] = 0
	}

	return &sessionKey, nil
}

// --- Crypto ---

func (n *Node) encryptSession(msg *InnerMessage, sessionKey *[32]byte) ([]byte, error) {
	plaintext, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], plaintext, &nonce, sessionKey)
	return encrypted, nil
}

func (n *Node) decryptSession(ciphertext []byte, sessionKey *[32]byte) (*InnerMessage, error) {
	if len(ciphertext) < 24+secretbox.Overhead {
		return nil, errors.New("ciphertext too short")
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	plaintext, ok := secretbox.Open(nil, ciphertext[24:], &nonce, sessionKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	var msg InnerMessage
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// --- Presence ---

func (n *Node) presenceLoop() {
	defer n.wg.Done()

	select {
	case <-time.After(10 * time.Second):
	case <-n.ctx.Done():
		return
	}

	n.QueuePresenceChecks()

	ticker := time.NewTicker(PresenceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.QueuePresenceChecks()
		}
	}
}

func (n *Node) presenceWorkerPool() {
	defer n.wg.Done()

	for {
		select {
		case <-n.ctx.Done():
			return
		case pid, ok := <-n.presenceChan:
			if !ok {
				return
			}
			n.checkSinglePresence(pid)
		}
	}
}

func (n *Node) ForceCheckAll() {
	n.mu.RLock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.mu.RUnlock()

	for _, c := range contacts {
		c.mu.Lock()
		c.NextCheckTime = time.Now()
		c.FailCount = 0
		c.Presence = PresenceChecking
		pid := c.PeerID
		c.mu.Unlock()

		select {
		case n.presenceChan <- pid:
		default:
		}
	}
}

func (n *Node) QueuePresenceChecks() {
	n.mu.RLock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.mu.RUnlock()

	for _, c := range contacts {
		c.mu.Lock()
		if c.Stream != nil {
			c.Presence = PresenceOnline
			c.LastSeen = time.Now()
			c.FailCount = 0
			c.mu.Unlock()
			continue
		}

		if time.Now().Before(c.NextCheckTime) {
			c.mu.Unlock()
			continue
		}

		c.Presence = PresenceChecking
		pid := c.PeerID
		c.mu.Unlock()

		select {
		case n.presenceChan <- pid:
		default:
		}
	}
}

func (n *Node) checkSinglePresence(pid peer.ID) {
	c := n.getContactByID(pid)
	if c == nil {
		return
	}

	if n.host.Network().Connectedness(pid) == network.Connected {
		c.mu.Lock()
		c.Presence = PresenceOnline
		c.LastSeen = time.Now()
		c.FailCount = 0
		c.NextCheckTime = time.Now().Add(PresenceInterval)
		c.mu.Unlock()
		return
	}

	ctx, cancel := context.WithTimeout(n.ctx, PresenceTimeout)
	defer cancel()

	info, err := n.dht.FindPeer(ctx, pid)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastChecked = time.Now()

	if err != nil {
		c.Presence = PresenceOffline
		c.FailCount++
		backoff := time.Duration(30*(1<<c.FailCount)) * time.Second
		if backoff > MaxPresenceBackoff {
			backoff = MaxPresenceBackoff
		}
		c.NextCheckTime = time.Now().Add(backoff)
		return
	}

	c.Presence = PresenceOnline
	c.LastSeen = time.Now()
	c.AddressCount = len(info.Addrs)
	c.FailCount = 0
	c.NextCheckTime = time.Now().Add(PresenceInterval)

	if len(info.Addrs) > 0 {
		n.host.Peerstore().AddAddrs(pid, info.Addrs, peerstore.TempAddrTTL)
	}
}

func (n *Node) FindContact(nick string) {
	c := n.getContactByNick(nick)
	if c == nil {
		n.SafePrintf("%s Контакт '%s' не найден\n", Style.Fail, nick)
		return
	}

	n.SafePrintf("%s Поиск %s в DHT...\n", Style.Searching, nick)

	ctx, cancel := context.WithTimeout(n.ctx, PresenceTimeout)
	defer cancel()

	start := time.Now()
	info, err := n.dht.FindPeer(ctx, c.PeerID)
	elapsed := time.Since(start)

	if err != nil {
		n.SafePrintf("%s %s не найден (%.1fs)\n", Style.Fail, nick, elapsed.Seconds())
		c.mu.Lock()
		c.Presence = PresenceOffline
		c.LastChecked = time.Now()
		c.mu.Unlock()
		return
	}

	n.SafePrintf("%s %s найден! (%d адресов, %.1fs)\n", Style.OK, nick, len(info.Addrs), elapsed.Seconds())

	c.mu.Lock()
	c.Presence = PresenceOnline
	c.LastSeen = time.Now()
	c.AddressCount = len(info.Addrs)
	c.LastChecked = time.Now()
	c.FailCount = 0
	c.mu.Unlock()

	n.host.Peerstore().AddAddrs(c.PeerID, info.Addrs, peerstore.PermanentAddrTTL)
}

// --- Persistence ---

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

// --- Helpers ---

func (n *Node) Debug(format string, a ...any) {
	if DebugMode {
		n.SafePrintf("[DEBUG] "+format+"\n", a...)
	}
}

func (n *Node) Login(nickname string) {
	n.mu.Lock()
	n.nickname = nickname
	n.mu.Unlock()
	n.saveIdentity()
	n.SafePrintf("%s Вы: %s\n", Style.OK, nickname)
	go func() {
		time.Sleep(100 * time.Millisecond)
		n.ShowInfo()
	}()
}

func (n *Node) ShowInfo() {
	if n.nickname == "" {
		n.SafePrintf("%s Сначала: .login <ник>\n", Style.Warning)
		return
	}

	hasRelay := false
	for _, addr := range n.host.Addrs() {
		if strings.Contains(addr.String(), "p2p-circuit") {
			hasRelay = true
			break
		}
	}
	connectedPeers := len(n.host.Network().Peers())

	var statusLine string
	if hasRelay {
		statusLine = Style.Global + " GLOBAL (relay)"
	} else if connectedPeers > 0 {
		statusLine = Style.Searching + " ONLINE"
	} else {
		statusLine = Style.Offline + " OFFLINE"
	}

	pubKeyB64 := base64.StdEncoding.EncodeToString(n.naclPublic[:])
	addCmd := fmt.Sprintf(".addfriend %s %s %s", n.nickname, n.host.ID().String(), pubKeyB64)
	fp := computeFingerprint(n.naclPublic[:])

	n.drawBox("ВАШИ ДАННЫЕ", []string{
		fmt.Sprintf("Ник:         %s", n.nickname),
		fmt.Sprintf("Статус:      %s", statusLine),
		fmt.Sprintf("Пиров:       %d", connectedPeers),
		fmt.Sprintf("Fingerprint: %s", fp),
		"",
		"PeerID:",
		n.host.ID().String(),
		"",
		"Для друга:",
		addCmd,
	})
}

func (n *Node) ConnectToBootstrap() {
	n.SafePrintf("%s Подключение к DHT...\n", Style.Info)
	var wg sync.WaitGroup
	connected := 0
	var mu sync.Mutex

	for _, addrInfo := range dht.DefaultBootstrapPeers {
		wg.Add(1)
		go func(info multiaddr.Multiaddr) {
			defer wg.Done()
			ai, err := peer.AddrInfoFromP2pAddr(info)
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(n.ctx, BootstrapTimeout)
			defer cancel()
			if err := n.host.Connect(ctx, *ai); err == nil {
				mu.Lock()
				connected++
				mu.Unlock()
			}
		}(addrInfo)
	}
	wg.Wait()
	if connected > 0 {
		n.SafePrintf("%s Подключено к %d узлам\n", Style.OK, connected)
		go func() {
			time.Sleep(3 * time.Second)
			n.ForceCheckAll()
		}()
	} else {
		n.SafePrintf("%s Не удалось подключиться\n", Style.Fail)
	}
}

func (n *Node) AddFriend(nickname, peerIDStr, pubKeyB64 string) {
	if nickname == "" {
		n.SafePrintf("%s Пустой ник\n", Style.Fail)
		return
	}
	peerID, err := peer.Decode(peerIDStr)
	if err != nil {
		n.SafePrintf("%s Ошибка PeerID\n", Style.Fail)
		return
	}
	if peerID == n.host.ID() {
		n.SafePrintf("%s Нельзя добавить себя\n", Style.Fail)
		return
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pubBytes) != 32 {
		n.SafePrintf("%s Ошибка ключа\n", Style.Fail)
		return
	}
	var pubKey [32]byte
	copy(pubKey[:], pubBytes)

	n.mu.Lock()
	if _, exists := n.nickMap[nickname]; exists {
		n.mu.Unlock()
		n.SafePrintf("%s Ник '%s' занят\n", Style.Fail, nickname)
		return
	}
	contact := &Contact{
		Nickname:   nickname,
		PeerID:     peerID,
		PublicKey:  pubKey,
		SeenNonces: make(map[int64]time.Time),
		State:      StateIdle,
		Presence:   PresenceUnknown,
	}
	n.contacts[peerID] = contact
	n.nickMap[nickname] = peerID
	n.mu.Unlock()

	fp := computeFingerprint(pubKey[:])
	n.SafePrintf("%s Добавлен: %s (FP: %s)\n", Style.OK, nickname, fp)

	go n.SaveContacts()
	go func() {
		time.Sleep(1 * time.Second)
		n.FindContact(nickname)
	}()
}

func (n *Node) getContactByNick(nick string) *Contact {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if pid, ok := n.nickMap[nick]; ok {
		return n.contacts[pid]
	}
	return nil
}

func (n *Node) getContactByID(id peer.ID) *Contact {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.contacts[id]
}

// --- Framing ---

func (n *Node) writeFrame(s network.Stream, data []byte) error {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := s.Write(buf)
	return err
}

func (n *Node) readFrame(s network.Stream) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(s, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > MaxMessageSize {
		return nil, fmt.Errorf("too large: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(s, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// --- Connection ---

func (n *Node) InitConnect(nickname string) {
	c := n.getContactByNick(nickname)
	if c == nil {
		n.SafePrintf("%s Контакт '%s' не найден\n", Style.Fail, nickname)
		return
	}

	c.mu.Lock()
	if c.Stream != nil {
		c.mu.Unlock()
		n.SafePrintf("%s Уже подключены к %s\n", Style.Warning, nickname)
		n.enterChat(c.PeerID)
		return
	}
	if c.Connecting {
		c.mu.Unlock()
		n.SafePrintf("%s Подключение в процессе\n", Style.Warning)
		return
	}
	c.Connecting = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.Connecting = false
		c.mu.Unlock()
	}()

	if n.host.Network().Connectedness(c.PeerID) != network.Connected {
		n.SafePrintf("%s Поиск %s...\n", Style.Searching, nickname)
		ctxT, cancel := context.WithTimeout(n.ctx, PeerLookupTimeout)
		defer cancel()

		info, err := n.dht.FindPeer(ctxT, c.PeerID)
		if err == nil && len(info.Addrs) > 0 {
			n.host.Peerstore().AddAddrs(c.PeerID, info.Addrs, peerstore.PermanentAddrTTL)
			n.SafePrintf("%s Найдено %d адресов\n", Style.OK, len(info.Addrs))
		}
	}

	streamCtx, streamCancel := context.WithTimeout(n.ctx, NewStreamTimeout)
	defer streamCancel()

	s, err := n.host.NewStream(streamCtx, c.PeerID, ProtocolID)
	if err != nil {
		n.SafePrintf("%s Ошибка подключения: %v\n", Style.Fail, err)
		return
	}

	c.mu.Lock()
	if c.Stream != nil {
		s.Close()
		c.mu.Unlock()
		n.enterChat(c.PeerID)
		return
	}
	c.Stream = s
	c.Presence = PresenceOnline
	c.LastSeen = time.Now()
	c.FailCount = 0
	c.mu.Unlock()

	ephPriv, ephPub, err := generateEphemeralKeys()
	if err != nil {
		n.SafePrintf("%s Ошибка ключей\n", Style.Fail)
		n.closeStream(c)
		return
	}

	c.mu.Lock()
	c.localEphPriv = ephPriv
	c.localEphPub = ephPub
	c.mu.Unlock()

	hsBytes, err := n.createHandshakeBytes(ephPub)
	if err != nil {
		n.SafePrintf("%s Ошибка handshake\n", Style.Fail)
		n.closeStream(c)
		return
	}

	if err := n.writeFrame(s, hsBytes); err != nil {
		n.SafePrintf("%s Ошибка отправки\n", Style.Fail)
		n.closeStream(c)
		return
	}

	c.mu.Lock()
	c.State = StatePending
	c.mu.Unlock()

	n.SafePrintf("%s Ожидание ответа...\n", Style.OK)

	n.wg.Add(1)
	go n.readLoop(c, true)
}

func (n *Node) HandleDecision(nick string, accept bool) {
	c := n.getContactByNick(nick)
	if c == nil {
		n.SafePrintf("%s Контакт '%s' не найден\n", Style.Fail, nick)
		return
	}
	c.mu.Lock()
	isPending := c.State == StatePending
	hasSession := c.sessionEstab
	c.mu.Unlock()

	if !isPending || !hasSession {
		n.SafePrintf("%s Нет запроса от %s\n", Style.Warning, nick)
		return
	}

	if accept {
		if err := n.sendSessionMessage(c, MsgTypeAccept, "OK"); err != nil {
			n.SafePrintf("%s Ошибка: %v\n", Style.Fail, err)
			return
		}
		c.mu.Lock()
		c.State = StateActive
		c.mu.Unlock()
		n.enterChat(c.PeerID)
	} else {
		n.sendSessionMessage(c, MsgTypeDecline, "NO")
		n.closeStream(c)
		n.SafePrintf("%s Отклонено\n", Style.OK)
	}
}

func (n *Node) handleStream(s network.Stream) {
	remoteID := s.Conn().RemotePeer()
	c := n.getContactByID(remoteID)
	if c == nil {
		s.Close()
		return
	}

	c.mu.Lock()
	if c.Stream != nil {
		localID := n.host.ID()
		if localID.String() < remoteID.String() {
			c.mu.Unlock()
			s.Close()
			return
		}
		c.Stream.Close()
	}

	c.LastConnectTime = time.Now()
	c.Stream = s
	c.Presence = PresenceOnline
	c.LastSeen = time.Now()
	c.FailCount = 0
	c.mu.Unlock()

	ephPriv, ephPub, err := generateEphemeralKeys()
	if err != nil {
		n.closeStream(c)
		return
	}

	c.mu.Lock()
	c.localEphPriv = ephPriv
	c.localEphPub = ephPub
	c.mu.Unlock()

	hsBytes, err := n.createHandshakeBytes(ephPub)
	if err != nil {
		n.closeStream(c)
		return
	}

	if err := n.writeFrame(s, hsBytes); err != nil {
		n.closeStream(c)
		return
	}

	n.wg.Add(1)
	go n.readLoop(c, false)
}

func (n *Node) readLoop(c *Contact, isInitiator bool) {
	defer n.wg.Done()
	defer n.handleDisconnect(c, nil)

	c.mu.Lock()
	s := c.Stream
	c.mu.Unlock()

	if s == nil {
		return
	}

	s.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	hsData, err := n.readFrame(s)
	if err != nil {
		return
	}

	remoteEphPub, err := n.verifyHandshake(c, hsData)
	if err != nil {
		n.SafePrintf("%s Ошибка handshake: %v\n", Style.Fail, err)
		return
	}

	c.mu.Lock()
	c.remoteEphPub = remoteEphPub

	sessionKey, err := deriveSessionKey(c.localEphPriv, c.localEphPub, remoteEphPub)
	if err != nil {
		c.mu.Unlock()
		return
	}
	c.sessionKey = sessionKey
	c.sessionEstab = true

	for i := range c.localEphPriv {
		c.localEphPriv[i] = 0
	}
	c.localEphPriv = nil
	c.mu.Unlock()

	if isInitiator {
		if err := n.sendSessionMessage(c, MsgTypeRequest, ""); err != nil {
			return
		}
	}

	go n.SaveContacts()

	for {
		c.mu.Lock()
		if c.Stream != s {
			c.mu.Unlock()
			return
		}
		sKey := c.sessionKey
		c.mu.Unlock()

		if sKey == nil {
			return
		}

		s.SetReadDeadline(time.Now().Add(StreamReadTimeout))
		data, err := n.readFrame(s)
		if err != nil {
			return
		}

		msg, err := n.decryptSession(data, sKey)
		if err != nil {
			continue
		}

		now := time.Now().UnixNano()
		if msg.Timestamp > now+int64(MaxTimeSkew) {
			continue
		}

		c.mu.Lock()
		if msg.Timestamp <= c.LastMsgTime {
			c.mu.Unlock()
			continue
		}
		c.LastMsgTime = msg.Timestamp
		c.mu.Unlock()

		if msg.Type == MsgTypeBye {
			return
		}
		if msg.Type == MsgTypePing {
			continue
		}

		content := msg.Content
		if msg.Type == MsgTypeText {
			content = SanitizeInput(content, MaxMsgLength)
		}
		n.processMessage(c, msg.Type, msg.Timestamp, content)
	}
}

func (n *Node) processMessage(c *Contact, msgType string, ts int64, body string) {
	switch msgType {
	case MsgTypeRequest:
		c.mu.Lock()
		if c.State == StateActive {
			c.mu.Unlock()
			return
		}
		c.State = StatePending
		c.mu.Unlock()
		n.SafePrintf("\n%s Запрос от %s! (.accept %s / .decline %s)\n",
			Style.Bell, c.Nickname, c.Nickname, c.Nickname)

	case MsgTypeAccept:
		c.mu.Lock()
		c.State = StateActive
		c.mu.Unlock()
		n.SafePrintf("\n%s %s принял!\n", Style.OK, c.Nickname)
		n.enterChat(c.PeerID)

	case MsgTypeDecline:
		n.closeStream(c)
		n.SafePrintf("\n%s %s отклонил\n", Style.Fail, c.Nickname)

	case MsgTypeText:
		c.mu.Lock()
		isActive := c.State == StateActive
		c.mu.Unlock()
		if !isActive {
			return
		}

		timestamp := time.Unix(0, ts).Format("15:04")
		n.mu.RLock()
		active := n.activeChat == c.PeerID
		n.mu.RUnlock()

		if active {
			n.SafePrintf("[%s %s]: %s\n", c.Nickname, timestamp, body)
		} else {
			n.SafePrintf("\n%s [%s %s]: %s\n", Style.Mail, c.Nickname, timestamp, body)
		}
	}
}

func (n *Node) SendChatMessage(peerID peer.ID, text string) {
	c := n.getContactByID(peerID)
	if c == nil {
		n.LeaveChat()
		return
	}

	c.mu.Lock()
	state := c.State
	c.mu.Unlock()

	if state != StateActive {
		n.SafePrintf("%s Чат не активен\n", Style.Warning)
		return
	}

	if err := n.sendSessionMessage(c, MsgTypeText, text); err != nil {
		n.SafePrintf("%s Ошибка: %v\n", Style.Fail, err)
		return
	}
	n.SafePrintf("[Вы %s]: %s\n", time.Now().Format("15:04"), text)
}

// --- Handshake ---

func (n *Node) createHandshakeBytes(ephPub *[32]byte) ([]byte, error) {
	privKey := n.host.Peerstore().PrivKey(n.host.ID())
	var nonce int64

	if err := binary.Read(rand.Reader, binary.LittleEndian, &nonce); err != nil {
		return nil, err
	}

	payload := HandshakePayload{
		Version:      ProtocolVersion,
		Timestamp:    time.Now().UnixNano(),
		Nonce:        nonce,
		NaClPubKey:   n.naclPublic[:],
		EphemeralPub: ephPub[:],
	}

	buf := new(bytes.Buffer)
	buf.WriteString(payload.Version)
	binary.Write(buf, binary.LittleEndian, payload.Timestamp)
	binary.Write(buf, binary.LittleEndian, payload.Nonce)
	buf.Write(payload.NaClPubKey)
	buf.Write(payload.EphemeralPub)

	sig, err := privKey.Sign(buf.Bytes())
	if err != nil {
		return nil, err
	}
	payload.Signature = sig

	return json.Marshal(payload)
}

func (n *Node) verifyHandshake(c *Contact, data []byte) (*[32]byte, error) {
	if len(data) > HandshakeLimit {
		return nil, errors.New("too large")
	}

	var payload HandshakePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	if payload.Version != ProtocolVersion {
		return nil, fmt.Errorf("version: %s", payload.Version)
	}

	if len(payload.EphemeralPub) != 32 {
		return nil, errors.New("bad eph key")
	}

	now := time.Now()
	ts := time.Unix(0, payload.Timestamp)
	if now.Sub(ts) > MaxTimeSkew || ts.Sub(now) > MaxTimeSkew {
		return nil, errors.New("time skew")
	}

	c.mu.Lock()
	if c.SeenNonces == nil {
		c.SeenNonces = make(map[int64]time.Time)
	}
	for k, t := range c.SeenNonces {
		if time.Since(t) > MaxTimeSkew {
			delete(c.SeenNonces, k)
		}
	}
	if len(c.SeenNonces) >= MaxNoncesPerContact {
		c.mu.Unlock()
		return nil, errors.New("flood")
	}
	if _, exists := c.SeenNonces[payload.Nonce]; exists {
		c.mu.Unlock()
		return nil, errors.New("replay")
	}
	c.SeenNonces[payload.Nonce] = time.Now()
	c.mu.Unlock()

	remotePub := n.host.Peerstore().PubKey(c.PeerID)
	if remotePub == nil {
		return nil, errors.New("no key")
	}

	buf := new(bytes.Buffer)
	buf.WriteString(payload.Version)
	binary.Write(buf, binary.LittleEndian, payload.Timestamp)
	binary.Write(buf, binary.LittleEndian, payload.Nonce)
	buf.Write(payload.NaClPubKey)
	buf.Write(payload.EphemeralPub)

	ok, _ := remotePub.Verify(buf.Bytes(), payload.Signature)
	if !ok {
		return nil, errors.New("bad sig")
	}

	var recKey [32]byte
	copy(recKey[:], payload.NaClPubKey)
	if recKey != c.PublicKey {
		return nil, errors.New("key mismatch")
	}

	var ephPub [32]byte
	copy(ephPub[:], payload.EphemeralPub)
	return &ephPub, nil
}

// --- Session ---

func (n *Node) sendSessionMessage(c *Contact, msgType, body string) error {
	c.mu.Lock()
	s := c.Stream
	sKey := c.sessionKey
	c.mu.Unlock()

	if s == nil || sKey == nil {
		return errors.New("no session")
	}

	msg := &InnerMessage{
		Type:      msgType,
		Timestamp: time.Now().UnixNano(),
		Content:   body,
	}

	encrypted, err := n.encryptSession(msg, sKey)
	if err != nil {
		return err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	if c.Stream != s {
		c.mu.Unlock()
		return errors.New("stream changed")
	}
	c.mu.Unlock()

	s.SetWriteDeadline(time.Now().Add(WriteTimeout))
	return n.writeFrame(s, encrypted)
}

func (n *Node) enterChat(id peer.ID) {
	n.mu.Lock()
	c := n.contacts[id]
	if c == nil {
		n.mu.Unlock()
		return
	}
	n.activeChat = id
	nick := c.Nickname
	n.mu.Unlock()

	n.updatePrompt()
	n.drawBox(fmt.Sprintf("ЧАТ: %s", nick), []string{
		"Forward Secrecy: ON",
		".leave - выход",
	})
}

func (n *Node) LeaveChat() {
	n.mu.Lock()
	id := n.activeChat
	n.activeChat = ""
	n.mu.Unlock()

	n.updatePrompt()

	if id == "" {
		n.SafePrintf("%s Вы не в чате\n", Style.Warning)
		return
	}

	c := n.getContactByID(id)
	if c != nil {
		n.sendSessionMessage(c, MsgTypeBye, "")
		n.closeStream(c)
		n.SafePrintf("%s Чат завершён\n", Style.OK)
	}
}

func (n *Node) closeStream(c *Contact) {
	c.mu.Lock()
	if c.Stream != nil {
		c.Stream.Close()
		c.Stream = nil
	}
	c.State = StateIdle
	c.Connecting = false

	if c.sessionKey != nil {
		for i := range c.sessionKey {
			c.sessionKey[i] = 0
		}
		c.sessionKey = nil
	}
	if c.localEphPriv != nil {
		for i := range c.localEphPriv {
			c.localEphPriv[i] = 0
		}
		c.localEphPriv = nil
	}
	c.localEphPub = nil
	c.remoteEphPub = nil
	c.sessionEstab = false
	c.mu.Unlock()
}

func (n *Node) handleDisconnect(c *Contact, err error) {
	c.mu.Lock()
	nick := c.Nickname
	pid := c.PeerID

	if c.Stream != nil {
		c.Stream.Close()
		c.Stream = nil
	}
	c.State = StateIdle
	c.Connecting = false

	if c.sessionKey != nil {
		for i := range c.sessionKey {
			c.sessionKey[i] = 0
		}
		c.sessionKey = nil
	}
	if c.localEphPriv != nil {
		for i := range c.localEphPriv {
			c.localEphPriv[i] = 0
		}
		c.localEphPriv = nil
	}
	c.localEphPub = nil
	c.remoteEphPub = nil
	c.sessionEstab = false
	c.mu.Unlock()

	n.mu.Lock()
	wasActive := n.activeChat == pid
	if wasActive {
		n.activeChat = ""
	}
	n.mu.Unlock()

	if wasActive {
		n.updatePrompt()
		n.SafePrintf("\n%s %s отключился\n", Style.Warning, nick)
	}
}

func (n *Node) Shutdown() {
	n.shutdownMu.Lock()
	if n.isShutdown {
		n.shutdownMu.Unlock()
		return
	}
	n.isShutdown = true
	n.shutdownMu.Unlock()

	fmt.Printf("\n%s Завершение...\n", Style.Info)

	n.cancel()

	// Закрываем канал
	select {
	case <-n.presenceChan:
	default:
		close(n.presenceChan)
	}

	// Закрываем соединения
	n.mu.RLock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.mu.RUnlock()

	for _, c := range contacts {
		n.sendSessionMessage(c, MsgTypeBye, "")
		n.closeStream(c)
	}

	n.SaveContacts()

	// Ждём goroutines с таймаутом
	done := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(ShutdownTimeout):
	}

	if n.rl != nil {
		n.rl.Close()
	}

	n.host.Close()
}

func (n *Node) ListContacts() {
	n.mu.RLock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.mu.RUnlock()

	var lines []string
	if len(contacts) == 0 {
		lines = append(lines, "(пусто)")
	}

	for _, c := range contacts {
		c.mu.Lock()
		state := c.State
		nick := c.Nickname
		hasStream := c.Stream != nil
		hasSession := c.sessionEstab
		presence := c.Presence
		lastSeen := c.LastSeen
		addrCount := c.AddressCount
		failCount := c.FailCount
		c.mu.Unlock()

		var icon, statusText string

		if hasStream && state == StateActive && hasSession {
			icon = Style.InChat
			statusText = "В ЧАТЕ"
		} else if hasStream && hasSession {
			icon = Style.Connected
			statusText = "CONNECTED"
		} else if state == StatePending {
			icon = Style.Pending
			statusText = "PENDING"
		} else {
			switch presence {
			case PresenceOnline:
				icon = Style.Online
				ago := time.Since(lastSeen).Round(time.Second)
				if addrCount > 0 {
					statusText = fmt.Sprintf("ONLINE (%d, %v)", addrCount, ago)
				} else {
					statusText = fmt.Sprintf("ONLINE (%v)", ago)
				}
			case PresenceOffline:
				icon = Style.Offline
				statusText = fmt.Sprintf("OFFLINE (%d)", failCount)
			case PresenceChecking:
				icon = Style.Searching
				statusText = "..."
			default:
				icon = Style.Unknown
				statusText = "?"
			}
		}

		lines = append(lines, fmt.Sprintf("%s %-12s %s", icon, nick, statusText))
	}

	n.drawBox("КОНТАКТЫ", lines)
}

func (n *Node) keepAliveLoop() {
	defer n.wg.Done()
	t := time.NewTicker(KeepAliveInterval)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
			n.mu.RLock()
			contacts := make([]*Contact, 0)
			for _, c := range n.contacts {
				contacts = append(contacts, c)
			}
			n.mu.RUnlock()

			for _, c := range contacts {
				c.mu.Lock()
				hasStream := c.Stream != nil
				hasSession := c.sessionEstab
				c.mu.Unlock()
				if hasStream && hasSession {
					n.sendSessionMessage(c, MsgTypePing, "")
				}
			}
		}
	}
}

func (n *Node) backgroundAdvertise() {
	defer n.wg.Done()

	select {
	case <-time.After(AdvertiseDelay):
	case <-n.ctx.Done():
		return
	}

	t := time.NewTicker(AdvertiseInterval)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
			if len(n.host.Network().Peers()) > 0 {
				n.discovery.Advertise(n.ctx, RendezvousString)
			}
		}
	}
}
