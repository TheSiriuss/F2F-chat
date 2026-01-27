package f2f

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
)

type Node struct {
	host        host.Host
	dht         *dht.IpfsDHT
	discovery   *routing.RoutingDiscovery
	nickname    string
	password    string
	naclPublic  [32]byte
	naclPrivate [32]byte

	contacts map[peer.ID]*Contact
	nickMap  map[string]peer.ID

	activeChat peer.ID
	mu         sync.RWMutex
	wg         sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc

	presenceChan chan peer.ID

	listener UIListener

	isShutdown bool
	shutdownMu sync.Mutex
}

// --- Безопасные методы для работы с UI (Fix #6) ---

func (n *Node) notifyContactUpdate() {
	if n.listener != nil {
		n.listener.OnContactUpdate()
	}
}

func (n *Node) notifyChatChanged(pid, nick string) {
	if n.listener != nil {
		n.listener.OnChatChanged(pid, nick)
	}
}

func (n *Node) notifyMessage(pid, nick, text string, ts time.Time) {
	if n.listener != nil {
		n.listener.OnMessage(pid, nick, text, ts)
	}
}

func (n *Node) notifyFileOffer(pid, nick, filename string, size int64) {
	if n.listener != nil {
		n.listener.OnFileOffer(pid, nick, filename, size)
	}
}

func (n *Node) notifyFileProgress(pid, nick, filename string, progress float64, isUpload bool) {
	if n.listener != nil {
		n.listener.OnFileProgress(pid, nick, filename, progress, isUpload)
	}
}

func (n *Node) notifyFileReceived(pid, nick, filename, path string, size int64) {
	if n.listener != nil {
		n.listener.OnFileReceived(pid, nick, filename, path, size)
	}
}

func (n *Node) notifyFileComplete(pid, nick, filename string, success bool, msg string) {
	if n.listener != nil {
		n.listener.OnFileComplete(pid, nick, filename, success, msg)
	}
}

// --- Валидация (Fix #2) ---

func (n *Node) validateNickname(nick string) error {
	if len(nick) == 0 {
		return errors.New("никнейм не может быть пустым")
	}
	if len(nick) > MaxNickLength {
		return errors.New("никнейм слишком длинный")
	}
	// Дополнительно можно проверить на недопустимые символы
	if strings.TrimSpace(nick) == "" {
		return errors.New("никнейм не может состоять только из пробелов")
	}
	return nil
}

// --- Getters ---

func (n *Node) GetContacts() []*Contact {
	n.mu.RLock()
	defer n.mu.RUnlock()

	list := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		list = append(list, c)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Nickname < list[j].Nickname
	})

	return list
}

func (n *Node) GetActiveChat() peer.ID {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.activeChat
}

func (n *Node) GetHostID() string {
	return n.host.ID().String()
}

func (n *Node) GetNickname() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.nickname
}

func (n *Node) Log(level string, format string, a ...any) {
	if n.listener != nil {
		n.listener.OnLog(level, format, a...)
	}
}

// --- Lifecycle ---

func (n *Node) Shutdown() {
	n.shutdownMu.Lock()
	if n.isShutdown {
		n.shutdownMu.Unlock()
		return
	}
	n.isShutdown = true
	n.shutdownMu.Unlock()

	n.Log(LogLevelInfo, "Завершение...")
	n.cancel()

	select {
	case <-n.presenceChan:
	default:
		close(n.presenceChan)
	}

	n.mu.RLock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.mu.RUnlock()

	for _, c := range contacts {
		// Используем новый метод для закрытия (Fix #4)
		n.sendTerminalMessage(c, MsgTypeBye, nil)
	}

	n.SaveContacts()

	done := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(ShutdownTimeout):
		n.Log(LogLevelWarning, "Таймаут ожидания горутин")
	}

	n.host.Close()
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
					n.sendSessionMessage(c, MsgTypePing, nil)
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

func (n *Node) GetNetworkStatus() (int, bool) {
	if n.host == nil {
		return 0, false
	}

	connectedPeers := len(n.host.Network().Peers())
	hasRelay := false
	for _, addr := range n.host.Addrs() {
		if strings.Contains(addr.String(), "p2p-circuit") {
			hasRelay = true
			break
		}
	}
	return connectedPeers, hasRelay
}
