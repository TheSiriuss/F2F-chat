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
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
)

type Node struct {
	host        host.Host
	dht         *dht.IpfsDHT
	discovery   *routing.RoutingDiscovery
	nickname   string
	password   string
	naclPublic [32]byte

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

// GetContactState returns the ChatState of the given nickname, or StateIdle
// if the contact doesn't exist. Thread-safe via contact mutex.
func (n *Node) GetContactState(nick string) ChatState {
	c := n.getContactByNick(nick)
	if c == nil {
		return StateIdle
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.State
}

// GetCallState returns the current CallState for the contact with the
// given nickname, or CallIdle if there's no contact / no call. Thread-safe.
func (n *Node) GetCallState(nick string) CallState {
	c := n.getContactByNick(nick)
	if c == nil {
		return CallIdle
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Call == nil {
		return CallIdle
	}
	return c.Call.State
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

// libp2pKeepAliveLoop sends a libp2p Ping to every direct-connected
// contact every Libp2pKeepAliveInterval. This is CRITICAL for UDP/QUIC
// connections — home routers drop inactive UDP NAT mappings at around
// 30 s, and when that mapping dies libp2p silently falls back to the
// relay circuit. Ping traffic keeps the NAT path "alive" so the direct
// connection survives idle periods.
//
// Only pings contacts we've explicitly added — not random libp2p peers
// (bootstrap, relay clients etc). Only pings DIRECT (non-circuit) conns
// — there's no point refreshing a relay path, and pinging over relay
// just burns the relay-bandwidth budget for nothing.
func (n *Node) libp2pKeepAliveLoop() {
	defer n.wg.Done()
	t := time.NewTicker(Libp2pKeepAliveInterval)
	defer t.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
			n.mu.RLock()
			pids := make([]peer.ID, 0, len(n.contacts))
			for pid := range n.contacts {
				pids = append(pids, pid)
			}
			n.mu.RUnlock()

			for _, pid := range pids {
				// Protect contact peers from connmgr eviction. Idempotent;
				// calling every tick ensures newly-connected contacts
				// get marked without a separate event hook.
				if cm := n.host.ConnManager(); cm != nil {
					cm.Protect(pid, "f2f-contact")
				}

				// If currently only on relay, try to upgrade to direct.
				// This catches the common "two clients on same LAN but
				// initial connect landed on circuit because identify
				// hadn't propagated LAN addrs yet" case. Also covers
				// hole-punch retries — libp2p's auto DCUtR gives up
				// after a few attempts, ours keeps trying every 20 s.
				if !n.hasDirectConn(pid) {
					// Only try upgrade if we're actually connected at
					// all (limited or not). Offline peers are skipped.
					if n.host.Network().Connectedness(pid) != network.NotConnected {
						go n.forceDirectDial(pid)
					}
					continue // skip ping on relay — wastes circuit bytes
				}

				// Direct conn exists — keep the NAT mapping warm.
				// Fire-and-forget ping with a short timeout; we don't
				// care about latency, just that a packet went out.
				go func(p peer.ID) {
					ctx, cancel := context.WithTimeout(n.ctx, 3*time.Second)
					defer cancel()
					res := <-libp2pPingOnce(ctx, n.host, p)
					_ = res.Error
				}(pid)
			}
		}
	}
}

// libp2pPingOnce wraps libp2p's ping.Ping for a single round-trip.
// Returns a channel that fires once with the result.
func libp2pPingOnce(ctx context.Context, h host.Host, p peer.ID) <-chan ping.Result {
	return ping.Ping(ctx, h, p)
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

// GetNetworkStatus returns (connected-peer count, usingRelay).
//
// usingRelay semantics — "at least one of my CONTACTS is reachable only
// via relay, with no direct path". Specifically:
//
//  1. Only inspect connections to peers that are in our contact list.
//     Random libp2p peers (bootstrap/autorelay clients) don't matter.
//  2. For each contact: if they have ZERO direct conns but at least one
//     circuit conn → they're relay-only → flag.
//  3. If contacts have BOTH direct and circuit (common: libp2p keeps
//     both for redundancy after hole-punch), we're still direct; don't
//     flag — libp2p will prefer direct for sub-protocol streams.
func (n *Node) GetNetworkStatus() (int, bool) {
	if n.host == nil {
		return 0, false
	}

	n.mu.RLock()
	contactIDs := make(map[peer.ID]struct{}, len(n.contacts))
	for pid := range n.contacts {
		contactIDs[pid] = struct{}{}
	}
	n.mu.RUnlock()

	peers := n.host.Network().Peers()
	usingRelay := false
	for _, p := range peers {
		if _, isContact := contactIDs[p]; !isContact {
			continue
		}
		hasDirect := false
		hasRelay := false
		for _, c := range n.host.Network().ConnsToPeer(p) {
			if strings.Contains(c.RemoteMultiaddr().String(), "p2p-circuit") {
				hasRelay = true
			} else {
				hasDirect = true
			}
		}
		// Only flag when truly relay-only — no direct path exists.
		if hasRelay && !hasDirect {
			usingRelay = true
			break
		}
	}
	return len(peers), usingRelay
}
