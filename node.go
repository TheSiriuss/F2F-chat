package main

import (
	"context"
	"sync"
	"time"

	"github.com/chzyer/readline"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
)

// Node represents the local P2P node
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

// Debug prints debug messages if enabled
func (n *Node) Debug(format string, a ...any) {
	if DebugMode {
		n.SafePrintf("[DEBUG] "+format+"\n", a...)
	}
}

// getContactByNick returns contact by nickname
func (n *Node) getContactByNick(nick string) *Contact {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if pid, ok := n.nickMap[nick]; ok {
		return n.contacts[pid]
	}
	return nil
}

// getContactByID returns contact by peer ID
func (n *Node) getContactByID(id peer.ID) *Contact {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.contacts[id]
}

// Shutdown gracefully stops the node
func (n *Node) Shutdown() {
	n.shutdownMu.Lock()
	if n.isShutdown {
		n.shutdownMu.Unlock()
		return
	}
	n.isShutdown = true
	n.shutdownMu.Unlock()

	n.SafePrintf("\n%s Завершение...\n", Style.Info)

	n.cancel()

	// Close presence channel
	select {
	case <-n.presenceChan:
	default:
		close(n.presenceChan)
	}

	// Close all connections
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

	// Wait for goroutines with timeout
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

// keepAliveLoop sends periodic pings to active sessions
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

// backgroundAdvertise periodically advertises presence in DHT
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
