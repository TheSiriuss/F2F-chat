package main

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

// presenceLoop periodically queues presence checks
func (n *Node) presenceLoop() {
	defer n.wg.Done()

	// Initial delay
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

// presenceWorkerPool processes presence check requests
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

// ForceCheckAll resets and queues all contacts for presence check
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

// QueuePresenceChecks queues contacts that need presence check
func (n *Node) QueuePresenceChecks() {
	n.mu.RLock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.mu.RUnlock()

	for _, c := range contacts {
		c.mu.Lock()
		// Skip if already connected
		if c.Stream != nil {
			c.Presence = PresenceOnline
			c.LastSeen = time.Now()
			c.FailCount = 0
			c.mu.Unlock()
			continue
		}

		// Skip if not time yet
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

// checkSinglePresence checks presence of a single peer
func (n *Node) checkSinglePresence(pid peer.ID) {
	c := n.getContactByID(pid)
	if c == nil {
		return
	}

	// Check if already connected at network level
	if n.host.Network().Connectedness(pid) == network.Connected {
		c.mu.Lock()
		c.Presence = PresenceOnline
		c.LastSeen = time.Now()
		c.FailCount = 0
		c.NextCheckTime = time.Now().Add(PresenceInterval)
		c.mu.Unlock()
		return
	}

	// Query DHT
	ctx, cancel := context.WithTimeout(n.ctx, PresenceTimeout)
	defer cancel()

	info, err := n.dht.FindPeer(ctx, pid)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastChecked = time.Now()

	if err != nil {
		c.Presence = PresenceOffline
		c.FailCount++
		// Exponential backoff
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

	// Cache addresses
	if len(info.Addrs) > 0 {
		n.host.Peerstore().AddAddrs(pid, info.Addrs, peerstore.TempAddrTTL)
	}
}

// FindContact manually searches for a contact in DHT
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
