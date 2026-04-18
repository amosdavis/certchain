// Package peer manages certchain peer discovery (UDP :9876) and block sync (TCP :9878).
//
// Discovery shares the UDP port with addrchain, distinguished by CAP_CERTCHAIN=0x04
// in the announce capabilities byte. Sync uses a separate TCP port so both
// blockchains can run on the same host without port conflict.
package peer

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const (
	// DiscoveryPort is shared with addrchain; CAP_CERTCHAIN distinguishes us.
	DiscoveryPort = 9876
	// CAP_CERTCHAIN is the capabilities bit advertised in UDP announce payloads.
	CAP_CERTCHAIN = 0x04

	announceInterval = 30 * time.Second
	peerTimeout      = 90 * time.Second
	announceVersion  = 1
	// UDP announce payload size: version(1) + capabilities(1) + sync_port(2) + pubkey(32) = 36
	announceSize = 36
)

// Peer holds information about a discovered certchain peer.
type Peer struct {
	Addr     *net.UDPAddr
	PubKey   [32]byte // node public key
	SyncPort uint16   // TCP port for block sync
	LastSeen time.Time
}

// Table is a thread-safe table of known peers.
type Table struct {
	mu    sync.RWMutex
	peers map[string]*Peer // key = addr string
}

// NewTable creates an empty peer table.
func NewTable() *Table {
	return &Table{peers: make(map[string]*Peer)}
}

// Upsert adds or updates a peer entry.
func (t *Table) Upsert(p *Peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[p.Addr.String()] = p
}

// Remove removes a peer by address string.
func (t *Table) Remove(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.peers, addr)
}

// All returns a snapshot of all known peers.
func (t *Table) All() []*Peer {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*Peer, 0, len(t.peers))
	for _, p := range t.peers {
		out = append(out, p)
	}
	return out
}

// Count returns the number of known peers.
func (t *Table) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.peers)
}

// Discoverer sends and receives UDP announce messages.
type Discoverer struct {
	table    *Table
	conn     *net.UDPConn
	selfKey  [32]byte
	syncPort uint16
	stop     chan struct{}
	wg       sync.WaitGroup
}

// NewDiscoverer creates a Discoverer. selfKey is the node's public key;
// syncPort is the TCP port used for block sync.
func NewDiscoverer(table *Table, selfKey [32]byte, syncPort uint16) *Discoverer {
	return &Discoverer{
		table:    table,
		selfKey:  selfKey,
		syncPort: syncPort,
		stop:     make(chan struct{}),
	}
}

// Start opens the UDP socket and begins announce/listen loops.
func (d *Discoverer) Start() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", DiscoveryPort))
	if err != nil {
		return fmt.Errorf("resolve discovery addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	d.conn = conn

	d.wg.Add(2)
	go d.listenLoop()
	go d.announceLoop()
	return nil
}

// Stop shuts down the discovery loops.
func (d *Discoverer) Stop() {
	close(d.stop)
	d.conn.Close()
	d.wg.Wait()
}

func (d *Discoverer) listenLoop() {
	defer d.wg.Done()
	buf := make([]byte, 256)
	for {
		n, addr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.stop:
				return
			default:
				log.Printf("peer: UDP read error: %v", err)
				continue
			}
		}
		d.handleAnnounce(buf[:n], addr)
	}
}

func (d *Discoverer) announceLoop() {
	defer d.wg.Done()
	bcast, err := net.ResolveUDPAddr("udp", fmt.Sprintf("255.255.255.255:%d", DiscoveryPort))
	if err != nil {
		log.Printf("peer: resolve broadcast: %v", err)
		return
	}

	ticker := time.NewTicker(announceInterval)
	defer ticker.Stop()

	// Send immediately on start.
	d.sendAnnounce(bcast)

	for {
		select {
		case <-ticker.C:
			d.sendAnnounce(bcast)
			d.evictStale()
		case <-d.stop:
			return
		}
	}
}

func (d *Discoverer) sendAnnounce(dst *net.UDPAddr) {
	payload := buildAnnounce(d.selfKey, d.syncPort)
	if _, err := d.conn.WriteToUDP(payload, dst); err != nil {
		log.Printf("peer: send announce: %v", err)
	}
}

func (d *Discoverer) handleAnnounce(data []byte, from *net.UDPAddr) {
	if len(data) < announceSize {
		return
	}
	version := data[0]
	if version != announceVersion {
		return
	}
	caps := data[1]
	if caps&CAP_CERTCHAIN == 0 {
		return // not a certchain peer
	}

	syncPort := binary.BigEndian.Uint16(data[2:4])
	var pubkey [32]byte
	copy(pubkey[:], data[4:36])

	// Skip self-announce.
	if pubkey == d.selfKey {
		return
	}

	peer := &Peer{
		Addr:     from,
		PubKey:   pubkey,
		SyncPort: syncPort,
		LastSeen: time.Now(),
	}
	d.table.Upsert(peer)
}

func (d *Discoverer) evictStale() {
	d.table.mu.Lock()
	defer d.table.mu.Unlock()
	cutoff := time.Now().Add(-peerTimeout)
	for addr, p := range d.table.peers {
		if p.LastSeen.Before(cutoff) {
			delete(d.table.peers, addr)
		}
	}
}

// buildAnnounce creates the UDP announce payload.
// Format: version(1) + capabilities(1) + sync_port(2 BE) + pubkey(32) = 36 bytes
func buildAnnounce(pubkey [32]byte, syncPort uint16) []byte {
	buf := make([]byte, announceSize)
	buf[0] = announceVersion
	buf[1] = CAP_CERTCHAIN
	binary.BigEndian.PutUint16(buf[2:4], syncPort)
	copy(buf[4:36], pubkey[:])
	return buf
}
