package peer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/amosdavis/certchain/internal/chain"
)

const (
	// SyncPort is the TCP port for certchain block sync (separate from addrchain's :9877).
	SyncPort = 9878

	syncTimeout   = 30 * time.Second
	maxMessageLen = 4 * 1024 * 1024 // 4 MiB per message
)

// Message type codes for the sync protocol.
const (
	MsgHello    byte = 0x01
	MsgSyncReq  byte = 0x02
	MsgSyncResp byte = 0x03
	MsgBlockPush byte = 0x04
)

// HelloMsg is sent on connect to establish chain identity and tip.
type HelloMsg struct {
	ChainID    [32]byte `json:"chain_id"`    // genesis block hash
	TipIndex   uint32   `json:"tip_index"`
	TipHash    [32]byte `json:"tip_hash"`
	NodePubKey [32]byte `json:"node_pub_key"`
}

// SyncReqMsg requests blocks from start_index to end_index (inclusive).
type SyncReqMsg struct {
	StartIndex uint32 `json:"start_index"`
	EndIndex   uint32 `json:"end_index"`
}

// SyncRespMsg carries the requested blocks.
type SyncRespMsg struct {
	Blocks []chain.Block `json:"blocks"`
}

// Syncer manages TCP block sync connections.
type Syncer struct {
	ch       *chain.Chain
	table    *Table
	selfKey  [32]byte
	listener net.Listener
	stop     chan struct{}
	wg       sync.WaitGroup

	// OnNewBlocks is called when a new candidate chain arrives from a peer.
	// The caller (daemon) should call chain.Replace with the candidate.
	OnNewBlocks func([]chain.Block)
}

// NewSyncer creates a Syncer.
func NewSyncer(ch *chain.Chain, table *Table, selfKey [32]byte) *Syncer {
	return &Syncer{
		ch:      ch,
		table:   table,
		selfKey: selfKey,
		stop:    make(chan struct{}),
	}
}

// Start begins listening for inbound sync connections.
func (s *Syncer) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", SyncPort))
	if err != nil {
		return fmt.Errorf("sync listen: %w", err)
	}
	s.listener = ln

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Stop shuts down the sync listener.
func (s *Syncer) Stop() {
	close(s.stop)
	s.listener.Close()
	s.wg.Wait()
}

// PushBlockToPeers sends a newly-mined block to all known peers.
func (s *Syncer) PushBlockToPeers(b chain.Block) {
	peers := s.table.All()
	for _, p := range peers {
		go s.pushBlock(p, b)
	}
}

// SyncFromPeers attempts to synchronise by pulling missing blocks from peers.
func (s *Syncer) SyncFromPeers() {
	peers := s.table.All()
	for _, p := range peers {
		go s.syncFromPeer(p)
	}
}

// ---- internal ----

func (s *Syncer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				log.Printf("sync: accept error: %v", err)
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *Syncer) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(syncTimeout))

	msgType, data, err := readMsg(conn)
	if err != nil {
		return
	}

	switch msgType {
	case MsgHello:
		s.handleHello(conn, data)
	case MsgBlockPush:
		s.handleBlockPush(data)
	default:
		log.Printf("sync: unknown message type 0x%02x from %s", msgType, conn.RemoteAddr())
	}
}

func (s *Syncer) handleHello(conn net.Conn, data []byte) {
	var hello HelloMsg
	if err := json.Unmarshal(data, &hello); err != nil {
		return
	}

	// Send our hello.
	tip := s.ch.Tip()
	ourHello := HelloMsg{
		ChainID:    s.ch.GenesisHash(),
		TipIndex:   tip.Index,
		TipHash:    tip.Hash,
		NodePubKey: s.selfKey,
	}
	if err := writeMsg(conn, MsgHello, ourHello); err != nil {
		return
	}

	// Read sync request.
	conn.SetDeadline(time.Now().Add(syncTimeout))
	msgType, data, err := readMsg(conn)
	if err != nil || msgType != MsgSyncReq {
		return
	}

	var req SyncReqMsg
	if err := json.Unmarshal(data, &req); err != nil {
		return
	}

	blocks := s.ch.GetBlocks()
	var resp []chain.Block
	for _, b := range blocks {
		if b.Index >= req.StartIndex && b.Index <= req.EndIndex {
			resp = append(resp, b)
		}
	}

	conn.SetDeadline(time.Now().Add(syncTimeout))
	_ = writeMsg(conn, MsgSyncResp, SyncRespMsg{Blocks: resp})
}

func (s *Syncer) handleBlockPush(data []byte) {
	var b chain.Block
	if err := json.Unmarshal(data, &b); err != nil {
		return
	}
	if err := s.ch.AddBlock(b); err != nil {
		log.Printf("sync: pushed block rejected: %v", err)
	}
}

func (s *Syncer) pushBlock(p *Peer, b chain.Block) {
	addr := fmt.Sprintf("%s:%d", p.Addr.IP, p.SyncPort)
	conn, err := net.DialTimeout("tcp", addr, syncTimeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(syncTimeout))
	_ = writeMsg(conn, MsgBlockPush, b)
}

func (s *Syncer) syncFromPeer(p *Peer) {
	addr := fmt.Sprintf("%s:%d", p.Addr.IP, p.SyncPort)
	conn, err := net.DialTimeout("tcp", addr, syncTimeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(syncTimeout))

	tip := s.ch.Tip()
	hello := HelloMsg{
		ChainID:    s.ch.GenesisHash(),
		TipIndex:   tip.Index,
		TipHash:    tip.Hash,
		NodePubKey: s.selfKey,
	}
	if err := writeMsg(conn, MsgHello, hello); err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(syncTimeout))
	msgType, data, err := readMsg(conn)
	if err != nil || msgType != MsgHello {
		return
	}

	var peerHello HelloMsg
	if err := json.Unmarshal(data, &peerHello); err != nil {
		return
	}

	// Only request blocks if peer is ahead.
	if peerHello.TipIndex <= tip.Index {
		return
	}

	req := SyncReqMsg{
		StartIndex: tip.Index + 1,
		EndIndex:   peerHello.TipIndex,
	}
	conn.SetDeadline(time.Now().Add(syncTimeout))
	if err := writeMsg(conn, MsgSyncReq, req); err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(syncTimeout))
	msgType, data, err = readMsg(conn)
	if err != nil || msgType != MsgSyncResp {
		return
	}

	var resp SyncRespMsg
	if err := json.Unmarshal(data, &resp); err != nil {
		return
	}

	if len(resp.Blocks) == 0 || s.OnNewBlocks == nil {
		return
	}

	// Prepend our local chain to build the full candidate.
	local := s.ch.GetBlocks()
	candidate := append(local, resp.Blocks...)
	s.OnNewBlocks(candidate)
}

// ---- wire framing: length(4 BE) + type(1) + payload ----

func writeMsg(conn net.Conn, msgType byte, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	total := 1 + len(data)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(total))
	_, err = conn.Write(hdr)
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte{msgType})
	if err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

func readMsg(conn net.Conn) (byte, []byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	total := binary.BigEndian.Uint32(hdr)
	if total == 0 || int(total) > maxMessageLen {
		return 0, nil, fmt.Errorf("sync: message size %d out of range", total)
	}
	buf := make([]byte, total)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}
