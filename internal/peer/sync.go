package peer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
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
	MsgHello     byte = 0x01
	MsgSyncReq   byte = 0x02
	MsgSyncResp  byte = 0x03
	MsgBlockPush byte = 0x04
	MsgCertReq   byte = 0x05 // request DER bytes for a cert_id
	MsgCertResp  byte = 0x06 // response carrying DER bytes (or found=false)
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
	ch        *chain.Chain
	table     *Table
	selfKey   [32]byte
	configDir string
	listener  net.Listener
	stop      chan struct{}
	wg        sync.WaitGroup

	// OnNewBlocks is called when a new candidate chain arrives from a peer.
	// The caller (daemon) should call chain.Replace with the candidate.
	OnNewBlocks func([]chain.Block)
}

// NewSyncer creates a Syncer. configDir is used to locate cached DER files for peer requests.
func NewSyncer(ch *chain.Chain, table *Table, selfKey [32]byte, configDir string) *Syncer {
	return &Syncer{
		ch:        ch,
		table:     table,
		selfKey:   selfKey,
		configDir: configDir,
		stop:      make(chan struct{}),
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

// SyncFromPeersAndWait syncs from all known peers and waits for completion or timeout.
func (s *Syncer) SyncFromPeersAndWait(timeout time.Duration) {
	peers := s.table.All()
	if len(peers) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p *Peer) {
			defer wg.Done()
			s.syncFromPeer(p)
		}(p)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Printf("sync: initial peer sync timed out after %v", timeout)
	}
}

// FetchDERFromPeers tries each known peer in turn until one returns the DER
// for the given cert_id hex string. Returns an error if no peer has it.
func (s *Syncer) FetchDERFromPeers(certIDHex string) ([]byte, error) {
	for _, p := range s.table.All() {
		der, err := s.fetchDERFromPeer(p, certIDHex)
		if err == nil && len(der) > 0 {
			return der, nil
		}
	}
	return nil, fmt.Errorf("DER not found on any peer for %s", certIDHex)
}

func (s *Syncer) fetchDERFromPeer(p *Peer, certIDHex string) ([]byte, error) {
	addr := net.JoinHostPort(p.Addr.IP.String(), fmt.Sprint(p.SyncPort))
	conn, err := net.DialTimeout("tcp", addr, syncTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(syncTimeout))

	req := struct {
		CertIDHex string `json:"cert_id_hex"`
	}{CertIDHex: certIDHex}
	if err := writeMsg(conn, MsgCertReq, req); err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(syncTimeout))
	msgType, data, err := readMsg(conn)
	if err != nil || msgType != MsgCertResp {
		return nil, fmt.Errorf("unexpected response from peer")
	}

	var resp struct {
		Found bool   `json:"found"`
		DER   []byte `json:"der,omitempty"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	if !resp.Found {
		return nil, fmt.Errorf("peer does not have DER")
	}
	return resp.DER, nil
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
		s.handleBlockPush(data, conn.RemoteAddr())
	case MsgCertReq:
		s.handleCertReq(conn, data)
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

func (s *Syncer) handleBlockPush(data []byte, remoteAddr net.Addr) {
	var b chain.Block
	if err := json.Unmarshal(data, &b); err != nil {
		return
	}
	if err := s.ch.AddBlock(b); err != nil {
		log.Printf("sync: pushed block rejected from %s: %v", remoteAddr, err)
		if host, _, splitErr := net.SplitHostPort(remoteAddr.String()); splitErr == nil {
			s.table.RecordFailureByIP(host)
		}
	}
}

func (s *Syncer) handleCertReq(conn net.Conn, data []byte) {
	var req struct {
		CertIDHex string `json:"cert_id_hex"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return
	}
	resp := struct {
		Found bool   `json:"found"`
		DER   []byte `json:"der,omitempty"`
	}{}
	derPath := filepath.Join(s.configDir, "certs", req.CertIDHex+".der")
	if der, err := os.ReadFile(derPath); err == nil {
		resp.Found = true
		resp.DER = der
	}
	conn.SetDeadline(time.Now().Add(syncTimeout))
	_ = writeMsg(conn, MsgCertResp, resp)
}

func (s *Syncer) pushBlock(p *Peer, b chain.Block) {
	addr := net.JoinHostPort(p.Addr.IP.String(), fmt.Sprint(p.SyncPort))
	conn, err := net.DialTimeout("tcp", addr, syncTimeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(syncTimeout))
	_ = writeMsg(conn, MsgBlockPush, b)
}

func (s *Syncer) syncFromPeer(p *Peer) {
	addr := net.JoinHostPort(p.Addr.IP.String(), fmt.Sprint(p.SyncPort))
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
