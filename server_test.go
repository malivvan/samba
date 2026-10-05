package samba

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// End-to-end tests over a real TCP socket: they drive the full server
// (listeners, framing, batching, the zero-copy read path, notifier and lease
// break delivery) the way a real SMB client does.

// startTestServer boots a server on an ephemeral port with a single worker so
// the bound address can be read back deterministically.
func startTestServer(tb testing.TB, dir string, tune func(*Config)) *Server {
	t := tb
	t.Helper()
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Workers = 1
	cfg.ServerName = "TESTSRV"
	cfg.LogLevel = LevelWarn
	cfg.Oplocks = true
	cfg.Shares = []ShareCfg{{Name: "t", Path: dir}}
	if tune != nil {
		tune(cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.Stop()
		srv.Wait()
	})
	return srv
}

// testClient is a minimal SMB2 client speaking NetBIOS framing over TCP. It is
// shared by the socket-level tests and the end-to-end benchmarks.
type testClient struct {
	t     testing.TB
	conn  net.Conn
	msgID uint64
	sess  uint64
	tree  uint32
}

func dialTestClient(tb testing.TB, addr string) *testClient {
	t := tb
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &testClient{t: t, conn: conn}
}

func (c *testClient) nextID() uint64 {
	c.msgID++
	return c.msgID
}

// exchange writes one NBT-framed request and reads the response frame.
func (c *testClient) exchange(frame []byte, tree uint32) resp {
	c.t.Helper()
	if err := c.writeFrame(frame); err != nil {
		c.t.Fatal(err)
	}
	_ = tree
	return c.readResp()
}

func (c *testClient) writeFrame(frame []byte) error {
	var nbt [4]byte
	n := len(frame)
	nbt[1] = byte(n >> 16)
	nbt[2] = byte(n >> 8)
	nbt[3] = byte(n)
	if _, err := c.conn.Write(nbt[:]); err != nil {
		return err
	}
	_, err := c.conn.Write(frame)
	return err
}

func (c *testClient) readFrame() ([]byte, error) {
	var nbt [4]byte
	if _, err := io.ReadFull(c.conn, nbt[:]); err != nil {
		return nil, err
	}
	n := int(nbt[1])<<16 | int(nbt[2])<<8 | int(nbt[3])
	frame := make([]byte, n)
	if _, err := io.ReadFull(c.conn, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func (c *testClient) readResp() resp {
	c.t.Helper()
	frame, err := c.readFrame()
	if err != nil {
		c.t.Fatal(err)
	}
	if len(frame) < 64 {
		c.t.Fatalf("short response (%d bytes)", len(frame))
	}
	h := frame[:64]
	return resp{
		status:    le32(h[8:12]),
		flags:     le32(h[16:20]),
		treeID:    le32(h[36:40]),
		sessionID: le64(h[40:48]),
		body:      append([]byte{}, frame[64:]...),
	}
}

// establish performs NEGOTIATE → SESSION_SETUP (anonymous → guest) → TREE_CONNECT.
func (c *testClient) establish(dialect uint16) {
	c.t.Helper()
	f := reqHdr(CmdNegotiate, c.nextID(), 0, 0)
	f.U16(36)
	f.U16(2)
	f.U16(1)
	f.U16(0)
	f.U32(0)
	f.Zeros(16 + 8)
	f.U16(0x0210)
	f.U16(dialect)
	r := c.exchange(f.Bytes(), 0)
	if r.status != StatusSuccess {
		c.t.Fatalf("negotiate status %#x", r.status)
	}

	// An empty security buffer is an anonymous SESSION_SETUP.
	f = reqHdr(CmdSessionSetup, c.nextID(), 0, 0)
	f.U16(25)
	f.U8(0)
	f.U8(1)
	f.U32(0)
	f.U32(0)
	f.U16(88)
	f.U16(0)
	f.U64(0)
	r = c.exchange(f.Bytes(), 0)
	if r.status != StatusSuccess {
		c.t.Fatalf("session setup status %#x", r.status)
	}
	c.sess = r.sessionID

	path := UTF16LE(`\\srv\t`)
	f = reqHdr(CmdTreeConnect, c.nextID(), 0, c.sess)
	f.U16(9)
	f.U16(0)
	f.U16(72)
	f.U16(uint16(len(path)))
	f.Bytes8(path)
	r = c.exchange(f.Bytes(), 0)
	if r.status != StatusSuccess {
		c.t.Fatalf("tree connect status %#x", r.status)
	}
	c.tree = r.treeID
}

func (c *testClient) create(name string, disp, opts, desired uint32, ctx []byte) (uint32, uint64) {
	c.t.Helper()
	n := UTF16LE(name)
	f := reqHdr(CmdCreate, c.nextID(), c.tree, c.sess)
	f.U16(57)
	f.U8(0)
	f.U8(0)
	f.U32(2)
	f.U64(0)
	f.U64(0)
	f.U32(desired)
	f.U32(0)
	f.U32(7)
	f.U32(disp)
	f.U32(opts)
	f.U16(120)
	f.U16(uint16(len(n)))
	if len(ctx) > 0 {
		// CreateContextsOffset is measured from the SMB2 header start.
		f.U32(64 + 56 + uint32(len(n)) + uint32(pad8(len(n))))
		f.U32(uint32(len(ctx)))
	} else {
		f.U32(0)
		f.U32(0)
	}
	f.Bytes8(n)
	if pad := pad8(len(n)); pad > 0 {
		f.Zeros(pad)
	}
	f.Bytes8(ctx)
	r := c.exchange(f.Bytes(), c.tree)
	var fid uint64
	if r.status == StatusSuccess {
		fid = le64(r.body[72:80])
	}
	return r.status, fid
}

func pad8(n int) int {
	if rem := (64 + 56 + n) % 8; rem != 0 {
		return 8 - rem
	}
	return 0
}

func (c *testClient) write(fid uint64, off uint64, data []byte) uint32 {
	c.t.Helper()
	f := reqHdr(CmdWrite, c.nextID(), c.tree, c.sess)
	f.U16(49)
	f.U16(112)
	f.U32(uint32(len(data)))
	f.U64(off)
	f.U64(fid)
	f.U64(fid)
	f.U32(0)
	f.U32(0)
	f.U16(0)
	f.U16(0)
	f.U32(0)
	f.Bytes8(data)
	return c.exchange(f.Bytes(), c.tree).status
}

func (c *testClient) read(fid uint64, off uint64, length uint32) (uint32, []byte) {
	c.t.Helper()
	f := reqHdr(CmdRead, c.nextID(), c.tree, c.sess)
	f.U16(49)
	f.U8(0)
	f.U8(0)
	f.U32(length)
	f.U64(off)
	f.U64(fid)
	f.U64(fid)
	f.U32(0)
	f.U32(0)
	f.U32(0)
	f.U16(0)
	f.U16(0)
	f.U8(0)
	r := c.exchange(f.Bytes(), c.tree)
	if r.status != StatusSuccess {
		return r.status, nil
	}
	n := int(le32(r.body[4:8]))
	if len(r.body) < 16+n {
		c.t.Fatalf("read body is %d bytes, need %d", len(r.body), 16+n)
	}
	return r.status, r.body[16 : 16+n]
}

func (c *testClient) close(fid uint64) uint32 {
	c.t.Helper()
	f := reqHdr(CmdClose, c.nextID(), c.tree, c.sess)
	f.U16(24)
	f.U16(1)
	f.U32(0)
	f.U64(fid)
	f.U64(fid)
	return c.exchange(f.Bytes(), c.tree).status
}

func TestServerEndToEnd(t *testing.T) {
	dir := t.TempDir()
	srv := startTestServer(t, dir, nil)
	c := dialTestClient(t, srv.Addr().String())
	c.establish(0x0302)

	// CREATE + WRITE + READ through the real socket.
	st, fid := c.create("hello.bin", fileOverwriteIf, 0x40, 0x1000_0000, nil)
	if st != StatusSuccess {
		t.Fatalf("create status %#x", st)
	}
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	if st := c.write(fid, 0, payload); st != StatusSuccess {
		t.Fatalf("write status %#x", st)
	}
	if st := c.close(fid); st != StatusSuccess {
		t.Fatalf("close status %#x", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "hello.bin")); err != nil {
		t.Fatalf("the file must exist on disk: %v", err)
	}

	st, fid = c.create("hello.bin", fileOpen, 0x40, 0x8000_0000, nil)
	if st != StatusSuccess {
		t.Fatalf("reopen status %#x", st)
	}
	st, got := c.read(fid, 0, 4096)
	if st != StatusSuccess {
		t.Fatalf("read status %#x", st)
	}
	if string(got) != string(payload) {
		t.Fatal("payload mismatch")
	}
	if st := c.close(fid); st != StatusSuccess {
		t.Fatalf("close status %#x", st)
	}

	// QUERY_DIRECTORY over the socket.
	st, dfid := c.create("", fileOpen, 0x1, 0x8000_0000, nil)
	if st != StatusSuccess {
		t.Fatalf("open root status %#x", st)
	}
	pat := UTF16LE("*")
	f := reqHdr(CmdQueryDirectory, c.nextID(), c.tree, c.sess)
	f.U16(33)
	f.U8(fileIDBothDirectoryInformation)
	f.U8(0)
	f.U32(0)
	f.U64(dfid)
	f.U64(dfid)
	f.U16(96)
	f.U16(uint16(len(pat)))
	f.U32(65536)
	f.Bytes8(pat)
	r := c.exchange(f.Bytes(), c.tree)
	if r.status != StatusSuccess {
		t.Fatalf("query directory status %#x", r.status)
	}
	if !containsBytes(r.body, UTF16LE("hello.bin")) {
		t.Fatal("the listing must contain hello.bin")
	}
	if st := c.close(dfid); st != StatusSuccess {
		t.Fatalf("close root status %#x", st)
	}
}

func containsBytes(hay, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// TestServerZeroCopyRead drives a read large enough to take the zero-copy
// path (header write + kernel splice from the file to the socket).
func TestServerZeroCopyRead(t *testing.T) {
	dir := t.TempDir()
	const size = 512 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	srv := startTestServer(t, dir, nil)
	c := dialTestClient(t, srv.Addr().String())
	c.establish(0x0302)

	st, fid := c.create("big.bin", fileOpen, 0x40, 0x8000_0000, nil)
	if st != StatusSuccess {
		t.Fatalf("create status %#x", st)
	}
	defer c.close(fid)

	// A 64 KiB read is above the zero-copy threshold. The offsets are visited
	// out of order (and one of them twice) on purpose: the zero-copy path must
	// read at exactly the offset the request names, and must not advance any
	// handle position that a later read would accidentally inherit.
	order := []int{size - 64*1024, 0, 4 * 64 * 1024, 0, 2 * 64 * 1024}
	for _, off := range order {
		st, got := c.read(fid, uint64(off), 64*1024)
		if st != StatusSuccess {
			t.Fatalf("read at %d status %#x", off, st)
		}
		if string(got) != string(payload[off:off+64*1024]) {
			t.Fatalf("payload mismatch at offset %d", off)
		}
	}
	// Interleave a buffered (positional) read, then a zero-copy one, to prove
	// the two paths agree on the handle state.
	if st, got := c.read(fid, 1024, 4096); st != StatusSuccess || string(got) != string(payload[1024:1024+4096]) {
		t.Fatalf("buffered read at 1024 status %#x", st)
	}
	if st, got := c.read(fid, 3*64*1024, 64*1024); st != StatusSuccess || string(got) != string(payload[3*64*1024:3*64*1024+64*1024]) {
		t.Fatalf("zero-copy read at %d status %#x", 3*64*1024, st)
	}
	// A read that starts past EOF must report end-of-file.
	if st, _ := c.read(fid, size+4096, 4096); st != StatusEndOfFile {
		t.Fatalf("read past EOF status %#x, want END_OF_FILE", st)
	}
}

// TestServerIoctl and the interface advertisement: a client asks which
// interfaces it may stripe across.
func TestServerIoctl(t *testing.T) {
	dir := t.TempDir()
	srv := startTestServer(t, dir, func(cfg *Config) { cfg.Multichannel = true })
	c := dialTestClient(t, srv.Addr().String())
	c.establish(0x0302)

	for _, ctl := range []uint32{fsctlValidateNegotiateInfo, fsctlQueryNetworkInterfaceInfo} {
		f := reqHdr(CmdIoctl, c.nextID(), c.tree, c.sess)
		f.U16(57)
		f.U16(0)
		f.U32(ctl)
		f.Zeros(16) // FileId
		f.U32(0)
		f.U32(0)
		f.U32(112)
		f.U32(0)
		f.U32(112)
		f.U32(0)
		f.U32(0)
		f.U32(0)
		r := c.exchange(f.Bytes(), c.tree)
		if r.status != StatusSuccess {
			t.Fatalf("ioctl %#x status %#x", ctl, r.status)
		}
		// The fixed IOCTL response is 48 bytes: StructureSize(2) Reserved(2)
		// CtlCode(4) FileId(16) InputOffset(4) InputCount(4) OutputOffset(4)
		// OutputCount(4) Flags(4) Reserved2(4).
		outCount := int(le32(r.body[36:40]))
		if len(r.body) < 48+outCount {
			t.Fatalf("ioctl %#x body is %d bytes, need %d", ctl, len(r.body), 48+outCount)
		}
		out := r.body[48 : 48+outCount]
		if ctl == fsctlValidateNegotiateInfo {
			if len(out) != 24 {
				t.Fatalf("validate-negotiate output is %d bytes", len(out))
			}
			// Layout: Capabilities(4) Guid(16) SecurityMode(2) Dialect(2).
			if secmode := le16(out[20:22]); secmode&securityModeSigningEnabled == 0 {
				t.Fatalf("echoed security mode = %#x", secmode)
			}
			if dialect := le16(out[22:24]); dialect != 0x0302 {
				t.Fatalf("echoed dialect = %#x", dialect)
			}
		} else if len(out)%152 != 0 {
			// Each interface entry is 24 bytes of header plus 128 of SOCKADDR.
			t.Fatalf("interface output is %d bytes, not a multiple of 152", len(out))
		}
	}
}

// TestServerChangeNotify exercises the notifier: a pended CHANGE_NOTIFY must
// complete asynchronously when the directory it watches changes.
func TestServerChangeNotify(t *testing.T) {
	dir := t.TempDir()
	srv := startTestServer(t, dir, nil)
	c := dialTestClient(t, srv.Addr().String())
	c.establish(0x0302)

	st, dfid := c.create("", fileOpen, 0x1, 0x8000_0000, nil)
	if st != StatusSuccess {
		t.Fatalf("open root status %#x", st)
	}
	defer c.close(dfid)

	// Pend the notification (STATUS_PENDING interim response).
	f := reqHdr(CmdChangeNotify, c.nextID(), c.tree, c.sess)
	f.U16(32)
	f.U16(0) // no WATCH_TREE
	f.U32(65536)
	f.U64(dfid)
	f.U64(dfid)
	f.U32(0x1F) // any change
	r := c.exchange(f.Bytes(), c.tree)
	if r.status != StatusPending {
		t.Fatalf("change notify status %#x, want STATUS_PENDING", r.status)
	}

	// Change the directory; the completion arrives out-of-band.
	if err := os.WriteFile(filepath.Join(dir, "created.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := c.readFrame()
	if err != nil {
		t.Fatalf("the notify completion must arrive: %v", err)
	}
	if got := le16(frame[12:14]); got != CmdChangeNotify {
		t.Fatalf("completion command = %d", got)
	}
	if got := le32(frame[8:12]); got != StatusSuccess {
		t.Fatalf("completion status = %#x", got)
	}
	if le32(frame[16:20])&FlagAsync == 0 {
		t.Fatal("the completion must be flagged async")
	}
	body := frame[64:]
	if got := le16(body[0:2]); got != 9 {
		t.Fatalf("notify StructureSize = %d", got)
	}
	outLen := int(le32(body[4:8]))
	if outLen <= 0 || !containsBytes(body[8:8+outLen], UTF16LE("created.txt")) {
		t.Fatalf("notify payload must name created.txt")
	}
}

// TestServerLeaseBreak drives two sessions: one holds a read-caching lease, the
// other writes the file, and the holder must receive a lease break.
func TestServerLeaseBreak(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shared.bin"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := startTestServer(t, dir, nil)
	addr := srv.Addr().String()

	holder := dialTestClient(t, addr)
	holder.establish(0x0302)
	writer := dialTestClient(t, addr)
	writer.establish(0x0302)

	// The holder requests a read-caching (+handle-caching) lease.
	var key [16]byte
	for i := range key {
		key[i] = 0x5A
	}
	leaseData := NewWriter(0)
	leaseData.Bytes8(key[:])
	leaseData.U32(LeaseReadCaching | LeaseHandleCaching)
	leaseData.U32(0) // flags
	leaseData.U64(0) // duration
	if leaseData.Len() != 32 {
		t.Fatalf("v1 lease request is %d bytes", leaseData.Len())
	}
	st, hfid := holder.create("shared.bin", fileOpen, 0x40, 0x8000_0000, rqlsCtx(leaseData.Bytes()))
	if st != StatusSuccess {
		t.Fatalf("lease open status %#x", st)
	}
	srv.Srv().leases.mu.Lock()
	grants := len(srv.Srv().leases.m)
	srv.Srv().leases.mu.Unlock()
	if grants == 0 {
		t.Fatal("the lease must be registered")
	}

	// The other session opens for writing; that must break the holder's lease.
	st, wfid := writer.create("shared.bin", fileOpen, 0x40, genericWrite, nil)
	if st != StatusSuccess {
		t.Fatalf("writer open status %#x", st)
	}
	if st := writer.write(wfid, 0, []byte("changed!")); st != StatusSuccess {
		t.Fatalf("write status %#x", st)
	}
	if st := writer.close(wfid); st != StatusSuccess {
		t.Fatalf("writer close status %#x", st)
	}

	// The holder must receive an OPLOCK_BREAK notification for its lease key.
	if err := holder.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := holder.readFrame()
	if err != nil {
		t.Fatalf("the lease break must arrive: %v", err)
	}
	if got := le16(frame[12:14]); got != CmdOplockBreak {
		t.Fatalf("break command = %d, want OPLOCK_BREAK", got)
	}
	if got := le64(frame[24:32]); got != ^uint64(0) {
		t.Fatalf("break MessageId = %#x", got)
	}
	body := frame[64:]
	if got := le16(body[0:2]); got != 44 {
		t.Fatalf("break StructureSize = %d", got)
	}
	if string(body[8:24]) != string(key[:]) {
		t.Fatal("the break must carry the holder's lease key")
	}
	if got := le32(body[24:28]); got != LeaseReadCaching|LeaseHandleCaching {
		t.Fatalf("CurrentLeaseState = %#x", got)
	}
	if got := le32(body[28:32]); got != 0 {
		t.Fatalf("NewLeaseState = %#x, want none", got)
	}
	if st := holder.close(hfid); st != StatusSuccess {
		t.Fatalf("holder close status %#x", st)
	}
}

// TestServerPipelinedRequests checks that several requests coalesced into one
// TCP segment are answered in order and with well-formed framing.
func TestServerPipelinedRequests(t *testing.T) {
	dir := t.TempDir()
	srv := startTestServer(t, dir, nil)
	c := dialTestClient(t, srv.Addr().String())
	c.establish(0x0302)

	// Write three ECHO requests back to back, then read three responses.
	const n = 3
	var buf []byte
	for range n {
		echo := reqHdr(CmdEcho, c.nextID(), 0, c.sess)
		echo.U16(4)
		echo.U16(0)
		body := echo.Bytes()
		var nbt [4]byte
		binary.BigEndian.PutUint32(nbt[:], 0)
		nbt[1] = byte(len(body) >> 16)
		nbt[2] = byte(len(body) >> 8)
		nbt[3] = byte(len(body))
		buf = append(buf, nbt[:]...)
		buf = append(buf, body...)
	}
	if _, err := c.conn.Write(buf); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		frame, err := c.readFrame()
		if err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		if got := le16(frame[12:14]); got != CmdEcho {
			t.Fatalf("response %d command = %d", i, got)
		}
		if got := le32(frame[8:12]); got != StatusSuccess {
			t.Fatalf("response %d status = %#x", i, got)
		}
	}
}

// TestServerRejectsBadFraming checks that a stream that is not NetBIOS session
// framing is dropped instead of interpreted.
func TestServerRejectsBadFraming(t *testing.T) {
	dir := t.TempDir()
	srv := startTestServer(t, dir, nil)
	c := dialTestClient(t, srv.Addr().String())
	// A non-zero first byte is not a NetBIOS session message.
	if _, err := c.conn.Write([]byte{0x01, 0, 0, 4, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.readFrame(); err == nil {
		t.Fatal("the server must close a desynchronized connection")
	}
}
