package samba

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/malivvan/samba/pkg/reuseport"
)

// Socket-level tests for the hardening added on review: the limits that keep one
// client from exhausting a shared resource, and the timeouts that keep a stalled
// client from holding one forever.

// TestServerRefusesBeyondMaxConnections checks that the connection cap refuses
// new connections instead of accepting work it cannot afford to serve.
func TestServerRefusesBeyondMaxConnections(t *testing.T) {
	dir := t.TempDir()
	srv := startTestServer(t, dir, func(cfg *Config) {
		one := 1
		cfg.MaxConnections = &one
	})
	addr := srv.Addr().String()

	first := dialTestClient(t, addr)
	first.establish(0x0302) // holds the only slot

	// The second connection is accepted at the TCP level, then closed by the
	// server because it is over the limit.
	second, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := second.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("the server must close a connection beyond max_connections")
	}

	// The first connection still works, and freeing it makes room again.
	if st, _ := first.read(0, 0, 1); st == StatusSuccess {
		t.Fatal("unexpected read success on an unused handle")
	}
	first.conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if srv.srv.conns.Count() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	third := dialTestClient(t, addr)
	third.establish(0x0302)
}

// TestServerReapsIncompleteFrame checks the frame-body timeout: a peer that
// announces a frame and then goes quiet must not hold a connection forever.
func TestServerReapsIncompleteFrame(t *testing.T) {
	old := frameBodyTimeout
	frameBodyTimeout = 100 * time.Millisecond
	t.Cleanup(func() { frameBodyTimeout = old })

	srv := startTestServer(t, t.TempDir(), nil)
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Announce a 1 MiB frame, then send one byte of it and stop.
	if _, err := conn.Write([]byte{0, 0x10, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0xFE}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the server must close a connection with an unfinished frame")
	}
}

func TestListenerRejectsBadAddress(t *testing.T) {
	// The listener creation lives in pkg/reuseport, which decides per platform
	// whether one socket or several are bound. An unusable address must be
	// reported the same way wherever the server runs.
	if _, err := reuseport.Listeners(2, "tcp", "not-an-address"); err == nil {
		t.Fatal("an invalid address must fail to bind")
	}
}

// TestServerStopIsIdempotent checks that shutdown can be requested twice, that a
// server that never started still stops cleanly, and that restarting a stopped
// server fails instead of leaving a worker nothing can shut down.
func TestServerStopIsIdempotent(t *testing.T) {
	srv, err := NewServer(testConfig(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	srv.Stop()
	srv.Stop()
	if srv.Addr() != nil {
		t.Fatal("a server that never started has no address")
	}
	if err := srv.Start(); err == nil {
		t.Fatal("starting a stopped server must fail rather than leak its workers")
	}

	// A normal lifecycle: start, serve, stop, wait.
	srv2, err := NewServer(testConfig(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv2.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	addr := srv2.Addr()
	if addr == nil {
		t.Fatal("a started server must report its address")
	}
	c := dialTestClient(t, addr.String())
	c.establish(0x0302)
	srv2.Stop()
	srv2.Wait()
	if n := srv2.Srv().conns.Count(); n != 0 {
		t.Fatalf("%d connections still counted after shutdown", n)
	}
}

// testConfig builds a minimal valid configuration for a temp share.
func testConfig(t *testing.T, dir string) *Config {
	t.Helper()
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Workers = 1
	cfg.LogLevel = LevelWarn
	cfg.Shares = []ShareCfg{{Name: "t", Path: dir}}
	return cfg
}

func TestDeliverBreakRouting(t *testing.T) {
	target := &conn{gen: 3, deferred: newDeferredQueue(), done: make(chan struct{})}
	w := &worker{id: 0, conns: map[int]*conn{2: target}}

	// A break for a live connection is queued for it.
	w.deliverBreak(BreakMsg{ConnIdx: 2, ConnGen: 3, SessionID: 9})
	if got := target.deferred.drain(); len(got) != 1 || got[0].brk == nil {
		t.Fatalf("break not delivered: %+v", got)
	}
	// A stale generation (the slot was recycled) is dropped.
	w.deliverBreak(BreakMsg{ConnIdx: 2, ConnGen: 4})
	if got := target.deferred.drain(); len(got) != 0 {
		t.Fatalf("a stale break must be dropped, got %+v", got)
	}
	// An unknown slot is dropped.
	w.deliverBreak(BreakMsg{ConnIdx: 9, ConnGen: 3})
	// A connection that is already closing is skipped.
	target.closingF.Store(true)
	w.deliverBreak(BreakMsg{ConnIdx: 2, ConnGen: 3})
	if got := target.deferred.drain(); len(got) != 0 {
		t.Fatalf("a closing connection must not be queued for, got %+v", got)
	}
	target.closingF.Store(false)
	// The guarded wrapper delegates (and would contain a panic).
	w.deliverBreakGuarded(BreakMsg{ConnIdx: 2, ConnGen: 3})
	if got := target.deferred.drain(); len(got) != 1 {
		t.Fatalf("guarded delivery failed: %+v", got)
	}
}

// socketPair returns two connected connections.
//
// This used to be a Unix socketpair. A loopback TCP pair replaces it so the
// transport tests run wherever the server does — the properties they need are
// two connected streams, a send buffer small enough to force a stall, and an
// orderly close, and a TCP connection has all three.
func socketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer ln.Close()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { a.Close(); r.c.Close() })
	return a, r.c
}

// setWriteBuffer shrinks a connection's send buffer, so a test can reach a full
// socket — and therefore a stalled transfer — in kilobytes rather than
// megabytes. A connection that will not take the setting is left alone: the
// tests that use it still assert the same outcome, just less promptly.
func setWriteBuffer(c net.Conn, size int) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetWriteBuffer(size)
	}
}

func TestWriteDeferredBreakAndNotify(t *testing.T) {
	local, peer := socketPair(t)
	pc := NewProtoConn(testSrv(t, t.TempDir(), nil), 0, 0, 1)
	pc.Channels[9] = &ChannelState{Sign: &SignCtx{Alg: SignAesCmac, Key: [16]byte{1}}}
	c := &conn{nc: local, pc: pc, deferred: newDeferredQueue()}

	// A lease break is built and written, and is signed because the session has
	// a signing context.
	c.writeDeferred(pendingFrame{brk: &BreakMsg{
		LeaseKey: [16]byte{1}, CurState: 1, NewState: 0, Epoch: 2, SessionID: 9,
	}})
	breakFrame := readNBTFrame(t, peer)
	if cmd := le16(breakFrame[12:14]); cmd != CmdOplockBreak {
		t.Fatalf("break command = %d", cmd)
	}
	if le32(breakFrame[16:20])&FlagSigned == 0 {
		t.Fatal("the break must be signed for a signing session")
	}

	// A CHANGE_NOTIFY completion for an active operation is written.
	pc.NotifyActive = [][2]uint64{{11, 22}}
	meta := AsyncMeta{MsgID: 5, SessionID: 9, AsyncID: 22, WantSign: true}
	c.writeDeferred(pendingFrame{notify: &notifyFired{
		pend:   NotifyPend{AsyncID: 22, OutLen: 4096, Meta: meta},
		status: StatusSuccess,
		events: []DirEvent{{Action: fileActionAdded, Name: "x"}},
	}})
	notifyFrame := readNBTFrame(t, peer)
	if cmd := le16(notifyFrame[12:14]); cmd != CmdChangeNotify {
		t.Fatalf("notify command = %d", cmd)
	}
	if le32(notifyFrame[16:20])&FlagSigned == 0 {
		t.Fatal("the notification must be signed when the session signs")
	}
	if len(pc.NotifyActive) != 0 {
		t.Fatal("the completed operation must be removed from the active set")
	}

	// A completion for an operation that is no longer active is dropped (the
	// cancel or close path already queued its own response).
	pc.NotifyActive = nil
	c.writeDeferred(pendingFrame{notify: &notifyFired{
		pend:   NotifyPend{AsyncID: 77, OutLen: 64, Meta: AsyncMeta{AsyncID: 77}},
		status: StatusSuccess,
	}})
	// Nothing was written: the peer sees a deadline instead.
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("a completion for an inactive operation must not be written")
	}

	// An empty pending frame is a no-op.
	if !c.writeDeferred(pendingFrame{}) {
		t.Fatal("an empty frame must succeed")
	}
}

// readNBTFrame reads one NetBIOS-framed message (without the length prefix).
func readNBTFrame(t *testing.T, c net.Conn) []byte {
	t.Helper()
	var nbt [4]byte
	if _, err := readFullConnFile(c, nbt[:]); err != nil {
		t.Fatalf("read the NBT prefix: %v", err)
	}
	n := int(nbt[1])<<16 | int(nbt[2])<<8 | int(nbt[3])
	frame := make([]byte, n)
	if _, err := readFullConnFile(c, frame); err != nil {
		t.Fatalf("read the frame (%d bytes): %v", n, err)
	}
	return frame
}

// readFullConnFile fills buf from a connection.
func readFullConnFile(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestDrainFramesStopsOnClosedChannel(t *testing.T) {
	ch := make(chan []byte)
	close(ch)
	c := &conn{frames: ch}
	if got := c.drainFrames(nil); len(got) != 0 {
		t.Fatalf("drained %+v from a closed channel", got)
	}
	// Frames that are already queued are taken.
	ch2 := make(chan []byte, 2)
	ch2 <- []byte("one")
	ch2 <- []byte("two")
	c2 := &conn{frames: ch2}
	got := c2.drainFrames(nil)
	if len(got) != 2 {
		t.Fatalf("drained %d frames, want 2", len(got))
	}
	// The batch limit is respected.
	ch3 := make(chan []byte, maxBatchFrames+5)
	for range maxBatchFrames + 5 {
		ch3 <- []byte("x")
	}
	c3 := &conn{frames: ch3}
	if got := c3.drainFrames(nil); len(got) != maxBatchFrames {
		t.Fatalf("drained %d frames, want the batch limit %d", len(got), maxBatchFrames)
	}
}

func TestServiceNotifyForwardsQueues(t *testing.T) {
	c := notifierConn()
	c.pc = &ProtoConn{Channels: map[uint64]*ChannelState{}}
	c.notifier = newNotifier(c)
	go c.notifier.run()
	defer c.notifier.stopNow()

	c.pc.NotifyNew = []NotifyPend{{AsyncID: 1, Path: t.TempDir(), OutLen: 64}}
	pc := c.pc
	c.serviceNotify()
	if pc.NotifyNew != nil {
		t.Fatal("the pending queue must be handed to the watcher")
	}
	pc.NotifyDone = []NotifyDone{{AsyncID: 1, Status: StatusCancelled}}
	c.serviceNotify()
	if pc.NotifyDone != nil {
		t.Fatal("the completion queue must be handed to the watcher")
	}
}

func TestServerServeAndStop(t *testing.T) {
	srv, err := NewServer(testConfig(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	// Wait for the listener to come up.
	deadline := time.Now().Add(10 * time.Second)
	for srv.Addr() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the server never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	c := dialTestClient(t, srv.Addr().String())
	c.establish(0x0302)
	srv.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after Stop")
	}
	if n := numCPU(); n < 1 {
		t.Fatalf("numCPU = %d", n)
	}
}

func TestZeroCopyShortReadOverSocket(t *testing.T) {
	// A zero-copy-sized read past EOF must be answered with END_OF_FILE rather
	// than dropping the connection, and a read straddling EOF returns the tail.
	dir := t.TempDir()
	payload := make([]byte, 200<<10)
	if err := os.WriteFile(filepath.Join(dir, "f.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	srv := startTestServer(t, dir, nil)
	c := dialTestClient(t, srv.Addr().String())
	c.establish(0x0302)
	st, fid := c.create("f.bin", fileOpen, 0x40, 0x8000_0000, nil)
	if st != StatusSuccess {
		t.Fatalf("create status %#x", st)
	}
	defer c.close(fid)

	// Entirely past EOF.
	if st, _ := c.read(fid, 1<<20, 64*1024); st != StatusEndOfFile {
		t.Fatalf("read past EOF status %#x, want END_OF_FILE", st)
	}
	// Straddling EOF: the tail is still served.
	st, got := c.read(fid, uint64(len(payload)-1024), 64*1024)
	if st != StatusSuccess {
		t.Fatalf("straddling read status %#x", st)
	}
	if len(got) != 1024 {
		t.Fatalf("straddling read returned %d bytes, want 1024", len(got))
	}
	// The connection is still usable afterwards.
	if st, _ := c.read(fid, 0, 4096); st != StatusSuccess {
		t.Fatalf("the connection was dropped after an EOF read (%#x)", st)
	}
}

func TestServerClosesOnUndecryptableTransform(t *testing.T) {
	srv := startTestServer(t, t.TempDir(), nil)
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A transform frame naming a session the server knows nothing about: it
	// cannot decrypt, so it must disconnect rather than leave the client
	// waiting for a response that will never come.
	frame := make([]byte, transformHdrLen+16)
	copy(frame[:4], transformProto)
	var nbt [4]byte
	nbt[1] = byte(len(frame) >> 16)
	nbt[2] = byte(len(frame) >> 8)
	nbt[3] = byte(len(frame))
	if _, err := conn.Write(nbt[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the server must close the connection")
	}
}

func TestLinkSpeedFallback(t *testing.T) {
	// A loopback interface with no /sys entry still advertises a fast link, so a
	// client is willing to open extra channels.
	if got := linkSpeedBps("definitely-not-an-interface", true); got != 100_000_000_000 {
		t.Fatalf("loopback fallback = %d", got)
	}
	if got := linkSpeedBps("definitely-not-an-interface", false); got != 10_000_000_000 {
		t.Fatalf("generic fallback = %d", got)
	}
	// A real interface reports its own speed when the kernel exposes one.
	if names, err := net.Interfaces(); err == nil {
		for _, n := range names {
			_ = linkSpeedBps(n.Name, n.Flags&net.FlagLoopback != 0)
		}
	}
}

func TestEncodeInterfaceInfoEmpty(t *testing.T) {
	if got := EncodeInterfaceInfo(nil); len(got) != 0 {
		t.Fatalf("an empty interface list encodes to %d bytes", len(got))
	}
}
