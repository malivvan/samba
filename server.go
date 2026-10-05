package samba

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Transport: SO_REUSEPORT listeners, one goroutine per connection, and a
// zero-copy READ path.
//
// This replaces the original io_uring reactor. The behavioural contract is the
// same — N workers each own a SO_REUSEPORT listener, every connection is
// served by a single serialized transmit stream, responses to all frames that
// arrived together are batched into one write, and large unsigned READs bypass
// userspace so file pages reach the socket through the kernel's splice path —
// but the mechanism is idiomatic Go: the runtime netpoller instead of a ring,
// goroutines instead of completion state machines.

// Transport tuning constants.
const (
	// txFlush is the accumulated-response size at which a batch is flushed
	// before processing more requests.
	txFlush = 1 << 20
	// maxFrame bounds an inbound NetBIOS-framed message.
	maxFrame = int(MaxTransact) + 0x11000
	// maxBatchFrames bounds how many coalesced frames are processed per wakeup.
	maxBatchFrames = 64
)

// pendingFrame is a server-initiated frame queued for a connection's own
// goroutine. Only that goroutine writes to the socket, so lease breaks and
// CHANGE_NOTIFY completions are queued rather than written directly.
type pendingFrame struct {
	brk    *BreakMsg
	notify *notifyFired
}

// deferredQueue is an unbounded, wakeable FIFO. It is the port of the reactor's
// per-connection deferred VecDeque: producers append from any goroutine, the
// owning connection drains it on its own goroutine.
type deferredQueue struct {
	mu     sync.Mutex
	q      []pendingFrame
	signal chan struct{}
}

func newDeferredQueue() *deferredQueue {
	return &deferredQueue{signal: make(chan struct{}, 1)}
}

func (d *deferredQueue) push(pf pendingFrame) {
	d.mu.Lock()
	d.q = append(d.q, pf)
	d.mu.Unlock()
	select {
	case d.signal <- struct{}{}:
	default:
	}
}

func (d *deferredQueue) drain() []pendingFrame {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.q
	d.q = nil
	return out
}

// Server is the running SMB server: one worker per configured listener, all
// sharing the same Srv context.
type Server struct {
	srv     *Srv
	workers []*worker
	stop    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

// NewServer resolves the configuration into a shared server context and one
// worker per configured listener, without binding anything yet.
func NewServer(cfg *Config) (*Server, error) {
	listenAddr, err := cfg.ListenAddr()
	if err != nil {
		return nil, err
	}
	users, err := cfg.UserDB()
	if err != nil {
		return nil, err
	}
	guid := [16]byte{}
	randBytes(guid[:])
	ifaces := EnumerateInterfaces()
	if len(cfg.AdvertiseOnly) > 0 {
		want := make(map[string]bool, len(cfg.AdvertiseOnly))
		for _, ip := range cfg.AdvertiseOnly {
			want[ip] = true
		}
		kept := ifaces[:0]
		for _, i := range ifaces {
			if want[i.Addr.String()] {
				kept = append(kept, i)
			}
		}
		ifaces = kept
	}
	nworkers := cfg.Workers
	if nworkers <= 0 {
		nworkers = numCPU()
	}
	mbs := make([]*Mailbox, nworkers)
	for i := range mbs {
		mbs[i] = NewMailbox()
	}
	srv := &Srv{
		cfg:        *cfg,
		guid:       guid,
		maxRead:    MaxReadTarget,
		startFT:    filetimeNow(),
		users:      users,
		allowGuest: cfg.GuestAllowed(),
		interfaces: ifaces,
		sessions:   NewRegistry(),
		mailboxes:  mbs,
		leases:     NewLeaseTable(),
	}
	s := &Server{srv: srv, stop: make(chan struct{})}
	for i := range nworkers {
		s.workers = append(s.workers, &worker{
			id:    i,
			srv:   srv,
			addr:  listenAddr,
			conns: make(map[int]*conn),
			gens:  make(map[int]uint16),
			stop:  s.stop,
		})
	}
	return s, nil
}

// Srv exposes the resolved shared context (used by tests).
func (s *Server) Srv() *Srv { return s.srv }

// Start binds every worker's listener and starts its accept loop.
func (s *Server) Start() error {
	for _, w := range s.workers {
		ln, err := listenReusePort(w.addr)
		if err != nil {
			s.Stop()
			return err
		}
		w.ln = ln
		s.wg.Add(1)
		go func(w *worker) {
			defer s.wg.Done()
			w.acceptLoop()
		}(w)
		s.wg.Add(1)
		go func(w *worker) {
			defer s.wg.Done()
			w.mailboxLoop()
		}(w)
	}
	return nil
}

// Addr returns the bound address of the first worker (tests bind :0 and read
// it back).
func (s *Server) Addr() net.Addr {
	if len(s.workers) == 0 || s.workers[0].ln == nil {
		return nil
	}
	return s.workers[0].ln.Addr()
}

// Serve starts the server and blocks until Stop is called.
func (s *Server) Serve() error {
	if err := s.Start(); err != nil {
		return err
	}
	s.wg.Wait()
	return nil
}

// Stop shuts down every listener and connection.
func (s *Server) Stop() {
	s.once.Do(func() {
		close(s.stop)
		for _, w := range s.workers {
			if w.ln != nil {
				w.ln.Close()
			}
			w.closeAll()
		}
	})
}

// Wait blocks until all workers have exited.
func (s *Server) Wait() { s.wg.Wait() }

// listenReusePort binds a TCP listener with SO_REUSEADDR + SO_REUSEPORT so every
// worker can share the same port and the kernel spreads connections across
// them.
func listenReusePort(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					serr = err
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					serr = err
				}
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}

// worker owns one SO_REUSEPORT listener and the connections accepted from it.
type worker struct {
	id   int
	srv  *Srv
	addr string
	ln   net.Listener

	mu    sync.Mutex
	conns map[int]*conn
	gens  map[int]uint16
	next  int
	free  []int

	stop chan struct{}
}

func (w *worker) acceptLoop() {
	for {
		nc, err := w.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-w.stop:
				return
			default:
			}
			// Transient failure (e.g. EMFILE): back off briefly and retry
			// rather than losing the worker.
			LogWarn("worker %d: accept failed: %v", w.id, err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if tc, ok := nc.(*net.TCPConn); ok {
			// SMB request/response benefits from disabling Nagle.
			_ = tc.SetNoDelay(true)
		}
		tcp, _ := nc.(*net.TCPConn)
		c := w.newConn(nc, tcp)
		LogDebug("worker %d: new connection (slot %d)", w.id, c.idx)
		go c.serve()
	}
}

// mailboxLoop delivers lease/oplock breaks posted by other workers.
func (w *worker) mailboxLoop() {
	mb := w.srv.mailboxes[w.id]
	for {
		select {
		case <-w.stop:
			return
		case <-mb.EventFd():
			for {
				msgs := mb.Drain()
				if len(msgs) == 0 {
					break
				}
				for _, b := range msgs {
					w.deliverBreak(b)
				}
			}
		}
	}
}

// deliverBreak routes a break to the connection that holds the lease, dropping
// it if the slot has been recycled or the connection is going away.
func (w *worker) deliverBreak(b BreakMsg) {
	w.mu.Lock()
	c := w.conns[b.ConnIdx]
	w.mu.Unlock()
	if c == nil || c.gen != b.ConnGen || c.closing() {
		return
	}
	brk := b
	c.deferred.push(pendingFrame{brk: &brk})
}

func (w *worker) newConn(nc net.Conn, tcp *net.TCPConn) *conn {
	w.mu.Lock()
	defer w.mu.Unlock()
	var idx int
	if n := len(w.free); n > 0 {
		idx = w.free[n-1]
		w.free = w.free[:n-1]
	} else {
		idx = w.next
		w.next++
		w.gens[idx] = 1
	}
	gen := w.gens[idx]
	c := &conn{
		w:        w,
		srv:      w.srv,
		nc:       nc,
		tcp:      tcp,
		idx:      idx,
		gen:      gen,
		pc:       NewProtoConn(w.srv, w.id, idx, gen),
		frames:   make(chan []byte, 64),
		deferred: newDeferredQueue(),
		done:     make(chan struct{}),
	}
	c.notifier = newNotifier(c)
	w.conns[idx] = c
	return c
}

// release recycles a connection slot, bumping its generation so stale lease
// references miss cleanly.
func (w *worker) release(idx int, c *conn) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conns[idx] != c {
		return
	}
	delete(w.conns, idx)
	w.gens[idx]++
	if w.gens[idx] == 0 {
		w.gens[idx] = 1
	}
	w.free = append(w.free, idx)
}

func (w *worker) closeAll() {
	w.mu.Lock()
	conns := make([]*conn, 0, len(w.conns))
	for _, c := range w.conns {
		conns = append(conns, c)
	}
	w.mu.Unlock()
	for _, c := range conns {
		c.shutdown()
	}
}

// conn is one accepted TCP connection, served end to end by a single goroutine
// for the transmit direction.
type conn struct {
	w   *worker
	srv *Srv
	nc  net.Conn
	// tcp is the typed connection, required by the zero-copy splice path.
	tcp *net.TCPConn
	idx int
	gen uint16
	pc  *ProtoConn
	// frames carries complete NetBIOS-framed messages from the reader.
	frames chan []byte
	// deferred holds server-initiated frames, drained by this connection's
	// goroutine (the only writer to the socket).
	deferred *deferredQueue
	notifier *notifier
	done     chan struct{}
	closingF atomic.Bool
	closeOne sync.Once
}

func (c *conn) closing() bool { return c.closingF.Load() }

func (c *conn) deferFrame(pf pendingFrame) { c.deferred.push(pf) }

// serve drives the connection: read frames, process them in batches, write the
// batched responses, and interleave server-initiated frames. It returns when
// the peer goes away, the peer closes, or a protocol-level failure requires a
// disconnect.
func (c *conn) serve() {
	defer c.teardown()
	go c.notifier.run()
	go c.readLoop()

	tx := NewWriter(4096)
	var pending *ZcReadPlan
	for {
		// Flush buffered responses, then any queued server-initiated frames.
		if tx.Len() > 0 {
			if !c.write(tx.Bytes()) {
				return
			}
			tx.Truncate(0)
		}
		if pending != nil {
			if !c.sendRead(pending) {
				return
			}
			pending = nil
			continue
		}
		if !c.flushDeferred() {
			return
		}
		select {
		case f, ok := <-c.frames:
			if !ok {
				return
			}
			plan, keep := c.processBatch(f, tx)
			if !keep {
				return
			}
			pending = plan
		case <-c.deferred.signal:
			// Loop around to drain; nothing else to do.
		case <-c.done:
			return
		}
	}
}

// processBatch processes the first frame plus any coalesced frames already
// waiting, batching their responses into tx. It stops early when a frame
// requires a zero-copy reply or a batch flush.
func (c *conn) processBatch(first []byte, tx *Writer) (*ZcReadPlan, bool) {
	frames := [][]byte{first}
loop:
	for len(frames) < maxBatchFrames {
		select {
		case f, ok := <-c.frames:
			if !ok {
				break loop
			}
			frames = append(frames, f)
		default:
			break loop
		}
	}
	for _, f := range frames {
		act, plan := ProcessFrame(c.srv, c.pc, f, tx)
		c.serviceNotify()
		switch act {
		case actionClose:
			// An undecryptable encrypted frame (e.g. guest + seal):
			// disconnect rather than leave the client hanging.
			return nil, false
		case actionZcRead:
			return plan, true
		}
		if tx.Len() >= txFlush {
			break
		}
	}
	return nil, true
}

// serviceNotify hands the protocol layer's notify queues to the watcher.
func (c *conn) serviceNotify() {
	if n := len(c.pc.NotifyNew); n > 0 {
		for i := range c.pc.NotifyNew {
			p := c.pc.NotifyNew[i]
			c.notifier.add(&p)
		}
		c.pc.NotifyNew = nil
	}
	if n := len(c.pc.NotifyDone); n > 0 {
		for _, d := range c.pc.NotifyDone {
			c.notifier.complete(d)
		}
		c.pc.NotifyDone = nil
	}
}

// sendRead serves a validated zero-copy READ: it writes the response header and
// then copies the file's bytes straight to the socket, which the Go runtime
// performs with the kernel splice path (no userspace copy of the file data).
func (c *conn) sendRead(plan *ZcReadPlan) bool {
	n := plan.Length
	if !plan.Linked {
		fi, err := plan.File.Stat()
		if err != nil {
			return c.writeReadErr(plan, statusFromErr(err))
		}
		size := uint64(fi.Size())
		if plan.Offset >= size {
			n = 0
		} else {
			n = uint32(min(uint64(plan.Length), size-plan.Offset))
		}
	}
	if n == 0 || n < plan.MinCount {
		return c.writeReadErr(plan, StatusEndOfFile)
	}
	hdr := NewWriter(0)
	BuildReadRespPrefix(plan, n, hdr)
	if !c.write(hdr.Bytes()) {
		return false
	}
	// Stream the payload straight from the file to the socket. Reads are
	// addressed by offset, so the handle's own position is never touched.
	if err := spliceFileToConn(c.tcp, plan.File, int64(plan.Offset), int(n)); err != nil {
		// The header already promised n bytes, so the response stream is
		// unusable: drop the connection.
		LogDebug("zerocopy: read failed (%v)", err)
		return false
	}
	return true
}

func (c *conn) writeReadErr(plan *ZcReadPlan, st uint32) bool {
	tx := NewWriter(0)
	BuildReadErr(plan, st, tx)
	return c.write(tx.Bytes())
}

// flushDeferred writes every queued server-initiated frame.
func (c *conn) flushDeferred() bool {
	for {
		items := c.deferred.drain()
		if len(items) == 0 {
			return true
		}
		for _, pf := range items {
			if !c.writeDeferred(pf) {
				return false
			}
		}
	}
}

func (c *conn) writeDeferred(pf pendingFrame) bool {
	switch {
	case pf.brk != nil:
		var sign *SignCtx
		if ch := c.pc.Channel(pf.brk.SessionID); ch != nil {
			sign = ch.Sign
		}
		frame := BuildLeaseBreak(
			&pf.brk.LeaseKey,
			pf.brk.CurState,
			pf.brk.NewState,
			pf.brk.Epoch,
			pf.brk.SessionID,
			sign,
		)
		LogDebug("lease: break state %d->%d", pf.brk.CurState, pf.brk.NewState)
		return c.write(frame)
	case pf.notify != nil:
		nf := pf.notify
		if nf.status == StatusSuccess && !c.removeNotifyActive(nf.pend.AsyncID) {
			// The pend was cancelled or its handle closed in the meantime; the
			// completion for that path is already queued.
			return true
		}
		c.removeNotifyActive(nf.pend.AsyncID)
		frame := BuildNotifyFinal(c.pc, &nf.pend.Meta, nf.status, nf.events, nf.pend.OutLen)
		LogDebug("notify complete aid=%d st=%#x events=%d", nf.pend.AsyncID, nf.status, len(nf.events))
		return c.write(frame)
	default:
		return true
	}
}

// removeNotifyActive drops a pended async operation from the live set, reporting
// whether it was present.
func (c *conn) removeNotifyActive(asyncID uint64) bool {
	for i, e := range c.pc.NotifyActive {
		if e[1] == asyncID {
			c.pc.NotifyActive = append(c.pc.NotifyActive[:i], c.pc.NotifyActive[i+1:]...)
			return true
		}
	}
	return false
}

// readLoop frames inbound NetBIOS session messages and hands them to the
// connection goroutine.
func (c *conn) readLoop() {
	defer close(c.frames)
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(c.nc, hdr[:]); err != nil {
			return
		}
		// Only NetBIOS session messages are legal on direct TCP 445; anything
		// else means the stream is desynchronized.
		if hdr[0] != 0 {
			return
		}
		flen := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		if flen > maxFrame {
			return
		}
		frame := make([]byte, flen)
		if _, err := io.ReadFull(c.nc, frame); err != nil {
			return
		}
		select {
		case c.frames <- frame:
		case <-c.done:
			return
		}
	}
}

func (c *conn) write(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	_, err := c.nc.Write(b)
	return err == nil
}

// shutdown makes the peer and this goroutine (if parked) unwind.
func (c *conn) shutdown() {
	c.closeOne.Do(func() {
		c.closingF.Store(true)
		close(c.done)
		c.nc.Close()
	})
}

// teardown releases everything the connection owned: leases, notifications,
// session channels, and its worker slot.
func (c *conn) teardown() {
	c.shutdown()
	c.notifier.stopNow()
	c.srv.leases.ReleaseConn(c.w.id, c.idx, c.gen)
	for sid := range c.pc.Channels {
		c.srv.dropChannel(sid)
	}
	c.pc.Channels = map[uint64]*ChannelState{}
	c.w.release(c.idx, c)
	LogDebug("worker %d: connection closed (slot %d)", c.w.id, c.idx)
}

// dropChannel decrements a session's channel count and tears the session down
// when its last channel goes away, so an abrupt disconnect cannot leak handles.
func (s *Srv) dropChannel(sid uint64) {
	sess, ok := s.sessions.Get(sid)
	if !ok {
		return
	}
	sess.Lock()
	if sess.Channels > 0 {
		sess.Channels--
	}
	drop := sess.Channels == 0
	sess.Unlock()
	if !drop {
		return
	}
	if dropped, ok := s.sessions.Remove(sid); ok {
		dropped.Lock()
		dropped.Handles.CloseAll()
		dropped.Unlock()
	}
}

// numCPU reports the number of usable CPUs for the default worker count.
func numCPU() int { return runtime.NumCPU() }
