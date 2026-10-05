package samba

import (
	"errors"
	"io"
	"net"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/malivvan/samba/pkg/reuseport"
	"github.com/malivvan/samba/pkg/zerocopy"
)

// Transport: shared listeners, one goroutine per connection, and a READ path
// that avoids copying the file's bytes where the platform allows it.
//
// This replaces the original io_uring reactor. The behavioural contract is the
// same — N workers each accept independently, every connection is served by a
// single serialized transmit stream, responses to all frames that arrived
// together are batched into one write, and large unsigned READs bypass userspace
// so file pages reach the socket through the kernel's own copy path — but the
// mechanism is idiomatic Go: the runtime netpoller instead of a ring, goroutines
// instead of completion state machines.
//
// The two platform-dependent pieces are not coded here. pkg/reuseport decides
// whether the workers get one socket each (SO_REUSEPORT, so the kernel balances
// the accepts) or share one, and pkg/zerocopy chooses between splice(2),
// sendfile(2) and a buffered copy. This file only ever sees a net.Listener and a
// net.Conn, which is what keeps the transport itself portable.

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

// frameBodyTimeout bounds how long a peer may take to finish a frame it has
// started. It is generous enough for a slow link sending a multi-megabyte write,
// and it stops a peer from holding a connection (and its buffers) forever with a
// truncated frame. An idle connection is unaffected: the timeout is only armed
// once a frame's length is known.
//
// It is a variable rather than a constant only so tests can shorten it.
var frameBodyTimeout = 5 * time.Minute

// stallTimeout bounds how long a peer may stall a response with no progress at
// all (a zero receive window, or a peer that stopped reading). It is reset by
// any progress, so a slow-but-moving client is never disconnected.
var stallTimeout = 5 * time.Minute

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
	ifaces := AdvertisedInterfaces(cfg.AdvertiseOnly)
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
	maxConns := DefaultMaxConnections
	if cfg.MaxConnections != nil {
		maxConns = *cfg.MaxConnections
	}
	srv.conns = newConnLimiter(maxConns)
	s := &Server{srv: srv, stop: make(chan struct{})}
	for i := range nworkers {
		s.workers = append(s.workers, &worker{
			id:    i,
			srv:   srv,
			addr:  listenAddr,
			wg:    &s.wg,
			conns: make(map[int]*conn),
			gens:  make(map[int]uint16),
			stop:  s.stop,
		})
	}
	return s, nil
}

// Srv exposes the resolved shared context (used by tests).
func (s *Server) Srv() *Srv { return s.srv }

// Start binds the listeners and starts every worker's accept loop.
//
// It reports an error if the server has already been stopped: starting workers
// that nothing will ever shut down would leave Wait blocked forever.
//
// How many sockets there are depends on the platform, and pkg/reuseport decides
// it: with SO_REUSEPORT every worker gets its own socket on the same address and
// the kernel balances accepts between them, and without it — Windows has no
// equivalent — one socket is shared by all the accept loops. Either way every
// worker accepts independently, so the only difference is whether the kernel or
// the runtime's accept mutex does the spreading.
func (s *Server) Start() error {
	select {
	case <-s.stop:
		return errors.New("samba: the server has already been stopped")
	default:
	}
	listeners, err := reuseport.Listeners(len(s.workers), "tcp", s.workers[0].addr)
	if err != nil {
		s.Stop()
		return err
	}
	for i, w := range s.workers {
		// One socket means every worker shares it; several mean each worker owns
		// one, in order.
		w.setListener(listeners[i%len(listeners)])
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
	if len(s.workers) == 0 {
		return nil
	}
	ln := s.workers[0].listener()
	if ln == nil {
		return nil
	}
	return ln.Addr()
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
			if ln := w.listener(); ln != nil {
				ln.Close()
			}
			w.closeAll()
		}
	})
}

// Wait blocks until every worker and every connection goroutine has finished.
func (s *Server) Wait() { s.wg.Wait() }

// worker owns one SO_REUSEPORT listener and the connections accepted from it.
type worker struct {
	id   int
	srv  *Srv
	addr string
	ln   net.Listener
	// wg is the server's WaitGroup, so Wait covers connection goroutines too and
	// not just the accept loops.
	wg *sync.WaitGroup

	mu    sync.Mutex
	conns map[int]*conn
	gens  map[int]uint16
	next  int
	free  []int

	stop chan struct{}
}

// setListener publishes this worker's bound listener.
func (w *worker) setListener(ln net.Listener) {
	w.mu.Lock()
	w.ln = ln
	w.mu.Unlock()
}

// listener returns this worker's listener, or nil before it is bound. The field
// is written by Start and read by Addr and Stop, so it needs the lock.
func (w *worker) listener() net.Listener {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ln
}

func (w *worker) acceptLoop() {
	for w.acceptOnce() {
	}
}

// acceptOnce accepts and starts one connection, reporting whether the worker
// should keep serving. It is a separate function so that a panic while handling
// one connection cannot end the worker: the panic is logged and the loop
// continues.
func (w *worker) acceptOnce() (keepGoing bool) {
	keepGoing = true
	defer func() {
		if r := recover(); r != nil {
			LogWarn("worker %d: panic while accepting: %v\n%s", w.id, r, debug.Stack())
			time.Sleep(50 * time.Millisecond)
		}
	}()
	ln := w.listener()
	if ln == nil {
		return false
	}
	nc, err := ln.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return false
		}
		select {
		case <-w.stop:
			return false
		default:
		}
		// Transient failure (e.g. EMFILE): back off briefly and retry rather
		// than losing the worker.
		LogWarn("worker %d: accept failed: %v", w.id, err)
		time.Sleep(50 * time.Millisecond)
		return true
	}
	// Refuse rather than accept a connection the server cannot afford to serve:
	// each one costs goroutines and buffered request bytes.
	if !w.srv.conns.Acquire() {
		LogWarn("worker %d: refusing connection: %d already served (max_connections)",
			w.id, w.srv.conns.Count())
		nc.Close()
		return true
	}
	started := false
	defer func() {
		if !started {
			// The connection never reached its own teardown (an error path or a
			// panic here), so give the slot back on its behalf.
			w.srv.conns.Release()
			nc.Close()
		}
	}()
	if tc, ok := nc.(*net.TCPConn); ok {
		// SMB request/response benefits from disabling Nagle.
		_ = tc.SetNoDelay(true)
	}
	c := w.newConn(nc)
	LogDebug("worker %d: new connection (slot %d)", w.id, c.idx)
	started = true
	if w.wg != nil {
		w.wg.Add(1)
	}
	go func() {
		if w.wg != nil {
			defer w.wg.Done()
		}
		c.serve()
	}()
	return true
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
					w.deliverBreakGuarded(b)
				}
			}
		}
	}
}

// deliverBreakGuarded delivers one break, containing a panic to this worker
// rather than letting it end the process.
func (w *worker) deliverBreakGuarded(b BreakMsg) {
	defer func() {
		if r := recover(); r != nil {
			LogWarn("worker %d: panic delivering a lease break: %v\n%s", w.id, r, debug.Stack())
		}
	}()
	w.deliverBreak(b)
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

func (w *worker) newConn(nc net.Conn) *conn {
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
		idx:      idx,
		gen:      gen,
		pc:       NewProtoConn(w.srv, w.id, idx, gen),
		frames:   make(chan []byte, 64),
		rxBudget: newBudget(maxQueuedRxBytes),
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
	idx int
	gen uint16
	pc  *ProtoConn
	// frames carries complete NetBIOS-framed messages from the reader.
	frames chan []byte
	// rxBudget bounds the request bytes this connection holds while they wait to
	// be processed, and rxHeld is how many the reader has reserved; teardown
	// hands them back.
	rxBudget *budget
	rxHeld   atomic.Int64
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
	c.guard("connection", c.serveLoop)
}

// guard runs fn, converting a panic into a logged teardown of this one
// connection. A file server must not have a reachable single point of failure:
// without this, one malformed frame that trips a bug would take the whole
// process (and every other client) down with it.
//
// The handler itself is written defensively — it must not be possible for the
// recovery path to panic in turn, or the containment would be worthless.
func (c *conn) guard(where string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			worker := -1
			if c.w != nil {
				worker = c.w.id
			}
			LogWarn("worker %d slot %d: panic in %s: %v\n%s", worker, c.idx, where, r, debug.Stack())
			if c.done != nil {
				c.shutdown()
			}
		}
	}()
	fn()
}

// serveLoop is the connection's driver: it reads frames, processes them in
// batches, writes the batched responses, and interleaves server-initiated
// frames. It returns when the peer goes away, the peer closes, or a
// protocol-level failure requires a disconnect.
func (c *conn) serveLoop() {
	go c.guard("notifier", c.notifier.run)
	go c.guard("reader", c.readLoop)

	tx := NewWriter(4096)
	var (
		zc      *ZcReadPlan
		backlog [][]byte
	)
	// A plan that is produced but never served (because the connection is torn
	// down first) still holds a reference to its handle: give it back.
	defer func() {
		if zc != nil {
			zc.release()
		}
	}()
	for {
		// Flush buffered responses, then any queued server-initiated frames.
		if tx.Len() > 0 {
			if !c.write(tx.Bytes()) {
				LogDebug("slot %d: driver ending: response write failed", c.idx)
				return
			}
			tx.Truncate(0)
		}
		if zc != nil {
			if !c.sendRead(zc) {
				LogDebug("slot %d: driver ending: zero-copy read failed", c.idx)
				return
			}
			zc = nil
			continue
		}
		if !c.flushDeferred() {
			LogDebug("slot %d: driver ending: deferred frame write failed", c.idx)
			return
		}
		if len(backlog) == 0 {
			select {
			case f, ok := <-c.frames:
				if !ok {
					LogDebug("slot %d: driver ending: reader finished", c.idx)
					return
				}
				backlog = append(backlog, f)
				backlog = c.drainFrames(backlog)
			case <-c.deferred.signal:
				continue
			case <-c.done:
				return
			}
		}
		var closeConn bool
		backlog, zc, closeConn = c.processBacklog(backlog, tx)
		if closeConn {
			LogDebug("slot %d: driver ending: the protocol layer asked to close", c.idx)
			return
		}
	}
}

// drainFrames takes whatever further frames are already waiting, up to a batch.
func (c *conn) drainFrames(into [][]byte) [][]byte {
	for len(into) < maxBatchFrames {
		select {
		case f, ok := <-c.frames:
			if !ok {
				return into
			}
			into = append(into, f)
		default:
			return into
		}
	}
	return into
}

// processBacklog processes up to a batch of queued frames into tx. It stops at
// a zero-copy read plan (which the transport serves next) or when the response
// batch reaches the flush watermark. Either way the frames it did not process
// are returned to the caller: a client is waiting for a response to every frame
// it sent, so dropping the rest of a batch would stall it until it timed out.
func (c *conn) processBacklog(backlog [][]byte, tx *Writer) ([][]byte, *ZcReadPlan, bool) {
	n := 0
	for n < len(backlog) && n < maxBatchFrames {
		frame := backlog[n]
		act, plan := ProcessFrame(c.srv, c.pc, frame, tx)
		n++
		// The frame is done with: hand its memory reservation back so the
		// reader can take more requests in.
		c.releaseFrame(len(frame))
		c.serviceNotify()
		switch act {
		case actionClose:
			// An undecryptable encrypted frame (e.g. guest + seal):
			// disconnect rather than leave the client hanging.
			return nil, nil, true
		case actionZcRead:
			return dropFrames(backlog, n), plan, false
		}
		if tx.Len() >= txFlush {
			break
		}
	}
	return dropFrames(backlog, n), nil, false
}

// dropFrames removes the first n frames from backlog, reusing its storage.
func dropFrames(backlog [][]byte, n int) [][]byte {
	if n >= len(backlog) {
		return backlog[:0]
	}
	return append(backlog[:0], backlog[n:]...)
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

// sendRead serves a validated READ: it writes the response header and then hands
// the file's bytes to pkg/zerocopy, which moves them with the kernel's own copy
// path where the platform has one (splice(2) on Linux, sendfile(2) on macOS and
// the BSDs) and through a bounded userspace buffer where it does not.
func (c *conn) sendRead(plan *ZcReadPlan) bool {
	// The plan holds a reference to its handle (taken under the session lock) so
	// a concurrent CLOSE cannot close the descriptor mid-read. Give it back on
	// every path out of here.
	defer plan.release()
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
	// Stream the payload from the file to the socket. Reads are addressed by
	// offset, so the handle's own position is never touched.
	if err := zerocopy.Send(c.nc, plan.File, int64(plan.Offset), int(n), stallTimeout); err != nil {
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
			LogDebug("slot %d: reader ending: %v", c.idx, err)
			return
		}
		// Only NetBIOS session messages are legal on direct TCP 445; anything
		// else means the stream is desynchronized.
		if hdr[0] != 0 {
			LogDebug("slot %d: reader ending: not a NetBIOS session message (%#x)", c.idx, hdr[0])
			return
		}
		flen := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		if flen > maxFrame {
			LogDebug("slot %d: reader ending: frame of %d bytes exceeds %d", c.idx, flen, maxFrame)
			return
		}
		// Reserve the frame's memory *before* allocating it, so a peer that
		// stops reading its responses cannot make the server buffer unboundedly:
		// once this connection's budget is spent the reader waits here, leaving
		// the rest of the request in the socket (where the kernel already bounds
		// it) instead of in the heap.
		if !c.rxBudget.Acquire(flen, c.closing) {
			LogDebug("slot %d: reader ending: could not reserve %d bytes (used %d)",
				c.idx, flen, c.rxBudget.Used())
			return
		}
		c.rxHeld.Add(int64(flen))
		frame := make([]byte, flen)
		// A peer that starts a frame must finish it within the timeout.
		_ = c.nc.SetReadDeadline(time.Now().Add(frameBodyTimeout))
		_, err := io.ReadFull(c.nc, frame)
		_ = c.nc.SetReadDeadline(time.Time{})
		if err != nil {
			LogDebug("slot %d: reader ending: incomplete frame of %d bytes: %v", c.idx, flen, err)
			c.releaseFrame(flen)
			return
		}
		select {
		case c.frames <- frame:
		case <-c.done:
			c.releaseFrame(flen)
			return
		}
	}
}

// releaseFrame returns a request frame's memory reservation.
func (c *conn) releaseFrame(n int) {
	c.rxHeld.Add(-int64(n))
	c.rxBudget.Release(n)
}

// write sends a response, bounding how long a stalled peer can pin this
// goroutine. The deadline is re-armed on every write and cleared afterwards, so
// a client that is slow but making progress is never disconnected.
func (c *conn) write(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	_ = c.nc.SetWriteDeadline(time.Now().Add(stallTimeout))
	_, err := c.nc.Write(b)
	_ = c.nc.SetWriteDeadline(time.Time{})
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
	// Wake the reader if it is parked on the memory budget, and account for
	// whatever it had reserved: the budget is per connection, so this is the
	// last chance to give it back.
	c.rxBudget.Shutdown(int(c.rxHeld.Swap(0)))
	c.srv.conns.Release()
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
