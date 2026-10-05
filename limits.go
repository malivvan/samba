package samba

import (
	"sync"
	"sync/atomic"
)

// Resource limits.
//
// Every one of these exists because the corresponding client-controllable
// resource is otherwise unbounded, which turns a single misbehaving or hostile
// peer into a denial of service against the whole server. They are deliberately
// generous — a real client never comes close — and the failure mode is always a
// protocol error for the client that hit the limit, never a crash or an
// unbounded allocation.
const (
	// DefaultMaxConnections caps how many TCP connections the server serves at
	// once. Each connection costs goroutines plus up to maxQueuedRxBytes of
	// buffered requests, so this is the operator's main lever on the server's
	// worst-case memory use: memory is bounded by roughly
	// max_connections × (maxQueuedRxBytes + a few tens of KiB). Raise it for a
	// big deployment, lower it for a small container. -1 means no limit.
	DefaultMaxConnections = 512
	// maxSessionsTotal bounds the sessions the whole server keeps. Each session
	// holds a handle table, so this also bounds the aggregate file-handle count.
	maxSessionsTotal = 1 << 16
	// maxSearchPatternRunes bounds a QUERY_DIRECTORY search pattern. Windows
	// caps SMB search patterns at 255 characters; a longer one is rejected
	// rather than used, which also bounds the work the wildcard matcher does.
	maxSearchPatternRunes = 255
)

// Bounds that belong to a facility and so live beside the code that enforces
// them, named here so this file stays the one place to look for "what is
// bounded":
//
//   - rangelock.MaxRangesPerHandle and rangelock.MaxRangesTotal bound the
//     byte-range locks one handle, and the server, may hold. A LOCK request may
//     carry 64 ranges and a client may repeat it, so without them a peer could
//     grow the lock table — the server's own *and* the kernel's — without limit.
//     Exceeding either answers STATUS_INSUFFICIENT_RESOURCES.
//
// Per-client limits that tests shorten. Each one exists because the
// corresponding resource is otherwise client-controllable without bound; the
// values are generous enough that no real client notices them.
var (
	// maxQueuedRxBytes bounds the request bytes a single connection may hold
	// while they wait to be processed. It is one maximum-size frame plus slack,
	// so a client can keep a large WRITE in flight while the previous one is
	// being answered, but cannot make the server buffer unboundedly when it
	// stops reading responses.
	maxQueuedRxBytes = maxFrame + (64 << 10)
	// maxSessionsPerConn bounds the SMB sessions one connection may set up.
	// Clients use one session per connection (multichannel spreads a session
	// across connections, not the other way round); the limit stops a single
	// connection from draining the global session budget.
	maxSessionsPerConn = 64
	// maxHandlesPerSession bounds the open handles one session may hold. It
	// protects the process file-descriptor table, which the OS would otherwise
	// let one client exhaust (breaking every other client's i/o).
	maxHandlesPerSession = 16384
	// maxTreesPerSession bounds the share connections one session may hold.
	maxTreesPerSession = 1 << 12
	// maxNotifyWatchesPerConn bounds the pending CHANGE_NOTIFY operations on one
	// connection. Each one costs a watch in the platform's own table (inotify,
	// kqueue, a completion port) and that budget is shared with every other
	// process on the host; several pends on one directory share one watch.
	maxNotifyWatchesPerConn = 256
	// maxLeasesPerFile bounds the read-caching leases held on one file. Leases
	// with handle-caching outlive CLOSE, so without a bound a client could grow
	// the lease table indefinitely by re-opening one file with fresh lease keys.
	maxLeasesPerFile = 64
	// maxLeasesTotal bounds the leases the whole server tracks, for the same
	// reason across many files.
	maxLeasesTotal = 1 << 16
)

// budget is a weighted byte budget: it lets a producer reserve memory before
// allocating it and blocks while the reservation would exceed the limit. One
// budget guards each connection's queued request bytes.
//
// The condition deliberately also checks giveUp, so a budget can be closed (with
// Shutdown) and every waiter woken without leaving a goroutine parked forever —
// the alternative, a plain sync.Cond, cannot be interrupted.
type budget struct {
	mu     sync.Mutex
	cond   *sync.Cond
	limit  int
	used   int
	closed bool
}

func newBudget(limit int) *budget {
	b := &budget{limit: limit}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Acquire reserves n bytes, blocking until they fit. It reports whether the
// reservation succeeded; it fails when the budget is shut down, or when giveUp
// reports that the caller no longer wants to wait (its connection is closing).
//
// A reservation larger than the whole budget is allowed only when nothing else
// is held, so a single maximum-size frame still makes progress: the connection
// may hold one such frame, never two.
func (b *budget) Acquire(n int, giveUp func() bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for !b.closed && b.used > 0 && b.used+n > b.limit {
		if giveUp != nil && giveUp() {
			return false
		}
		b.cond.Wait()
	}
	if b.closed {
		return false
	}
	b.used += n
	return true
}

// Release returns n reserved bytes.
func (b *budget) Release(n int) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
	b.mu.Unlock()
	b.cond.Broadcast()
}

// Shutdown closes the budget: every waiter is released, further reservations
// fail, and n bytes are returned on behalf of bytes the owner is dropping.
func (b *budget) Shutdown(n int) {
	b.mu.Lock()
	b.closed = true
	if n > 0 {
		b.used -= n
		if b.used < 0 {
			b.used = 0
		}
	}
	b.mu.Unlock()
	b.cond.Broadcast()
}

// Used reports the currently reserved bytes (diagnostics and tests).
func (b *budget) Used() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// connLimiter counts the connections the server is serving, so that a flood of
// connections cannot exhaust memory or file descriptors.
type connLimiter struct {
	limit int
	count atomic.Int64
}

func newConnLimiter(limit int) *connLimiter { return &connLimiter{limit: limit} }

// Acquire reserves a connection slot, reporting false when the server is at its
// limit. A negative limit means unlimited. A nil limiter is unlimited, so a
// zero-value Srv (as protocol-level tests build) never panics.
func (l *connLimiter) Acquire() bool {
	if l == nil {
		return true
	}
	if l.limit < 0 {
		l.count.Add(1)
		return true
	}
	for {
		cur := l.count.Load()
		if cur >= int64(l.limit) {
			return false
		}
		if l.count.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// Release returns a connection slot.
func (l *connLimiter) Release() {
	if l == nil {
		return
	}
	if n := l.count.Add(-1); n < 0 {
		// Defensive: an unmatched Release must not make the counter drift
		// negative and permanently open the gate.
		l.count.Store(0)
	}
}

// Count reports the number of live connections.
func (l *connLimiter) Count() int {
	if l == nil {
		return 0
	}
	return int(l.count.Load())
}
