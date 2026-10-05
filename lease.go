package samba

import "sync"

// Cross-worker lease/oplock break delivery.
//
// Two opens of the same file can be served by different workers, so a write (or
// a conflicting open) arriving on one worker may need to break a lease held by a
// connection owned by another. The shared Srv therefore holds a per-worker
// Mailbox: any worker enqueues a BreakMsg for the owning worker and wakes it;
// the owning worker drains the queue and pushes the break onto the target
// connection's deferred queue (the same path CHANGE_NOTIFY uses for async
// server→client frames).

// BreakMsg is a pending lease/oplock break to deliver to a connection owned by
// a (possibly different) worker.
type BreakMsg struct {
	// Wid is the owning worker id — selects the mailbox to post to.
	Wid int
	// ConnIdx is the target connection slot in the owning worker's table.
	ConnIdx int
	// ConnGen guards against the slot having been recycled.
	ConnGen uint16
	// LeaseKey is the client's 16-byte lease key (identifies which lease breaks).
	LeaseKey [16]byte
	// CurState/NewState are the lease states before and after the break (the
	// server breaks read-caching → none).
	CurState uint32
	NewState uint32
	// Epoch is the lease epoch advertised in the break (v2 leases; 0 for v1).
	Epoch uint16
	// SessionID is needed to build the break-notification header.
	SessionID uint64
}

// LeaseGrant is a granted lease on a file, plus where its holder connection
// lives so a break raised on any worker can be routed back to it.
type LeaseGrant struct {
	LeaseKey  [16]byte
	State     uint32 // currently-granted caching bits (read-caching only today)
	Epoch     uint16
	SessionID uint64
	Wid       int
	ConnIdx   int
	ConnGen   uint16
}

// fileKey identifies a file for the lease table: (share index, inode).
type fileKey struct {
	ShareIdx uint32
	Ino      uint64
}

// LeaseTable is the file-keyed lease registry, shared across all workers.
// Read-caching leases held by distinct lease keys (clients) coexist; a
// conflicting write breaks the *other* keys to none.
type LeaseTable struct {
	mu    sync.Mutex
	m     map[fileKey][]LeaseGrant
	count int
}

// NewLeaseTable returns an empty lease registry.
func NewLeaseTable() *LeaseTable { return &LeaseTable{m: make(map[fileKey][]LeaseGrant)} }

// Len reports the number of leases currently granted, across every file.
func (t *LeaseTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

// Grant grants (or refreshes) a lease for g.LeaseKey on a file. There is one
// lease per (file, lease key): a re-open with the same key replaces the prior
// grant.
//
// It reports false when the table is full — too many leases on this file, or too
// many overall. A handle-caching lease outlives CLOSE, so without a bound a
// client could grow the table without limit by re-opening one file with fresh
// lease keys. The caller opens the file without a lease rather than failing.
func (t *LeaseTable) Grant(key fileKey, g LeaseGrant) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.m[key]
	for i := range v {
		if v[i].LeaseKey == g.LeaseKey {
			v[i] = g
			return true
		}
	}
	if len(v) >= maxLeasesPerFile || t.count >= maxLeasesTotal {
		return false
	}
	t.m[key] = append(v, g)
	t.count++
	return true
}

// BreakConflicts handles a conflicting access from a holder with lease key
// writerKey (nil = an un-leased writer): it breaks every lease with a
// *different* key to none, removes them, and returns the break messages. A
// read-caching → none break carries no dirty data and needs no acknowledgement,
// so it is fire-and-forget.
func (t *LeaseTable) BreakConflicts(key fileKey, writerKey *[16]byte) []BreakMsg {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[key]
	if !ok {
		return nil
	}
	var breaks []BreakMsg
	kept := v[:0]
	for _, g := range v {
		if writerKey != nil && *writerKey == g.LeaseKey {
			kept = append(kept, g) // the writer's own lease is not broken
			continue
		}
		t.count--
		breaks = append(breaks, BreakMsg{
			Wid:       g.Wid,
			ConnIdx:   g.ConnIdx,
			ConnGen:   g.ConnGen,
			LeaseKey:  g.LeaseKey,
			CurState:  g.State,
			NewState:  0,
			Epoch:     g.Epoch + 1,
			SessionID: g.SessionID,
		})
	}
	if len(kept) == 0 {
		delete(t.m, key)
	} else {
		t.m[key] = kept
	}
	return breaks
}

// Release drops one lease (on CLOSE).
func (t *LeaseTable) Release(key fileKey, leaseKey [16]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[key]
	if !ok {
		return
	}
	kept := v[:0]
	for _, g := range v {
		if g.LeaseKey != leaseKey {
			kept = append(kept, g)
			continue
		}
		t.count--
	}
	if len(kept) == 0 {
		delete(t.m, key)
	} else {
		t.m[key] = kept
	}
}

// ReleaseConn drops every lease held by a connection (on teardown), so a
// connection that disappears without a clean CLOSE does not leak grants.
func (t *LeaseTable) ReleaseConn(wid, idx int, gen uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.m {
		kept := v[:0]
		for _, g := range v {
			if g.Wid != wid || g.ConnIdx != idx || g.ConnGen != gen {
				kept = append(kept, g)
				continue
			}
			t.count--
		}
		if len(kept) == 0 {
			delete(t.m, k)
		} else {
			t.m[k] = kept
		}
	}
}

// Mailbox is a per-worker wakeable break queue. Any goroutine may Post to any
// worker's mailbox; the owning worker drains it.
type Mailbox struct {
	mu   sync.Mutex
	q    []BreakMsg
	wake chan struct{}
}

// NewMailbox returns an empty mailbox with a signalling channel.
func NewMailbox() *Mailbox {
	return &Mailbox{wake: make(chan struct{}, 1)}
}

// EventFd returns the wake channel the owning worker selects on.
func (m *Mailbox) EventFd() <-chan struct{} { return m.wake }

// Post enqueues a break for the owning worker and wakes it.
func (m *Mailbox) Post(msg BreakMsg) {
	m.mu.Lock()
	m.q = append(m.q, msg)
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Drain removes and returns all queued breaks.
func (m *Mailbox) Drain() []BreakMsg {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.q
	m.q = nil
	return out
}

// Len reports how many breaks are queued.
func (m *Mailbox) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.q)
}
