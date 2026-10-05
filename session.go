package samba

import (
	"sync"
	"sync/atomic"
)

// Cross-connection session registry for SMB3 multichannel.
//
// Sessions and their open-file handles are shared across all worker
// connections (channels) so a single client can stripe one share over many TCP
// connections, one per core. Each session carries its own mutex, so different
// sessions never contend; within a session the lock is held only briefly
// (handle/tree lookup), and file I/O then runs without it.
//
// Per-channel signing state stays connection-local (in ProtoConn), so the
// signature verify/sign path needs no registry lock.

// Session is the shared, lock-protected state of one SMB session, reachable
// from every channel (connection) bound to it.
type Session struct {
	sync.Mutex

	// SessionKey is the exported session key from the first authentication.
	// All channels derive their signing keys from it, regardless of the
	// per-channel key-exchange randomness in a binding authentication.
	SessionKey      [16]byte
	Established     bool
	Guest           bool
	SigningRequired bool
	User            string
	Trees           map[uint32]Tree
	NextTreeID      uint32
	Handles         HandleTable
	// Channels is the number of connections currently bound to this session.
	Channels uint32
}

func newSession() *Session {
	return &Session{Trees: make(map[uint32]Tree)}
}

// Registry is the global session table shared by all workers.
type Registry struct {
	mu     sync.Mutex
	byID   map[uint64]*Session
	nextID atomic.Uint64
}

// NewRegistry returns an empty session registry.
func NewRegistry() *Registry {
	r := &Registry{byID: make(map[uint64]*Session)}
	// Start high and odd so ids look like real SMB session handles and never
	// collide with the 0 / all-ones sentinels.
	r.nextID.Store(0x1000_0000_0001)
	return r
}

// Create allocates a fresh session and inserts an empty (un-established) entry.
func (r *Registry) Create() (uint64, *Session) {
	id := r.nextID.Add(2)
	s := newSession()
	r.mu.Lock()
	r.byID[id] = s
	r.mu.Unlock()
	return id, s
}

// Get returns the session for id.
func (r *Registry) Get(id uint64) (*Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.byID[id]
	return s, ok
}

// Remove drops the session for id and returns it.
func (r *Registry) Remove(id uint64) (*Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.byID[id]
	if ok {
		delete(r.byID, id)
	}
	return s, ok
}
