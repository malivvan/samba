// Package watch reports changes to the directories a server is asked to watch.
//
// It exists because the platforms samba runs on have four different mechanisms
// for the same job, and because the protocol needs a *portable* answer where a
// platform has none:
//
//   - Linux: inotify, which reports the changed entry's name.
//   - macOS, FreeBSD, OpenBSD, NetBSD, DragonFly: kqueue with EVFILT_VNODE,
//     which reports that a watched directory changed but never *what* changed.
//   - Windows: ReadDirectoryChangesW, which reports names and, with it, the
//     distinction between a rename's two halves.
//   - Everywhere else: a portable polling watcher, which diffs directory
//     listings. It is slower and cannot see a rename as a rename, but it is a
//     real implementation rather than a refusal — and it is what the platforms
//     without a native facility actually use.
//
// # What a caller gets
//
// Add a directory, receive Notifications about it, Remove it. Several Adds of
// the same directory share one kernel watch and are counted, because the kernel
// watch budget is a per-user resource shared with every other process on the
// host: a client that pends many CHANGE_NOTIFYs on one directory must not cost
// one watch each.
//
// A Notification whose Events are empty means "something in this directory
// changed and the mechanism could not say what" — the SMB protocol has an answer
// for that (the client re-enumerates) and the backends that cannot attribute a
// change use it rather than inventing a name. A Notification whose Gone is set
// means the watched directory itself went away.
package watch

import (
	"errors"
	"sync"
	"time"
)

// Action is what happened to an entry. The values are the
// FILE_NOTIFY_INFORMATION action codes from MS-FSCC 2.4.37, so the protocol
// layer can carry them through unchanged.
type Action uint32

const (
	// Added is a new entry.
	Added Action = 1
	// Removed is a deleted entry.
	Removed Action = 2
	// Modified is an entry whose contents or attributes changed.
	Modified Action = 3
	// RenamedOld is the old name of a renamed entry.
	RenamedOld Action = 4
	// RenamedNew is the new name of a renamed entry.
	RenamedNew Action = 5
)

// Event is one change inside a watched directory.
type Event struct {
	Action Action
	// Name is the entry's base name. An empty Name means the change could not
	// be attributed to an entry, and the client must re-enumerate the
	// directory to find out what happened.
	Name string
}

// ID identifies a watch. It is stable for the life of a Watcher and is not
// reused.
type ID uint64

// Notification is a batch of news about one watch.
type Notification struct {
	ID ID
	// Events are the changes seen since the last notification for this watch,
	// newest last. An empty slice means "changed, contents unknown".
	Events []Event
	// Gone reports that the watched directory itself was removed, renamed or
	// unmounted, so the watch no longer exists: the caller must not expect
	// further notifications for this ID and should treat the directory as
	// unresolvable.
	Gone bool
}

// Watcher watches directories.
//
// The zero value is not usable; construct one with New. A Watcher owns
// goroutines and, once a directory has been added, kernel resources; Close
// releases them.
type Watcher interface {
	// Add starts watching dir (a path, not an open handle) and returns its ID.
	// Adding a directory that is already watched increments its count and
	// returns the same ID.
	Add(dir string) (ID, error)
	// Remove drops one reference to a watch. When the last one goes, the
	// kernel resources for that directory are released. Removing an unknown ID
	// is not an error, so a caller can unwind without tracking whether it ever
	// added.
	Remove(id ID) error
	// Events delivers notifications until the Watcher is closed, after which
	// the channel is closed.
	Events() <-chan Notification
	// Close releases everything. It is idempotent.
	Close() error
}

// ErrClosed reports an Add on a closed Watcher.
var ErrClosed = errors.New("watch: the watcher is closed")

// DefaultPollInterval is how often the polling backend re-reads a directory.
// Two seconds keeps a pended CHANGE_NOTIFY from being noticeably late while
// costing a handful of getdents calls per second per watched directory, on the
// platforms where polling is all there is.
const DefaultPollInterval = 2 * time.Second

// eventBuffer is the depth of the notification channel. A consumer that stops
// draining applies backpressure to the backend's own loop, which is deliberate:
// the alternative is dropping a completion and leaving a client waiting for a
// notification that will never come. The consumer in this server never blocks —
// it queues the completion for the connection's writer — so the buffer is only
// there to absorb a burst.
const eventBuffer = 128

// catalog assigns stable IDs to watched directories and counts references, so
// that several watches of one directory share a single kernel watch: the kernel's
// watch budget is a per-user resource shared with every other process on the
// host, and a client that pends many CHANGE_NOTIFYs on one directory must not
// cost one watch each.
//
// A catalog belongs to one Watcher, so it is never contended across connections;
// a single mutex is enough, and it is held across the backend's registration
// call so that two Add calls for one path cannot both create a kernel watch.
type catalog struct {
	mu     sync.Mutex
	byPath map[string]*entry
	byID   map[ID]*entry
	next   ID
}

// entry is one watched directory.
type entry struct {
	id   ID
	path string
	refs int
	// handle is the backend's own bookkeeping for this directory: a watch
	// descriptor, a file descriptor, a completion key.
	handle any
}

func newCatalog() *catalog {
	return &catalog{byPath: make(map[string]*entry), byID: make(map[ID]*entry)}
}

// acquire returns the entry for path, calling register to create the backend
// handle the first time the path is watched. register receives the ID the watch
// is about to get, because a backend that keys its own bookkeeping by that ID
// (the Windows completion port does) has to know it before the handle is usable.
func (c *catalog) acquire(path string, register func(id ID) (any, error)) (*entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byPath[path]; ok {
		e.refs++
		return e, nil
	}
	c.next++
	id := c.next
	h, err := register(id)
	if err != nil {
		return nil, err
	}
	e := &entry{id: id, path: path, refs: 1, handle: h}
	c.byPath[path] = e
	c.byID[id] = e
	return e, nil
}

// release drops one reference, reporting the entry and whether that was the last
// one — and therefore whether the backend has to unregister the handle.
func (c *catalog) release(id ID) (*entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[id]
	if !ok {
		return nil, false
	}
	e.refs--
	if e.refs > 0 {
		return nil, false
	}
	delete(c.byID, id)
	delete(c.byPath, e.path)
	return e, true
}

// forget drops an entry that the backend has already lost — a directory deleted
// or unmounted under an inotify watch, say — so that the bookkeeping agrees with
// the kernel. A Remove for the same ID afterwards is then a no-op, which is what
// a caller unwinding several watches on one directory needs.
func (c *catalog) forget(id ID) *entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[id]
	if !ok {
		return nil
	}
	delete(c.byID, id)
	delete(c.byPath, e.path)
	return e
}

// snapshot returns every watched entry, for the backends that have to inspect
// the directories themselves.
func (c *catalog) snapshot() []*entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*entry, 0, len(c.byID))
	for _, e := range c.byID {
		out = append(out, e)
	}
	return out
}

// Backend names the mechanism in use on this platform: "inotify", "kqueue",
// "ReadDirectoryChangesW" or "poll". It is what the operator-facing capability
// report prints and what the README support table documents.
func Backend() string { return backend }

// Supported reports whether the platform has a change-notification facility of
// its own. When it is false, New returns the polling watcher: notifications
// still arrive, later and with less detail than a kernel facility could give.
func Supported() bool { return nativeSupported() }
