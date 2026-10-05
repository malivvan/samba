package samba

import (
	"sync"

	"github.com/malivvan/samba/pkg/watch"
)

// CHANGE_NOTIFY plumbing.
//
// The notifier owns one directory watcher per connection and the bookkeeping that
// turns watcher notifications into CHANGE_NOTIFY completions. Which mechanism
// actually observes the filesystem is pkg/watch's business: inotify on Linux,
// kqueue on macOS and the BSDs, ReadDirectoryChangesW on Windows, and a polling
// watcher on the platforms with none of those. The protocol layer above this file
// is the same on every platform, which is the point of the split.
//
// # Why registration is synchronous
//
// Registering a watch happens on the connection's own goroutine rather than on
// the watcher's, and that ordering is deliberate: the interim STATUS_PENDING
// response is written *after* the frame that asked for it has been processed, so
// registering during processing means the directory is being watched before the
// client is told the operation is pending. The guarantee this buys is the one the
// protocol wants: a client that pends a CHANGE_NOTIFY and then changes the file
// cannot miss the change. The other way round — telling the client it is pending
// and registering later — leaves a window in which the change is lost and the
// pending operation never completes at all, which a client can only end by
// cancelling it (or by disconnecting).
//
// The watcher's own kernel resources are still created lazily, on the first Add,
// so a connection that never pends a notification costs no descriptor.
//
// # Who touches what
//
// mu guards the pending list and is held across every watcher call, which is what
// makes the registration window above impossible: a notification that arrives
// while a watch is being added waits for the entry to be recorded instead of
// being matched against a list that does not have it yet. Event *delivery* runs
// on its own goroutine and only queues frames — it never writes to the socket, so
// the connection's single-writer invariant holds.

// FILE_NOTIFY_INFORMATION action codes (MS-FSCC 2.4.37).
//
// The numbering is the protocol's, and pkg/watch uses the same numbering for its
// own action codes, so a watcher event becomes a wire event by conversion rather
// than by a lookup table. TestWatchActionsMatchTheWire pins the two together.
const (
	fileActionAdded      uint32 = 1
	fileActionRemoved    uint32 = 2
	fileActionModified   uint32 = 3
	fileActionRenamedOld uint32 = 4
	fileActionRenamedNew uint32 = 5
)

// watchEntry is one pending CHANGE_NOTIFY and the watcher id it is registered
// under. Several entries may share one id: the watcher counts references per
// directory, so a client that pends many notifications on one directory costs one
// kernel watch rather than one each.
type watchEntry struct {
	id   watch.ID
	pend NotifyPend
}

// notifyFired reports a completed watch back to the owning connection.
type notifyFired struct {
	pend   NotifyPend
	status uint32
	events []DirEvent
}

// notifier owns a connection's directory watcher and its pending notifications.
type notifier struct {
	conn *conn
	w    watch.Watcher
	stop chan struct{}
	once sync.Once
	mu   sync.Mutex
	// entries is the live pending list, guarded by mu. It is held by the
	// connection's goroutine when it registers, and by the watcher goroutine when
	// it completes one, which is what orders the two.
	entries []watchEntry
}

func newNotifier(c *conn) *notifier {
	return &notifier{
		conn: c,
		w:    watch.New(),
		stop: make(chan struct{}),
	}
}

// add registers a watch for a pended CHANGE_NOTIFY, on the caller's goroutine.
//
// It returns only once the watch exists, which is what makes the interim
// STATUS_PENDING response a promise: the response is written after this returns.
func (n *notifier) add(p *NotifyPend) {
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-n.stop:
		return
	default:
	}
	id, err := n.w.Add(p.Path)
	if err != nil {
		// A directory that cannot be watched must complete the operation rather
		// than leave the client waiting forever for a watch that does not exist.
		LogDebug("notify: watching %s failed: %v", p.Path, err)
		n.queueLocked(*p, StatusInsufficientResources, nil)
		return
	}
	LogDebug("notify pend on %s (watch %d)", p.Path, id)
	n.entries = append(n.entries, watchEntry{id: id, pend: *p})
}

// complete releases the watch for a pended CHANGE_NOTIFY and queues the final
// response with the given status (cancel / handle close).
func (n *notifier) complete(d NotifyDone) {
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-n.stop:
		return
	default:
	}
	// An AsyncID is unique to one operation, so at most one entry can match, and
	// an unknown id is not an error: the watch may already have fired.
	kept := n.entries[:0:0]
	for _, e := range n.entries {
		if e.pend.AsyncID != d.AsyncID {
			kept = append(kept, e)
			continue
		}
		_ = n.w.Remove(e.id)
		n.queueLocked(e.pend, d.Status, nil)
	}
	n.entries = kept
}

// stopNow shuts the watcher down. Registration and completion stop being honoured
// from here on; the watcher goroutine closes the watcher itself as it returns.
func (n *notifier) stopNow() { n.once.Do(func() { close(n.stop) }) }

// run is the watcher goroutine: it turns notifications into deferred frames until
// the watcher is closed.
func (n *notifier) run() {
	defer func() { _ = n.w.Close() }()
	for {
		select {
		case <-n.stop:
			return
		case nf, ok := <-n.w.Events():
			if !ok {
				// The watcher stopped (its resources are gone). Anything still
				// pending would hang forever, so complete it with the
				// "re-enumerate" answer rather than leaving it to the client to
				// notice.
				n.completeAll(StatusNotifyEnumDir)
				return
			}
			n.deliver(nf)
		}
	}
}

// deliver completes every pending notification registered for one watcher id.
//
// A notification ends the pends it matches: SMB completes a CHANGE_NOTIFY once,
// and the client re-issues it if it wants to keep watching. A watcher event whose
// Events are empty means the mechanism could not attribute the change to a name,
// which the protocol expresses as STATUS_NOTIFY_ENUM_DIR — the client is told to
// re-enumerate rather than being handed an invented name.
func (n *notifier) deliver(nf watch.Notification) {
	var events []DirEvent
	if nf.Events != nil {
		events = make([]DirEvent, 0, len(nf.Events))
		for _, ev := range nf.Events {
			events = append(events, DirEvent{Action: uint32(ev.Action), Name: ev.Name})
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	kept := n.entries[:0:0]
	for _, e := range n.entries {
		if e.id != nf.ID {
			kept = append(kept, e)
			continue
		}
		// The watcher has already released a gone watch itself, so only a live
		// one needs its reference dropped.
		if !nf.Gone {
			_ = n.w.Remove(e.id)
		}
		LogDebug("notify complete aid=%d watch=%d events=%d gone=%v",
			e.pend.AsyncID, nf.ID, len(events), nf.Gone)
		n.queueLocked(e.pend, StatusSuccess, events)
	}
	n.entries = kept
}

// completeAll answers every pending notification with the given status, used when
// the watcher itself goes away.
func (n *notifier) completeAll(status uint32) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, e := range n.entries {
		n.queueLocked(e.pend, status, nil)
	}
	n.entries = nil
}

// queueLocked queues a completion for a pending operation. n.mu must be held: the
// pending entry it belongs to is being retired in the same step, and the frame
// goes to the connection's own goroutine, which is the only writer to the socket.
func (n *notifier) queueLocked(p NotifyPend, status uint32, events []DirEvent) {
	n.conn.deferFrame(pendingFrame{notify: &notifyFired{
		pend: p, status: status, events: events,
	}})
}
