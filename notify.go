package samba

import (
	"sync"

	"github.com/malivvan/samba/pkg/watch"
)

// CHANGE_NOTIFY plumbing.
//
// The notifier owns one directory watcher per connection and the bookkeeping
// that turns watcher notifications into CHANGE_NOTIFY completions. Which
// mechanism actually observes the filesystem is pkg/watch's business: inotify on
// Linux, kqueue on macOS and the BSDs, ReadDirectoryChangesW on Windows, and a
// polling watcher on the platforms with none of those. The protocol layer above
// this file is the same on every platform, which is the point of the split.
//
// The notifier runs on its own goroutine so a slow socket never delays watch
// registration, and it never writes to the socket itself: completions are queued
// as deferred frames for the connection goroutine, which is the only writer.

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
// directory, so a client that pends many notifications on one directory costs
// one kernel watch rather than one each.
type watchEntry struct {
	id   watch.ID
	pend NotifyPend
}

// notifyMsg is an instruction to a connection's notify watcher. A single
// channel carries both kinds so add/complete ordering is preserved.
type notifyMsg struct {
	add  *NotifyPend
	done *NotifyDone
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
	msgs chan notifyMsg
	stop chan struct{}
	once sync.Once
}

func newNotifier(c *conn) *notifier {
	return &notifier{
		conn: c,
		msgs: make(chan notifyMsg, 32),
		stop: make(chan struct{}),
	}
}

// add registers a watch for a pended CHANGE_NOTIFY.
func (n *notifier) add(p *NotifyPend) {
	select {
	case n.msgs <- notifyMsg{add: p}:
	case <-n.stop:
	}
}

// complete releases the watch for a pended CHANGE_NOTIFY and queues the final
// response with the given status (cancel / handle close).
func (n *notifier) complete(d NotifyDone) {
	select {
	case n.msgs <- notifyMsg{done: &d}:
	case <-n.stop:
	}
}

// stopNow shuts the watcher down.
func (n *notifier) stopNow() { n.once.Do(func() { close(n.stop) }) }

// run is the watcher goroutine. It owns the watcher and the entry list, so
// nothing below needs a lock: registrations arrive on msgs, and notifications
// arrive on the watcher's channel.
func (n *notifier) run() {
	// New is cheap and creates nothing: the watcher's own kernel resources are
	// created by the first Add, so a connection that never pends a CHANGE_NOTIFY
	// costs no descriptor and no goroutine beyond this one.
	w := watch.New()
	defer func() { _ = w.Close() }()

	var entries []watchEntry
	// fail completes a pend that could not be registered, so the client is not
	// left waiting forever for a watch that does not exist.
	fail := func(p NotifyPend) {
		n.conn.deferFrame(pendingFrame{notify: &notifyFired{
			pend: p, status: StatusInsufficientResources,
		}})
	}
	for {
		select {
		case <-n.stop:
			return
		case m := <-n.msgs:
			switch {
			case m.add != nil:
				id, err := w.Add(m.add.Path)
				if err != nil {
					LogDebug("notify: watching %s failed: %v", m.add.Path, err)
					fail(*m.add)
					continue
				}
				LogDebug("notify pend on %s (watch %d)", m.add.Path, id)
				entries = append(entries, watchEntry{id: id, pend: *m.add})
			case m.done != nil:
				// Cancelled or the handle closed: drop the reference and answer
				// with the status the caller asked for. An unknown id is not an
				// error — the watch may already have fired. An AsyncID is unique
				// to one operation, so at most one entry can match.
				kept := entries[:0:0]
				for _, e := range entries {
					if e.pend.AsyncID != m.done.AsyncID {
						kept = append(kept, e)
						continue
					}
					_ = w.Remove(e.id)
					n.conn.deferFrame(pendingFrame{notify: &notifyFired{
						pend: e.pend, status: m.done.Status,
					}})
				}
				entries = kept
			}
		case nf, ok := <-w.Events():
			if !ok {
				// The watcher stopped (its resources are gone); anything still
				// pending would hang forever, so complete it with the
				// "re-enumerate" answer.
				for _, e := range entries {
					n.conn.deferFrame(pendingFrame{notify: &notifyFired{
						pend: e.pend, status: StatusNotifyEnumDir,
					}})
				}
				return
			}
			entries = n.deliver(entries, nf, w)
		}
	}
}

// deliver completes every pending notification registered for one watcher id and
// returns the entries that remain.
//
// A notification ends the pends it matches: SMB completes a CHANGE_NOTIFY once,
// and the client re-issues it if it wants to keep watching. A watcher event
// whose Events are empty means the mechanism could not attribute the change to a
// name, which the protocol expresses as STATUS_NOTIFY_ENUM_DIR — the client is
// told to re-enumerate rather than being handed an invented name.
func (n *notifier) deliver(entries []watchEntry, nf watch.Notification, w watch.Watcher) []watchEntry {
	var events []DirEvent
	if nf.Events != nil {
		events = make([]DirEvent, 0, len(nf.Events))
		for _, ev := range nf.Events {
			events = append(events, DirEvent{Action: uint32(ev.Action), Name: ev.Name})
		}
	}
	kept := entries[:0:0]
	for _, e := range entries {
		if e.id != nf.ID {
			kept = append(kept, e)
			continue
		}
		// The watcher has already released a gone watch itself, so only a live
		// one needs its reference dropped.
		if !nf.Gone {
			_ = w.Remove(e.id)
		}
		LogDebug("notify complete aid=%d watch=%d events=%d gone=%v",
			e.pend.AsyncID, nf.ID, len(events), nf.Gone)
		n.conn.deferFrame(pendingFrame{notify: &notifyFired{
			pend: e.pend, status: StatusSuccess, events: events,
		}})
	}
	return kept
}
