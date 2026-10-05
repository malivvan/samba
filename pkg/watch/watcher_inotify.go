//go:build linux

package watch

import (
	"encoding/binary"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Linux watches directories with inotify, which reports the *name* of the
// changed entry, distinguishies a rename's two halves, and needs one watch
// descriptor per directory rather than one descriptor per entry.
const backend = "inotify"

// nativeSupported reports that this platform has a change-notification facility
// of its own, so the polling watcher is not in use.
func nativeSupported() bool { return true }

// New returns the platform's watcher.
func New() Watcher { return newInotify() }

// inMask is the set of inotify events a pended CHANGE_NOTIFY cares about.
// Creation, deletion, modification, attribute changes and both halves of a
// rename cover every SMB action code the protocol can report.
const inMask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MODIFY | unix.IN_ATTRIB |
	unix.IN_CLOSE_WRITE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF

// inotifyWatcher is the inotify-backed implementation. Its inotify instance is
// created on the first Add, so a connection that never pends a CHANGE_NOTIFY
// costs no descriptor at all.
type inotifyWatcher struct {
	catalog   *catalog
	events    chan Notification
	stop      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	fd        *os.File
	wdToID    map[int]ID
	startErr  error
}

func newInotify() *inotifyWatcher {
	return &inotifyWatcher{
		catalog: newCatalog(),
		events:  make(chan Notification, eventBuffer),
		stop:    make(chan struct{}),
		wdToID:  make(map[int]ID),
	}
}

// startLocked creates the inotify instance and starts the reader, with w.mu held.
// It reports the error that stopped it, so the first Add can surface it to the
// caller instead of leaving the watch silently dead.
func (w *inotifyWatcher) startLocked() error {
	if w.fd != nil {
		return nil
	}
	if w.startErr != nil {
		return w.startErr
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		w.startErr = err
		return err
	}
	// The descriptor is non-blocking and wrapped so the Go runtime poller parks
	// the reader goroutine; closing it wakes the reader cleanly.
	f := os.NewFile(uintptr(fd), "inotify")
	w.fd = f
	// The descriptor is passed to the reader rather than read from the field:
	// Close clears the field, and the reader must not touch it again.
	go w.read(f)
	return nil
}

// Add registers a directory, holding w.mu for its whole duration.
//
// That is the invariant the backend needs: Add and Close are the two operations
// that create and destroy the kernel resources, and letting them interleave means
// a registration can be in flight against a descriptor Close has already closed —
// a use-after-close, and a data race on the *os.File itself. The catalog's own
// lock is taken inside this one, never the other way round; the reader goroutine
// takes w.mu only to translate a watch descriptor, so it is never the one holding
// the other lock.
func (w *inotifyWatcher) Add(dir string) (ID, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrClosed
	}
	if err := w.startLocked(); err != nil {
		return 0, err
	}
	fd := w.fd
	e, err := w.catalog.acquire(dir, func(id ID) (any, error) {
		wd, err := unix.InotifyAddWatch(int(fd.Fd()), dir, inMask)
		if err != nil {
			return nil, err
		}
		w.wdToID[wd] = id
		return wd, nil
	})
	if err != nil {
		return 0, err
	}
	return e.id, nil
}

// Remove drops one reference to a watch, holding w.mu for its whole duration so
// that it cannot run against a Close that is tearing the instance down. The
// descriptor is an *os.File, whose Close mutates state the unsynchronized Fd
// call would read.
func (w *inotifyWatcher) Remove(id ID) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.removeLocked(id)
}

func (w *inotifyWatcher) removeLocked(id ID) error {
	e, last := w.catalog.release(id)
	if !last || e == nil {
		return nil
	}
	wd, ok := e.handle.(int)
	if !ok {
		return nil
	}
	delete(w.wdToID, wd)
	fd := w.fd
	if fd != nil {
		// Best effort: the watch may already be gone, and the reference count is
		// what decides whether the client sees the notification.
		_, _ = unix.InotifyRmWatch(int(fd.Fd()), uint32(wd))
	}
	return nil
}

func (w *inotifyWatcher) Events() <-chan Notification { return w.events }

func (w *inotifyWatcher) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		fd := w.fd
		w.fd = nil
		w.mu.Unlock()
		close(w.stop)
		if fd != nil {
			// Closing the descriptor is what unblocks the reader, which then
			// closes the notification channel.
			_ = fd.Close()
		} else {
			// The reader never started, so nothing else will close the channel.
			close(w.events)
		}
	})
	return nil
}

// read pumps raw inotify reads into notifications until the instance closes.
func (w *inotifyWatcher) read(f *os.File) {
	defer close(w.events)
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			w.dispatch(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// dispatch decodes one read into per-watch notifications.
func (w *inotifyWatcher) dispatch(data []byte) {
	groups, gone := parseInotifyEvents(data)
	for wd, events := range groups {
		w.mu.Lock()
		id, ok := w.wdToID[wd]
		w.mu.Unlock()
		if !ok {
			continue
		}
		// A nameless event arrives as a nil slice, which is the "the directory
		// changed, contents unknown" answer the protocol has a status for.
		w.send(Notification{ID: id, Events: events})
	}
	for _, wd := range gone {
		w.mu.Lock()
		id, ok := w.wdToID[wd]
		delete(w.wdToID, wd)
		w.mu.Unlock()
		if !ok {
			continue
		}
		// The kernel watch is gone with the directory, so drop the bookkeeping
		// too: a later Remove for this ID is then a no-op, which is what the
		// callers unwinding several watches on one directory need.
		w.catalog.forget(id)
		w.send(Notification{ID: id, Gone: true})
	}
}

func (w *inotifyWatcher) send(n Notification) {
	select {
	case w.events <- n:
	case <-w.stop:
	}
}

// parseInotifyEvents decodes a raw inotify read into per-watch event lists plus
// the watch descriptors whose directory went away.
//
// The layout is the kernel's: a sequence of variable-length records, each a
// wd/mask/cookie/length header followed by a NUL-terminated name. The length is
// attacker-influenced only in the sense that a truncated buffer must not be read
// past, so every field access is bounds-checked and a record that does not fit
// ends the parse.
func parseInotifyEvents(data []byte) (groups map[int][]Event, gone []int) {
	groups = make(map[int][]Event)
	for off := 0; off+16 <= len(data); {
		wd := int(int32(binary.LittleEndian.Uint32(data[off : off+4])))
		mask := binary.LittleEndian.Uint32(data[off+4 : off+8])
		nameLen := int(binary.LittleEndian.Uint32(data[off+12 : off+16]))
		if nameLen < 0 || off+16+nameLen > len(data) {
			break
		}
		raw := data[off+16 : off+16+nameLen]
		off += 16 + nameLen
		for i, b := range raw {
			if b == 0 {
				raw = raw[:i]
				break
			}
		}
		name := string(raw)

		if mask&(unix.IN_DELETE_SELF|unix.IN_IGNORED|unix.IN_UNMOUNT) != 0 {
			gone = append(gone, wd)
			continue
		}
		var action Action
		switch {
		case mask&unix.IN_CREATE != 0:
			action = Added
		case mask&unix.IN_DELETE != 0:
			action = Removed
		case mask&unix.IN_MOVED_FROM != 0:
			action = RenamedOld
		case mask&unix.IN_MOVED_TO != 0:
			action = RenamedNew
		default:
			action = Modified
		}
		if name != "" {
			groups[wd] = append(groups[wd], Event{Action: action, Name: name})
		} else if _, ok := groups[wd]; !ok {
			// An event without a name means the client must re-enumerate.
			groups[wd] = nil
		}
	}
	return groups, gone
}
