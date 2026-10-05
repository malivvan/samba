package watch

import (
	"encoding/binary"
	"errors"
	"sync"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// Windows watches directories with ReadDirectoryChangesW, which is the richest
// of the four mechanisms: it reports the changed entry's name and, uniquely, the
// two halves of a rename as separate events, so an SMB client gets exactly the
// notification list a Windows client expects.
//
// The asynchronous form is not optional here. A synchronous
// ReadDirectoryChangesW blocks until something changes, and a blocked syscall
// pins an OS thread for its whole duration — with up to a few hundred pending
// notifications per connection that would be a few hundred threads. So each
// watched directory has an overlapped handle attached to one I/O completion
// port, and a single goroutine per watcher drains the completions.
const backend = "ReadDirectoryChangesW"

// nativeSupported reports that this platform has a change-notification facility
// of its own, so the polling watcher is not in use.
func nativeSupported() bool { return true }

// New returns the platform's watcher.
func New() Watcher { return newWindows() }

const (
	// notifyHeaderSize is the fixed part of FILE_NOTIFY_INFORMATION: the
	// next-entry offset, the action and the name length.
	notifyHeaderSize = 12
	// notifyBufferSize is the per-directory buffer the kernel fills. The Windows
	// default assumption is 4 KiB; a larger buffer reduces the chance of an
	// overflow notification, at the cost of one allocation per watch.
	notifyBufferSize = 16 << 10
)

// windowsWatcher is the ReadDirectoryChangesW-backed implementation. Its
// completion port is created on the first Add, so a connection that never pends
// a CHANGE_NOTIFY costs nothing.
type windowsWatcher struct {
	catalog   *catalog
	events    chan Notification
	stop      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	iocp      windows.Handle
	byKey     map[uintptr]*winWatch
	// retired holds watches whose handles have been closed while a completion
	// was still queued. The kernel writes into the watch's buffer until that
	// completion has been retrieved, so the memory must stay alive until then;
	// the entry is dropped when its completion arrives, which bounds the list by
	// the number of watches whose removal is still in flight.
	retired  map[uintptr]*winWatch
	startErr error
}

// winWatch is one watched directory.
type winWatch struct {
	id   ID
	path string
	// handle is the directory handle; buf receives the kernel's notification
	// records and overlapped carries the completion. Both are referenced by the
	// kernel until the completion arrives, so neither may move into a local
	// variable while a read is outstanding.
	handle     windows.Handle
	buf        []byte
	overlapped windows.Overlapped
}

func newWindows() *windowsWatcher {
	return &windowsWatcher{
		catalog: newCatalog(),
		events:  make(chan Notification, eventBuffer),
		stop:    make(chan struct{}),
		byKey:   make(map[uintptr]*winWatch),
		retired: make(map[uintptr]*winWatch),
	}
}

// startLocked creates the completion port and the goroutine that drains it, with
// w.mu held.
func (w *windowsWatcher) startLocked() error {
	if w.iocp != 0 {
		return nil
	}
	if w.startErr != nil {
		return w.startErr
	}
	iocp, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 0)
	if err != nil {
		w.startErr = err
		return err
	}
	w.iocp = iocp
	go w.loop(iocp)
	return nil
}

// Add opens the directory and issues the first asynchronous read.
//
// The completion key is the watch ID, which is why the catalog hands the ID to
// the registration function: the key is what a completion is matched against.
// Add registers a directory, holding w.mu for its whole duration so that a
// registration can never be in flight against resources Close has already torn
// down. See inotifyWatcher.Add for why that matters and how the locks are
// ordered.
func (w *windowsWatcher) Add(dir string) (ID, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrClosed
	}
	if err := w.startLocked(); err != nil {
		return 0, err
	}
	iocp := w.iocp
	e, err := w.catalog.acquire(dir, func(id ID) (any, error) {
		handle, err := openWatchDir(dir)
		if err != nil {
			return nil, err
		}
		wp := &winWatch{id: id, path: dir, handle: handle, buf: make([]byte, notifyBufferSize)}
		if _, err := windows.CreateIoCompletionPort(handle, iocp, uintptr(id), 0); err != nil {
			_ = windows.CloseHandle(handle)
			return nil, err
		}
		if err := beginRead(wp); err != nil {
			_ = windows.CloseHandle(handle)
			return nil, err
		}
		w.byKey[uintptr(id)] = wp
		return wp, nil
	})
	if err != nil {
		return 0, err
	}
	return e.id, nil
}

// Remove drops one reference to a watch, holding w.mu for its whole duration so
// that it cannot run against a Close that is cancelling and closing the same
// handles.
func (w *windowsWatcher) Remove(id ID) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	e, last := w.catalog.release(id)
	if !last || e == nil {
		return nil
	}
	wp, ok := e.handle.(*winWatch)
	if !ok {
		return nil
	}
	delete(w.byKey, uintptr(id))
	w.retired[uintptr(id)] = wp
	// Cancel the outstanding read, then close the handle. The completion still
	// arrives (with ERROR_OPERATION_ABORTED), which is what lets the loop drop
	// the watch's memory safely; PostQueuedCompletionStatus is not needed for a
	// single watch.
	_ = windows.CancelIoEx(wp.handle, &wp.overlapped)
	_ = windows.CloseHandle(wp.handle)
	return nil
}

func (w *windowsWatcher) Events() <-chan Notification { return w.events }

func (w *windowsWatcher) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		iocp := w.iocp
		watches := make([]*winWatch, 0, len(w.byKey))
		for _, wp := range w.byKey {
			watches = append(watches, wp)
		}
		w.byKey = make(map[uintptr]*winWatch)
		// The cancelled watches are retired rather than dropped: each one owns a
		// buffer the kernel may still be writing a cancelled transfer into, so
		// the memory has to stay reachable until its completion has been
		// retrieved. The loop holds them until it has drained the port.
		for _, wp := range watches {
			w.retired[uintptr(wp.id)] = wp
		}
		w.mu.Unlock()
		close(w.stop)
		for _, wp := range watches {
			_ = windows.CancelIoEx(wp.handle, &wp.overlapped)
			_ = windows.CloseHandle(wp.handle)
		}
		if iocp != 0 {
			// A completion packet with no overlapped is how the loop is told to
			// stop, after every watch above has been cancelled.
			_ = windows.PostQueuedCompletionStatus(iocp, 0, 0, nil)
			return
		}
		close(w.events)
	})
	return nil
}

// loop drains completions until it is told to stop, then releases everything.
func (w *windowsWatcher) loop(iocp windows.Handle) {
	defer func() {
		w.mu.Lock()
		w.retired = make(map[uintptr]*winWatch)
		w.iocp = 0
		w.mu.Unlock()
		_ = windows.CloseHandle(iocp)
		close(w.events)
	}()
	for {
		var (
			bytesRead  uint32
			key        uintptr
			overlapped *windows.Overlapped
		)
		err := windows.GetQueuedCompletionStatus(iocp, &bytesRead, &key, &overlapped, windows.INFINITE)
		if overlapped == nil {
			// The shutdown packet posted by Close. Every cancelled transfer's
			// completion is queued by now, so drain the rest before letting the
			// buffers go: a packet left in the port would otherwise be retrieved
			// by nobody, and the kernel would write into memory nothing
			// references any more. A zero timeout makes an empty port the end of
			// the drain.
			w.drain(iocp)
			return
		}
		w.mu.Lock()
		wp, live := w.byKey[key]
		if !live {
			// A watch that was removed: its completion has now arrived, so its
			// buffer is no longer referenced by the kernel and the memory can go.
			delete(w.retired, key)
		}
		w.mu.Unlock()
		if !live {
			continue
		}
		switch {
		case errors.Is(err, windows.ERROR_OPERATION_ABORTED):
			// Either the watch was cancelled or its directory is gone. Cancelling
			// only happens on the way out, so report the directory as gone and
			// let the caller stop watching it.
			w.forget(wp)
			w.send(Notification{ID: wp.id, Gone: true})
			continue
		case errors.Is(err, windows.ERROR_NOTIFY_ENUM_DIR):
			// The kernel's buffer overflowed: changes were lost, so the only
			// honest answer is "re-enumerate".
			w.send(Notification{ID: wp.id})
		case err != nil:
			// An unusable directory handle. Report it gone rather than leaving
			// the pending notification hanging forever.
			w.forget(wp)
			w.send(Notification{ID: wp.id, Gone: true})
			continue
		case bytesRead > 0:
			w.dispatch(wp, bytesRead)
		default:
			// Zero bytes with no error is the documented overflow signal.
			w.send(Notification{ID: wp.id})
		}
		// Reissue the read to keep watching.
		if err := beginRead(wp); err != nil {
			w.forget(wp)
			w.send(Notification{ID: wp.id, Gone: true})
		}
	}
}

// drain retrieves whatever completions are still queued, discarding them: it is
// called once the watcher is shutting down, when every watch has been cancelled
// and no packet can mean anything any more. It returns when the port is empty.
func (w *windowsWatcher) drain(iocp windows.Handle) {
	for {
		var (
			bytesRead  uint32
			key        uintptr
			overlapped *windows.Overlapped
		)
		// A zero timeout turns the wait into a poll: ERROR_TIMEOUT means there is
		// nothing left.
		err := windows.GetQueuedCompletionStatus(iocp, &bytesRead, &key, &overlapped, 0)
		if overlapped == nil && err != nil {
			return
		}
		w.discard(key)
	}
}

// discard drops a retired watch whose completion has now been retrieved, which
// releases the buffer the kernel was writing into.
func (w *windowsWatcher) discard(key uintptr) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.byKey[key] == nil {
		delete(w.retired, key)
	}
}

// forget removes a watch whose directory is no longer watchable, so that a later
// Remove is a no-op.
func (w *windowsWatcher) forget(wp *winWatch) {
	w.mu.Lock()
	delete(w.byKey, uintptr(wp.id))
	w.retired[uintptr(wp.id)] = wp
	w.mu.Unlock()
	w.catalog.forget(wp.id)
	_ = windows.CloseHandle(wp.handle)
}

// dispatch decodes one buffer of FILE_NOTIFY_INFORMATION records.
//
// The records are a packed sequence whose entries are aligned to four bytes; the
// name is UTF-16LE and not NUL-terminated, so it is decoded from the byte slice
// rather than read as a string. Every field access is bounds-checked, because
// the buffer is filled by the kernel from a directory whose names a remote user
// chose.
func (w *windowsWatcher) dispatch(wp *winWatch, bytesRead uint32) {
	limit := int(bytesRead)
	if limit > len(wp.buf) {
		limit = len(wp.buf)
	}
	events := make([]Event, 0, 8)
	for off := 0; off+notifyHeaderSize <= limit; {
		next := int(binary.LittleEndian.Uint32(wp.buf[off : off+4]))
		action := binary.LittleEndian.Uint32(wp.buf[off+4 : off+8])
		nameLen := int(binary.LittleEndian.Uint32(wp.buf[off+8 : off+12]))
		nameStart := off + notifyHeaderSize
		if nameLen < 0 || nameStart+nameLen > limit {
			// A truncated or malformed record: stop rather than read past it.
			break
		}
		name := decodeUTF16(wp.buf[nameStart : nameStart+nameLen])
		if a := actionOf(action); a != 0 && name != "" {
			events = append(events, Event{Action: a, Name: name})
		}
		if next <= 0 {
			break
		}
		off += next
	}
	if len(events) == 0 {
		// Nothing usable in the buffer: the caller still needs to know something
		// changed, and the protocol's answer for that is re-enumeration.
		w.send(Notification{ID: wp.id})
		return
	}
	w.send(Notification{ID: wp.id, Events: events})
}

func (w *windowsWatcher) send(n Notification) {
	select {
	case w.events <- n:
	case <-w.stop:
	}
}

// actionOf maps a FILE_ACTION_* code onto the protocol's action code, which uses
// the same numbering; an unrecognised value becomes "no event".
func actionOf(action uint32) Action {
	switch Action(action) {
	case Added, Removed, Modified, RenamedOld, RenamedNew:
		return Action(action)
	default:
		return 0
	}
}

// decodeUTF16 decodes a UTF-16LE name field, stopping at a NUL if one is present
// (the kernel does not terminate names, but a defensive cut costs nothing).
func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

// openWatchDir opens a directory handle that can be watched: read-directory
// access only, shared with everyone, no reparse-point traversal.
func openWatchDir(dir string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		p,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		// FILE_FLAG_BACKUP_SEMANTICS is what allows a *directory* handle at all;
		// FILE_FLAG_OVERLAPPED is what makes the read asynchronous and therefore
		// completable rather than a pinned thread.
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
}

// beginRead issues the asynchronous ReadDirectoryChangesW for a watch.
func beginRead(wp *winWatch) error {
	err := windows.ReadDirectoryChanges(
		wp.handle,
		&wp.buf[0],
		uint32(len(wp.buf)),
		false, // one directory, not its subtree: a pended CHANGE_NOTIFY is always non-recursive
		windows.FILE_NOTIFY_CHANGE_FILE_NAME|
			windows.FILE_NOTIFY_CHANGE_DIR_NAME|
			windows.FILE_NOTIFY_CHANGE_ATTRIBUTES|
			windows.FILE_NOTIFY_CHANGE_SIZE|
			windows.FILE_NOTIFY_CHANGE_LAST_WRITE,
		nil, // with an overlapped pointer this must be NULL: the call is asynchronous
		&wp.overlapped,
		0, // no completion routine; the completion port delivers it
	)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		return nil
	}
	return err
}
