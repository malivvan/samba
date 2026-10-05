//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package watch

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

// macOS and the BSDs watch a directory with kqueue and EVFILT_VNODE.
//
// What kqueue can and cannot say is worth stating plainly, because it decides
// how much work a client does:
//
//   - It reports *that* a watched directory changed (NOTE_WRITE, and NOTE_EXTEND
//     for a growing file), and it reports the directory itself being deleted,
//     renamed, or unmounted. That covers every case the protocol needs to react
//     to.
//   - It never reports *which* entry changed. That is a property of the
//     interface, not of this implementation: the vnode filter is per vnode, and a
//     directory's vnode has no notion of which child moved. Reporting names
//     would need FSEvents, which lives in a framework that cannot be reached
//     without cgo.
//
// So a change here is delivered as "this directory changed, contents unknown",
// which the protocol has a first-class answer for: the client is told to
// re-enumerate (STATUS_NOTIFY_ENUM_DIR). The result is correct, always — only
// the amount of traffic differs from a platform whose mechanism reports names.
const backend = "kqueue"

// nativeSupported reports that this platform has a change-notification facility
// of its own, so the polling watcher is not in use.
func nativeSupported() bool { return true }

// New returns the platform's watcher.
func New() Watcher { return newKqueue() }

// kqueueMask is what is asked of every watched directory: every kind of change
// to its contents, and its own disappearance.
const kqueueMask = unix.NOTE_WRITE | unix.NOTE_EXTEND | unix.NOTE_ATTRIB | unix.NOTE_LINK |
	unix.NOTE_DELETE | unix.NOTE_RENAME

// kqueueWatcher is the kqueue-backed implementation. Its queue and its wake pipe
// are created on the first Add, so a connection that never pends a
// CHANGE_NOTIFY costs nothing.
type kqueueWatcher struct {
	catalog   *catalog
	events    chan Notification
	stop      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	kq        int
	wakeR     int
	wakeW     int
	fdToID    map[int]ID
	startErr  error
}

func newKqueue() *kqueueWatcher {
	return &kqueueWatcher{
		catalog: newCatalog(),
		events:  make(chan Notification, eventBuffer),
		stop:    make(chan struct{}),
		kq:      -1,
		wakeR:   -1,
		wakeW:   -1,
		fdToID:  make(map[int]ID),
	}
}

// startLocked creates the kqueue, the self-pipe that interrupts it, and the loop,
// with w.mu held.
//
// The self-pipe is what makes Close prompt: a blocking kevent(2) cannot be
// interrupted by closing the queue from another thread, so the loop also waits
// on a pipe read end and Close writes a byte to it.
func (w *kqueueWatcher) startLocked() error {
	if w.kq >= 0 {
		return nil
	}
	if w.startErr != nil {
		return w.startErr
	}
	kq, err := unix.Kqueue()
	if err != nil {
		w.startErr = err
		return err
	}
	var pipeFDs [2]int
	if err := unix.Pipe(pipeFDs[:]); err != nil {
		_ = unix.Close(kq)
		w.startErr = err
		return err
	}
	// The self-pipe is an implementation detail of this process and must not be
	// inherited by a child if one is ever spawned, so both ends are marked
	// close-on-exec. The kqueue itself has no such flag.
	for _, fd := range pipeFDs {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC)
	}
	w.kq, w.wakeR, w.wakeW = kq, pipeFDs[0], pipeFDs[1]

	// Register the wake end. EV_CLEAR means the readiness is reset once it has
	// been reported, so no re-arming is needed.
	var kev unix.Kevent_t
	unix.SetKevent(&kev, w.wakeR, unix.EVFILT_READ, unix.EV_ADD|unix.EV_CLEAR)
	if _, err := unix.Kevent(w.kq, []unix.Kevent_t{kev}, nil, nil); err != nil {
		_ = unix.Close(w.wakeR)
		_ = unix.Close(w.wakeW)
		_ = unix.Close(w.kq)
		w.kq, w.wakeR, w.wakeW = -1, -1, -1
		w.startErr = err
		return err
	}
	go w.loop(kq, w.wakeR)
	return nil
}

// Add registers a directory, holding w.mu for its whole duration so that a
// registration can never be in flight against resources Close has already torn
// down. See inotifyWatcher.Add for why that matters and how the locks are
// ordered.
func (w *kqueueWatcher) Add(dir string) (ID, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrClosed
	}
	if err := w.startLocked(); err != nil {
		return 0, err
	}
	kq := w.kq
	e, err := w.catalog.acquire(dir, func(id ID) (any, error) {
		fd, err := openWatchFD(dir)
		if err != nil {
			return nil, err
		}
		var kev unix.Kevent_t
		// SetKevent is used rather than assigning Ident directly: the field is
		// 32 bits wide on some 32-bit BSD targets and 64 bits on the others, and
		// the helper writes whichever is correct.
		unix.SetKevent(&kev, fd, unix.EVFILT_VNODE, unix.EV_ADD|unix.EV_CLEAR)
		kev.Fflags = kqueueMask
		if _, err := unix.Kevent(kq, []unix.Kevent_t{kev}, nil, nil); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		w.fdToID[fd] = id
		return fd, nil
	})
	if err != nil {
		return 0, err
	}
	return e.id, nil
}

// Remove drops one reference to a watch, holding w.mu for its whole duration so
// that it cannot run against a Close that is tearing the queue down.
func (w *kqueueWatcher) Remove(id ID) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	e, last := w.catalog.release(id)
	if !last || e == nil {
		return nil
	}
	fd, ok := e.handle.(int)
	if !ok {
		return nil
	}
	delete(w.fdToID, fd)
	kq := w.kq
	if kq >= 0 {
		var kev unix.Kevent_t
		unix.SetKevent(&kev, fd, unix.EVFILT_VNODE, unix.EV_DELETE)
		// Best effort: the vnode may already be gone, in which case the kernel
		// has dropped the registration itself.
		_, _ = unix.Kevent(kq, []unix.Kevent_t{kev}, nil, nil)
	}
	_ = unix.Close(fd)
	return nil
}

func (w *kqueueWatcher) Events() <-chan Notification { return w.events }

func (w *kqueueWatcher) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		started := w.kq >= 0
		wakeW := w.wakeW
		w.mu.Unlock()
		close(w.stop)
		if started {
			// Wake the loop; it closes the queue, the pipe and the channel.
			_, _ = unix.Write(wakeW, []byte{0})
			return
		}
		close(w.events)
	})
	return nil
}

// loop waits for directory events until the wake pipe is signalled.
func (w *kqueueWatcher) loop(kq, wakeR int) {
	defer func() {
		w.mu.Lock()
		wakeW, fds := w.wakeW, make([]int, 0, len(w.fdToID))
		for fd := range w.fdToID {
			fds = append(fds, fd)
		}
		w.fdToID = make(map[int]ID)
		w.kq, w.wakeR, w.wakeW = -1, -1, -1
		w.mu.Unlock()
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		if wakeW >= 0 {
			_ = unix.Close(wakeW)
		}
		_ = unix.Close(wakeR)
		_ = unix.Close(kq)
		close(w.events)
	}()
	events := make([]unix.Kevent_t, 64)
	for {
		n, err := unix.Kevent(kq, nil, events, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			// The queue is unusable. There is no way to tell the callers, so the
			// loop stops; the consumer sees the channel close.
			return
		}
		for _, ev := range events[:n] {
			fd := int(ev.Ident)
			if fd == wakeR {
				return
			}
			if !w.dispatch(fd, ev.Fflags) {
				return
			}
		}
	}
}

// dispatch turns one vnode event into a notification, reporting whether the loop
// should keep running.
func (w *kqueueWatcher) dispatch(fd int, fflags uint32) bool {
	w.mu.Lock()
	id, ok := w.fdToID[fd]
	closed := w.closed
	w.mu.Unlock()
	if !ok {
		return !closed
	}
	if fflags&(unix.NOTE_DELETE|unix.NOTE_RENAME) != 0 {
		w.mu.Lock()
		delete(w.fdToID, fd)
		w.mu.Unlock()
		_ = unix.Close(fd)
		// Forgetting the entry makes a later Remove a no-op, which is what a
		// caller unwinding several watches on one directory needs — and means a
		// re-created directory gets a fresh watch rather than inheriting this
		// one's gone-ness.
		w.catalog.forget(id)
		w.send(Notification{ID: id, Gone: true})
		return true
	}
	if fflags&kqueueMask != 0 {
		// "Something here changed." The vnode filter cannot say what, so the
		// client is told to re-enumerate.
		w.send(Notification{ID: id})
	}
	return true
}

func (w *kqueueWatcher) send(n Notification) {
	select {
	case w.events <- n:
	case <-w.stop:
	}
}
