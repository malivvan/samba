package samba

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// inotify (Linux) event masks and CHANGE_NOTIFY action codes.

// inMask is the set of inotify events a pended CHANGE_NOTIFY watches for.
const inMask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MODIFY | unix.IN_ATTRIB |
	unix.IN_CLOSE_WRITE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF

// FILE_NOTIFY_INFORMATION action codes (MS-FSCC 2.4.37).
const (
	fileActionAdded      uint32 = 1
	fileActionRemoved    uint32 = 2
	fileActionModified   uint32 = 3
	fileActionRenamedOld uint32 = 4
	fileActionRenamedNew uint32 = 5
)

// watch is one registered inotify watch and the CHANGE_NOTIFY it belongs to.
// Several watches may share a kernel watch descriptor (the same directory can
// back several pends), so removal only drops the kernel watch with the last one.
type watch struct {
	wd   int
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

// notifier owns a connection's inotify instance, its live watches, and the
// bookkeeping that turns kernel events into CHANGE_NOTIFY completions. It runs
// on its own goroutine so a slow socket never delays watch registration, and it
// never writes to the socket itself: completions are queued as deferred frames
// for the connection goroutine, which is the only writer.
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

// run is the watcher goroutine.
func (n *notifier) run() {
	var (
		watches []watch
		ifd     *os.File
		evCh    chan []byte
	)
	defer func() {
		if ifd != nil {
			ifd.Close()
		}
	}()
	for {
		select {
		case <-n.stop:
			return
		case m := <-n.msgs:
			switch {
			case m.add != nil:
				if ifd == nil {
					fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
					if err != nil {
						LogDebug("notify: inotify_init failed: %v", err)
						n.conn.deferFrame(pendingFrame{notify: &notifyFired{
							pend: *m.add, status: StatusInsufficientResources,
						}})
						continue
					}
					ifd = os.NewFile(uintptr(fd), "inotify")
					evCh = make(chan []byte)
					go readInotify(ifd, evCh, n.stop)
				}
				wd, err := unix.InotifyAddWatch(int(ifd.Fd()), m.add.Path, inMask)
				if err != nil {
					LogDebug("notify: add_watch(%s) failed: %v", m.add.Path, err)
					n.conn.deferFrame(pendingFrame{notify: &notifyFired{
						pend: *m.add, status: StatusInsufficientResources,
					}})
					continue
				}
				LogDebug("notify pend on %s (wd %d)", m.add.Path, wd)
				watches = append(watches, watch{wd: wd, pend: *m.add})
			case m.done != nil:
				for i := range watches {
					if watches[i].pend.AsyncID != m.done.AsyncID {
						continue
					}
					w := watches[i]
					watches = append(watches[:i], watches[i+1:]...)
					if ifd != nil && !anyWatchWD(watches, w.wd) {
						// Best effort: the watch may be gone already, and the
						// completion reaches the client either way.
						_, _ = unix.InotifyRmWatch(int(ifd.Fd()), uint32(w.wd))
					}
					n.conn.deferFrame(pendingFrame{notify: &notifyFired{
						pend: w.pend, status: m.done.Status,
					}})
					break
				}
			}
		case data, ok := <-evCh:
			if !ok {
				evCh = nil
				if ifd != nil {
					ifd.Close()
					ifd = nil
				}
				continue
			}
			groups, selfGone := parseInotifyEvents(data)
			fired := make([]notifyFired, 0, len(groups)+len(selfGone))
			for wd, events := range groups {
				for i := range watches {
					if watches[i].wd != wd {
						continue
					}
					fired = append(fired, notifyFired{pend: watches[i].pend, status: StatusSuccess, events: events})
				}
				kept := watches[:0]
				for _, w := range watches {
					if w.wd != wd {
						kept = append(kept, w)
					}
				}
				watches = kept
				if ifd != nil {
					// Best effort, exactly as in the DONE case above.
					_, _ = unix.InotifyRmWatch(int(ifd.Fd()), uint32(wd))
				}
			}
			for _, wd := range selfGone {
				for i := range watches {
					if watches[i].wd == wd {
						fired = append(fired, notifyFired{pend: watches[i].pend, status: StatusSuccess})
					}
				}
				kept := watches[:0]
				for _, w := range watches {
					if w.wd != wd {
						kept = append(kept, w)
					}
				}
				watches = kept
			}
			for i := range fired {
				n.conn.deferFrame(pendingFrame{notify: &fired[i]})
			}
		}
	}
}

func anyWatchWD(ws []watch, wd int) bool {
	for _, w := range ws {
		if w.wd == wd {
			return true
		}
	}
	return false
}

// readInotify pumps raw inotify reads into a channel until the instance closes.
// The descriptor is created non-blocking, so the Go runtime poller parks this
// goroutine instead of burning a thread, and Close unblocks it cleanly.
func readInotify(f *os.File, out chan<- []byte, stop <-chan struct{}) {
	defer close(out)
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case out <- data:
			case <-stop:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// parseInotifyEvents decodes a raw inotify read into per-watch event lists plus
// the watch descriptors whose directory went away.
func parseInotifyEvents(data []byte) (groups map[int][]DirEvent, selfGone []int) {
	groups = make(map[int][]DirEvent)
	off := 0
	for off+16 <= len(data) {
		wd := int(le32(data[off : off+4]))
		mask := le32(data[off+4 : off+8])
		nameLen := int(le32(data[off+12 : off+16]))
		var name string
		if end := off + 16 + nameLen; end <= len(data) {
			raw := data[off+16 : end]
			for i, b := range raw {
				if b == 0 {
					raw = raw[:i]
					break
				}
			}
			name = string(raw)
		}
		off += 16 + nameLen

		if mask&(unix.IN_DELETE_SELF|unix.IN_IGNORED|unix.IN_UNMOUNT) != 0 {
			selfGone = append(selfGone, wd)
			continue
		}
		var action uint32
		switch {
		case mask&unix.IN_CREATE != 0:
			action = fileActionAdded
		case mask&unix.IN_DELETE != 0:
			action = fileActionRemoved
		case mask&unix.IN_MOVED_FROM != 0:
			action = fileActionRenamedOld
		case mask&unix.IN_MOVED_TO != 0:
			action = fileActionRenamedNew
		default:
			action = fileActionModified
		}
		if name != "" {
			groups[wd] = append(groups[wd], DirEvent{Action: action, Name: name})
		} else if _, ok := groups[wd]; !ok {
			// Event without a name → make the client re-enumerate.
			groups[wd] = nil
		}
	}
	return groups, selfGone
}
