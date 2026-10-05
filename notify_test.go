package samba

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseInotifyEvents(t *testing.T) {
	// Two events for one watch (a create and a modify), one for another, a
	// nameless event, and a watch that went away.
	buf := NewWriter(0)
	add := func(wd int32, mask uint32, name string) {
		buf.U32(uint32(wd))
		buf.U32(mask)
		buf.U32(0) // cookie
		buf.U32(uint32(len(name) + 1))
		buf.Bytes8([]byte(name))
		buf.U8(0)
	}
	add(1, unix.IN_CREATE, "created.txt")
	add(1, unix.IN_MOVED_TO, "arrived.txt")
	add(2, unix.IN_DELETE, "gone.txt")
	add(2, unix.IN_ATTRIB, "")      // no name
	add(3, unix.IN_DELETE_SELF, "") // the directory itself
	add(4, unix.IN_IGNORED, "")
	add(5, unix.IN_UNMOUNT, "")

	groups, selfGone := parseInotifyEvents(buf.Bytes())
	events := groups[1]
	if len(events) != 2 {
		t.Fatalf("watch 1 has %d events: %+v", len(events), events)
	}
	if events[0].Name != "created.txt" || events[0].Action != fileActionAdded {
		t.Fatalf("first event = %+v", events[0])
	}
	if events[1].Action != fileActionRenamedNew {
		t.Fatalf("second event action = %d", events[1].Action)
	}
	if got := groups[2]; len(got) != 1 || got[0].Action != fileActionRemoved {
		t.Fatalf("watch 2 = %+v", got)
	}
	// A nameless event still fires (the client is told to re-enumerate).
	if _, ok := groups[2]; !ok {
		t.Fatal("watch 2 must be recorded even without a name")
	}
	if len(selfGone) != 3 {
		t.Fatalf("self-gone watches = %v", selfGone)
	}
	// Truncated input must not panic or read past the end.
	for i := range buf.Len() {
		_, _ = parseInotifyEvents(buf.Bytes()[:i])
	}
}

func TestParseInotifyEventActions(t *testing.T) {
	cases := []struct {
		mask uint32
		want uint32
	}{
		{unix.IN_CREATE, fileActionAdded},
		{unix.IN_DELETE, fileActionRemoved},
		{unix.IN_MOVED_FROM, fileActionRenamedOld},
		{unix.IN_MOVED_TO, fileActionRenamedNew},
		{unix.IN_MODIFY, fileActionModified},
		{unix.IN_CLOSE_WRITE, fileActionModified},
	}
	for _, c := range cases {
		buf := NewWriter(0)
		buf.U32(7)
		buf.U32(c.mask)
		buf.U32(0)
		buf.U32(uint32(len("name") + 1)) // the kernel counts the trailing NUL
		buf.Bytes8([]byte("name"))
		buf.U8(0)
		groups, _ := parseInotifyEvents(buf.Bytes())
		if got := groups[7]; len(got) != 1 || got[0].Action != c.want {
			t.Errorf("mask %#x produced %+v, want action %d", c.mask, got, c.want)
		}
	}
}

func TestAnyWatchWD(t *testing.T) {
	ws := []watch{{wd: 1}, {wd: 2}}
	if !anyWatchWD(ws, 2) {
		t.Fatal("watch 2 is present")
	}
	if anyWatchWD(ws, 3) {
		t.Fatal("watch 3 is not present")
	}
	if anyWatchWD(nil, 1) {
		t.Fatal("an empty list has no watches")
	}
}

// notifierConn builds the minimum connection a notifier needs: it only queues
// completions.
func notifierConn() *conn {
	return &conn{deferred: newDeferredQueue(), done: make(chan struct{})}
}

func TestNotifierDeliversCompletions(t *testing.T) {
	dir := t.TempDir()
	c := notifierConn()
	n := newNotifier(c)
	go n.run()
	defer n.stopNow()

	pend := NotifyPend{
		AsyncID: 7,
		Path:    dir,
		OutLen:  4096,
		Meta:    AsyncMeta{MsgID: 1, AsyncID: 7, SessionID: 2},
	}
	n.add(&pend)

	// Wait until the watch is registered by touching the directory until a
	// completion shows up.
	deadline := time.Now().Add(10 * time.Second)
	var fired *notifyFired
	for time.Now().Before(deadline) {
		if err := os.WriteFile(filepath.Join(dir, "touched"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		items := c.deferred.drain()
		for _, pf := range items {
			if pf.notify != nil {
				fired = pf.notify
			}
		}
		if fired != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fired == nil {
		t.Fatal("the watch never fired")
	}
	if fired.status != StatusSuccess {
		t.Fatalf("completion status = %#x", fired.status)
	}
	if fired.pend.AsyncID != 7 {
		t.Fatalf("completion is for %d, want 7", fired.pend.AsyncID)
	}
	if len(fired.events) == 0 {
		t.Fatal("the completion should carry the changed name")
	}
}

func TestNotifierCompleteAndUnknown(t *testing.T) {
	dir := t.TempDir()
	c := notifierConn()
	n := newNotifier(c)
	go n.run()
	defer n.stopNow()

	// Completing a watch that was never registered is a no-op, not a panic.
	n.complete(NotifyDone{AsyncID: 99, Status: StatusCancelled})
	time.Sleep(50 * time.Millisecond)
	if items := c.deferred.drain(); len(items) != 0 {
		t.Fatalf("an unknown completion produced %d frames", len(items))
	}

	// Register, then complete explicitly: the completion is queued with the
	// requested status.
	n.add(&NotifyPend{AsyncID: 5, Path: dir, OutLen: 64, Meta: AsyncMeta{AsyncID: 5}})
	time.Sleep(100 * time.Millisecond)
	n.complete(NotifyDone{AsyncID: 5, Status: StatusCancelled})
	deadline := time.Now().Add(5 * time.Second)
	for {
		items := c.deferred.drain()
		for _, pf := range items {
			if pf.notify != nil {
				if pf.notify.status != StatusCancelled {
					t.Fatalf("status = %#x, want CANCELLED", pf.notify.status)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the explicit completion was never queued")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNotifierAddFailsOnBadPath(t *testing.T) {
	c := notifierConn()
	n := newNotifier(c)
	go n.run()
	defer n.stopNow()
	// A path that cannot be watched must complete with an error status rather
	// than leaving the operation pending forever.
	n.add(&NotifyPend{AsyncID: 3, Path: filepath.Join(t.TempDir(), "missing"), OutLen: 64,
		Meta: AsyncMeta{AsyncID: 3}})
	deadline := time.Now().Add(5 * time.Second)
	for {
		items := c.deferred.drain()
		for _, pf := range items {
			if pf.notify != nil {
				if pf.notify.status != StatusInsufficientResources {
					t.Fatalf("status = %#x, want INSUFFICIENT_RESOURCES", pf.notify.status)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("a bad watch path must complete the operation")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNotifierStopsCleanly(t *testing.T) {
	c := notifierConn()
	n := newNotifier(c)
	done := make(chan struct{})
	go func() {
		n.run()
		close(done)
	}()
	// A message sent after the stop must not block or panic.
	n.stopNow()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the notifier did not stop")
	}
	// stopNow is idempotent, and a send after it is dropped.
	n.stopNow()
	n.add(&NotifyPend{AsyncID: 1, Path: t.TempDir()})
	n.complete(NotifyDone{AsyncID: 1})
}
