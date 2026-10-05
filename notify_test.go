package samba

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/malivvan/samba/pkg/watch"
)

// TestWatchActionsMatchTheWire pins the two action-code tables together. The
// server builds the wire form from its own constants and takes the action from
// pkg/watch, so a drift between them would send a client the wrong action for a
// change — a failure that would otherwise be invisible, because the notification
// arrives and looks well-formed.
func TestWatchActionsMatchTheWire(t *testing.T) {
	cases := []struct {
		wire uint32
		pkg  watch.Action
	}{
		{fileActionAdded, watch.Added},
		{fileActionRemoved, watch.Removed},
		{fileActionModified, watch.Modified},
		{fileActionRenamedOld, watch.RenamedOld},
		{fileActionRenamedNew, watch.RenamedNew},
	}
	for _, c := range cases {
		if uint32(c.pkg) != c.wire {
			t.Errorf("pkg/watch action %d does not match the protocol code %d", c.pkg, c.wire)
		}
	}
}

// notifierConn builds the minimum connection a notifier needs: it only queues
// completions.
func notifierConn() *conn {
	return &conn{deferred: newDeferredQueue(), done: make(chan struct{})}
}

// waitFired drains the connection's deferred queue until a notify completion
// appears.
func waitFired(t *testing.T, c *conn, within time.Duration) *notifyFired {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, pf := range c.deferred.drain() {
			if pf.notify != nil {
				return pf.notify
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the notification never completed")
	return nil
}

// TestNotifierDeliversCompletions checks that a change under a watched directory
// ends the pending CHANGE_NOTIFY.
//
// What the completion carries depends on the mechanism, and is asserted as such:
// inotify, ReadDirectoryChangesW and the polling watcher name the entry that
// changed, while kqueue can only say that the directory did — which the protocol
// expresses by telling the client to re-enumerate.
func TestNotifierDeliversCompletions(t *testing.T) {
	dir := t.TempDir()
	c := notifierConn()
	n := newNotifier(c)
	go n.run()
	defer n.stopNow()

	n.add(&NotifyPend{
		AsyncID: 7,
		Path:    dir,
		OutLen:  4096,
		Meta:    AsyncMeta{MsgID: 1, AsyncID: 7, SessionID: 2},
	})

	// Touch the directory until the watch fires: registration happens on the
	// notifier's own goroutine, so it is asynchronous with respect to this test.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if err := os.WriteFile(filepath.Join(dir, "touched"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, pf := range c.deferred.drain() {
			if pf.notify == nil {
				continue
			}
			fired := pf.notify
			if fired.status != StatusSuccess {
				t.Fatalf("completion status = %#x, want success", fired.status)
			}
			if fired.pend.AsyncID != 7 {
				t.Fatalf("completion is for %d, want 7", fired.pend.AsyncID)
			}
			if len(fired.events) > 0 {
				if fired.events[0].Name != "touched" {
					t.Fatalf("the completion named %q, want the entry that changed", fired.events[0].Name)
				}
				return
			}
			// An empty list is the documented answer where the mechanism cannot
			// attribute a change, and it means "re-enumerate".
			if watch.Backend() == "kqueue" {
				return
			}
			t.Fatalf("%s completed the notification without naming the change", watch.Backend())
		}
		if time.Now().After(deadline) {
			t.Fatal("the watch never fired")
		}
		time.Sleep(20 * time.Millisecond)
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
	if fired := waitFired(t, c, 5*time.Second); fired.status != StatusCancelled {
		t.Fatalf("status = %#x, want CANCELLED", fired.status)
	}
}

// TestNotifierSharesOneWatchForOneDirectory checks the reference counting end to
// end: two pends on one directory share a watch, and completing one leaves the
// other pending.
func TestNotifierSharesOneWatchForOneDirectory(t *testing.T) {
	dir := t.TempDir()
	c := notifierConn()
	n := newNotifier(c)
	go n.run()
	defer n.stopNow()

	for _, aid := range []uint64{11, 22} {
		n.add(&NotifyPend{AsyncID: aid, Path: dir, OutLen: 4096, Meta: AsyncMeta{AsyncID: aid}})
	}
	// Let both registrations land, then complete one of them.
	time.Sleep(100 * time.Millisecond)
	n.complete(NotifyDone{AsyncID: 11, Status: StatusCancelled})
	if fired := waitFired(t, c, 5*time.Second); fired.pend.AsyncID != 11 {
		t.Fatalf("completion is for %d, want 11", fired.pend.AsyncID)
	}

	// The other pend is still live: a change completes it.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := os.WriteFile(filepath.Join(dir, "changed"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, pf := range c.deferred.drain() {
			if pf.notify == nil {
				continue
			}
			if pf.notify.pend.AsyncID != 22 {
				t.Fatalf("completion is for %d, want 22", pf.notify.pend.AsyncID)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the second pend on the same directory never completed")
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
	if fired := waitFired(t, c, 5*time.Second); fired.status != StatusInsufficientResources {
		t.Fatalf("status = %#x, want INSUFFICIENT_RESOURCES", fired.status)
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
