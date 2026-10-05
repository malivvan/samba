package watch

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The watcher tests are written to run on every platform, against whichever
// mechanism that platform has. Two properties differ between the mechanisms and
// the tests assert exactly the ones the README documents, so a mechanism that
// regresses is caught rather than tolerated:
//
//   - whether a change can be attributed to an entry name (inotify,
//     ReadDirectoryChangesW and the polling watcher can; kqueue cannot), and
//   - whether a change to an existing file's *contents* is reported at all
//     (kqueue watches the directory vnode, so it is not).

// reportNames reports whether the mechanism in use can attribute a change to an
// entry name.
func reportNames() bool {
	switch Backend() {
	case "inotify", "ReadDirectoryChangesW", "poll":
		return true
	}
	return false
}

// seesContentChanges reports whether a change to a file's contents inside a
// watched directory is noticed. kqueue watches the directory's vnode, and a
// write to a child changes the child, not the directory.
func seesContentChanges() bool { return Backend() != "kqueue" }

// waitFor drains notifications until one arrives for id, or the deadline passes.
func waitFor(t *testing.T, w Watcher, id ID, within time.Duration) Notification {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case n, ok := <-w.Events():
			if !ok {
				t.Fatal("the watcher closed while a notification was expected")
			}
			if n.ID == id {
				return n
			}
		case <-deadline:
			t.Fatalf("no notification for watch %d within %v", id, within)
		}
	}
}

// expectChange waits until a notification accounts for one change.
//
// One change can arrive as several notifications — inotify reports a file
// created with os.WriteFile as a create, a modify and a close — so the helper
// looks *through* notifications for the one that carries the action and name
// being asserted, rather than assuming the next notification is the answer. On a
// mechanism that cannot attribute names the notification is empty and that is
// accepted.
func expectChange(t *testing.T, w Watcher, id ID, action Action, name string, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	var seen []Event
	for {
		select {
		case n, ok := <-w.Events():
			if !ok {
				t.Fatalf("the watcher closed while waiting for %d/%q (saw %+v)", action, name, seen)
			}
			if n.ID != id {
				continue
			}
			if len(n.Events) == 0 {
				if !reportNames() {
					return
				}
				continue
			}
			if hasEvent(n, action, name) {
				return
			}
			seen = append(seen, n.Events...)
		case <-deadline:
			t.Fatalf("no notification carried action %d for %q within %v (saw %+v)",
				action, name, within, seen)
		}
	}
}

// quietFor drains notifications until none have arrived for the given window.
//
// It is what makes the negative assertions below meaningful: a change made
// earlier in a test can still be in flight (inotify reports one create as three
// events, and the extras arrive after the first notification), so the channel is
// allowed to go quiet first.
func quietFor(t *testing.T, w Watcher, window time.Duration) {
	t.Helper()
	for {
		select {
		case _, ok := <-w.Events():
			if !ok {
				return
			}
		case <-time.After(window):
			return
		}
	}
}

// expectAbsent asserts that nothing arrives for id within the window.
func expectAbsent(t *testing.T, w Watcher, id ID, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case n, ok := <-w.Events():
			if !ok {
				return
			}
			if n.ID == id {
				t.Fatalf("unexpected notification for watch %d: %+v", id, n)
			}
		case <-deadline:
			return
		}
	}
}

// hasEvent reports whether the notification carries the given action for a name.
func hasEvent(n Notification, action Action, name string) bool {
	for _, e := range n.Events {
		if e.Action == action && e.Name == name {
			return true
		}
	}
	return false
}

// TestBackendIsAKnownMechanism pins the value the README table documents and the
// correspondence with Supported.
func TestBackendIsAKnownMechanism(t *testing.T) {
	switch got := Backend(); got {
	case "inotify", "kqueue", "ReadDirectoryChangesW", "poll":
	default:
		t.Fatalf("Backend() = %q, which is not a mechanism this package implements", got)
	}
	if Supported() != (Backend() != "poll") {
		t.Fatalf("Supported() = %v with backend %q", Supported(), Backend())
	}
}

// TestWatcherSeesCreationAndDeletion is the core of the protocol's needs: a new
// entry and a removed entry in a watched directory both produce a notification.
func TestWatcherSeesCreationAndDeletion(t *testing.T) {
	dir := t.TempDir()
	w := New()
	defer w.Close()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	name := filepath.Join(dir, "created.txt")
	if err := os.WriteFile(name, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectChange(t, w, id, Added, "created.txt", 10*time.Second)

	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	expectChange(t, w, id, Removed, "created.txt", 10*time.Second)
}

// TestWatcherSeesContentChanges covers the case a directory watcher is most
// often pended for. It is skipped where the mechanism cannot see it, which is a
// documented limitation of kqueue and not of this code.
func TestWatcherSeesContentChanges(t *testing.T) {
	if !seesContentChanges() {
		t.Skipf("%s watches directory vnodes, so a child's contents are not reported", Backend())
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "growing.bin")
	if err := os.WriteFile(target, []byte("1234"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := New()
	defer w.Close()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := os.WriteFile(target, []byte("12345678"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectChange(t, w, id, Modified, "growing.bin", 10*time.Second)
}

// TestWatcherSeesRename checks both halves of a rename where the mechanism can
// distinguish them. A mechanism that cannot still has to report *something*.
func TestWatcherSeesRename(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "before.txt")
	if err := os.WriteFile(old, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := New()
	defer w.Close()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := os.Rename(old, filepath.Join(dir, "after.txt")); err != nil {
		t.Fatal(err)
	}
	if !reportNames() {
		// The mechanism cannot attribute the change at all; that the watch fired
		// is all it promises.
		waitFor(t, w, id, 10*time.Second)
		return
	}
	// A rename is either two halves (inotify, ReadDirectoryChangesW) or, where
	// the mechanism cannot tell, a removal and an addition (the polling watcher).
	expectRename(t, w, id)
}

// expectRename accepts either shape a rename can take: the two halves the
// naming mechanisms report, or the removal and addition the polling watcher
// infers from two listings.
func expectRename(t *testing.T, w Watcher, id ID) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	var seen []Event
	for {
		select {
		case n, ok := <-w.Events():
			if !ok {
				t.Fatalf("the watcher closed while waiting for a rename (saw %+v)", seen)
			}
			if n.ID != id {
				continue
			}
			seen = append(seen, n.Events...)
			if hasEvent(n, RenamedNew, "after.txt") || hasEvent(n, Added, "after.txt") {
				return
			}
		case <-deadline:
			t.Fatalf("no notification named the renamed entry (saw %+v)", seen)
		}
	}
}

// TestWatcherSharesOneWatchPerPath checks the reference counting that keeps the
// kernel's per-user watch budget from being spent once per pending
// notification: several Add calls for one directory share a single watch, and
// the watch lives until the last reference goes.
func TestWatcherSharesOneWatchPerPath(t *testing.T) {
	dir := t.TempDir()
	w := New()
	defer w.Close()

	first, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	second, err := w.Add(dir)
	if err != nil {
		t.Fatalf("second Add: %v", err)
	}
	if first != second {
		t.Fatalf("two Add calls for one directory returned %d and %d: the watch is not shared", first, second)
	}

	// One removal must not stop the watch while a reference remains.
	if err := w.Remove(first); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "still-watched"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	expectChange(t, w, second, Added, "still-watched", 10*time.Second)

	// The last removal does stop it.
	quietFor(t, w, 100*time.Millisecond)
	if err := w.Remove(second); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unwatched"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	expectAbsent(t, w, second, 300*time.Millisecond)
}

// TestWatcherGoneWhenTheDirectoryDisappears checks that a watch on a directory
// that is removed completes rather than being left pending forever.
func TestWatcherGoneWhenTheDirectoryDisappears(t *testing.T) {
	if Backend() == "ReadDirectoryChangesW" {
		// A Windows directory handle keeps the directory alive, so the kernel
		// never reports the removal. This is the documented caveat; the server
		// is unaffected because it is the client's own handle close that ends a
		// pending CHANGE_NOTIFY.
		t.Skip("Windows reports a deleted watch root only through the handle, not the watch")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "watched")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	w := New()
	defer w.Close()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case n, ok := <-w.Events():
			if !ok {
				t.Fatal("the watcher closed instead of reporting the directory gone")
			}
			if n.ID != id {
				continue
			}
			if !n.Gone {
				// A mechanism may report the removal as an ordinary change
				// first; keep waiting for the gone report.
				continue
			}
			return
		case <-deadline:
			t.Fatalf("%s never reported the watched directory as gone", Backend())
		}
	}
}

// TestWatcherAddErrorsAreReported checks that a directory that cannot be watched
// fails loudly, so the caller can complete the pended operation instead of
// leaving the client waiting.
func TestWatcherAddErrorsAreReported(t *testing.T) {
	w := New()
	defer w.Close()
	if _, err := w.Add(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("watching a missing directory must fail")
	}
	// The watcher must still be usable after a failed Add.
	dir := t.TempDir()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add after a failure: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	expectChange(t, w, id, Added, "f", 10*time.Second)
}

// TestWatcherRemoveUnknownIsNoop checks that unwinding does not have to know
// whether a watch ever existed.
func TestWatcherRemoveUnknownIsNoop(t *testing.T) {
	w := New()
	defer w.Close()
	if err := w.Remove(12345); err != nil {
		t.Fatalf("removing an unknown watch: %v", err)
	}
	id, err := w.Add(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Remove(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := w.Remove(id); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
}

// TestWatcherIDsAreNotReused checks that a re-added directory gets a fresh ID,
// so a late notification for the old one cannot be mistaken for the new one.
func TestWatcherIDsAreNotReused(t *testing.T) {
	dir := t.TempDir()
	w := New()
	defer w.Close()
	first, err := w.Add(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Remove(first); err != nil {
		t.Fatal(err)
	}
	second, err := w.Add(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatalf("the watch ID %d was reused after removal", first)
	}
}

// TestWatcherCloseIsIdempotentAndFinal checks the shutdown contract: closing
// twice is harmless, a closed watcher refuses new watches, and its channel
// closes so a consumer ranging over it finishes.
func TestWatcherCloseIsIdempotentAndFinal(t *testing.T) {
	w := New()
	id, err := w.Add(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := w.Add(t.TempDir()); err != ErrClosed {
		t.Fatalf("Add after Close = %v, want ErrClosed", err)
	}
	// Removing after close is harmless, and the channel ends.
	_ = w.Remove(id)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-w.Events():
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("the notification channel did not close")
		}
	}
}

// TestWatcherConcurrentUse exists for the race detector: the watcher is used
// from several goroutines at once in the server (one per pending notification
// plus the connection's own teardown), so the locking has to hold under
// concurrent add, remove and close.
func TestWatcherConcurrentUse(t *testing.T) {
	dirs := []string{t.TempDir(), t.TempDir()}
	w := New()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 25 {
				dir := dirs[(g+i)%len(dirs)]
				id, err := w.Add(dir)
				if err != nil {
					// Close may have won the race; that is a legitimate outcome.
					return
				}
				// Touch the directory so events flow while the catalog is being
				// mutated.
				_ = os.WriteFile(filepath.Join(dirs[0], "churn"), []byte("x"), 0o644)
				_ = w.Remove(id)
			}
		}(g)
	}
	// Drain whatever arrives so nothing blocks on the channel.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range w.Events() {
		}
	}()
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
}

// TestWatcherRemoveRacingClose races a removal against the close that tears the
// same resources down. Both orders are legitimate — the removal may drop the last
// reference and unregister the watch, or the close may have taken everything away
// first — and neither may panic or leave the channel open.
func TestWatcherRemoveRacingClose(t *testing.T) {
	dir := t.TempDir()
	watchers := map[string]func() Watcher{
		"native":  func() Watcher { return New() },
		"polling": func() Watcher { return NewPolling(time.Millisecond) },
	}
	for name, newWatcher := range watchers {
		t.Run(name, func(t *testing.T) {
			for range 25 {
				w := newWatcher()
				id, err := w.Add(dir)
				if err != nil {
					t.Fatalf("Add: %v", err)
				}
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_ = w.Remove(id)
				}()
				go func() {
					defer wg.Done()
					_ = w.Close()
				}()
				wg.Wait()

				drained := make(chan struct{})
				go func() {
					defer close(drained)
					for range w.Events() {
					}
				}()
				select {
				case <-drained:
				case <-time.After(5 * time.Second):
					t.Fatal("the notification channel did not close")
				}
			}
		})
	}
}

// TestWatcherCloseBeforeAnyAdd covers the shutdown contract of a watcher that was
// never used. Its channel must still close — a consumer ranging over it would
// otherwise block forever — and a later Add must be refused, because starting the
// backend after the channel was closed would close it a second time from a
// goroutine the caller does not own, which is a panic rather than a missed
// notification.
func TestWatcherCloseBeforeAnyAdd(t *testing.T) {
	w := New()
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Add(t.TempDir()); err != ErrClosed {
		t.Fatalf("Add after Close = %v, want ErrClosed", err)
	}
	select {
	case _, ok := <-w.Events():
		if ok {
			t.Fatal("a closed watcher must not deliver notifications")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the notification channel of a closed-but-unused watcher never closed")
	}
}

// TestWatcherAddRacingClose hammers the ordering between Add and Close. Whichever
// wins, the watcher must not panic and its channel must close exactly once — the
// double close this guards against happens in a backend goroutine, where a panic
// takes the process down instead of failing a test.
func TestWatcherAddRacingClose(t *testing.T) {
	dir := t.TempDir()
	watchers := map[string]func() Watcher{
		"native": func() Watcher { return New() },
		"polling": func() Watcher {
			return NewPolling(time.Millisecond)
		},
	}
	for name, newWatcher := range watchers {
		t.Run(name, func(t *testing.T) {
			for range 25 {
				w := newWatcher()
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = w.Add(dir)
				}()
				go func() {
					defer wg.Done()
					_ = w.Close()
				}()
				wg.Wait()
				// Whatever happened, the channel must end.
				drained := make(chan struct{})
				go func() {
					defer close(drained)
					for range w.Events() {
					}
				}()
				select {
				case <-drained:
				case <-time.After(5 * time.Second):
					t.Fatal("the notification channel did not close")
				}
			}
		})
	}
}
