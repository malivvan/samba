package watch

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The polling watcher is tested explicitly on every platform, not only on the
// platforms that depend on it: it is the graceful degradation the project
// promises, so it has to be verified wherever the test suite runs.

// pollInterval is short enough to keep the tests quick and long enough that a
// directory can be changed completely before a sweep sees it.
const pollInterval = 25 * time.Millisecond

// collect waits for one notification for id.
func collect(t *testing.T, w Watcher, id ID, within time.Duration) Notification {
	t.Helper()
	return waitFor(t, w, id, within)
}

// eventNames lists the names a notification carries, for error messages.
func eventNames(n Notification) []string {
	out := make([]string, 0, len(n.Events))
	for _, e := range n.Events {
		out = append(out, fmt.Sprintf("%d:%s", e.Action, e.Name))
	}
	return out
}

func TestPollingReportsNamedChanges(t *testing.T) {
	dir := t.TempDir()
	w := NewPolling(pollInterval)
	defer w.Close()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	target := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(target, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	n := collect(t, w, id, 5*time.Second)
	if len(n.Events) != 1 || n.Events[0].Action != Added || n.Events[0].Name != "file.txt" {
		t.Fatalf("creation reported as %v", eventNames(n))
	}

	// A change that alters the size is a modify.
	if err := os.WriteFile(target, []byte("one and two"), 0o644); err != nil {
		t.Fatal(err)
	}
	n = collect(t, w, id, 5*time.Second)
	if len(n.Events) != 1 || n.Events[0].Action != Modified || n.Events[0].Name != "file.txt" {
		t.Fatalf("modification reported as %v", eventNames(n))
	}

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	n = collect(t, w, id, 5*time.Second)
	if len(n.Events) != 1 || n.Events[0].Action != Removed || n.Events[0].Name != "file.txt" {
		t.Fatalf("removal reported as %v", eventNames(n))
	}
}

// TestPollingRenameIsRemovePlusAdd documents the shape a rename takes here: two
// listings a moment apart cannot tell a rename from a delete and a create, so
// both halves are reported and the client reconstructs the rest.
func TestPollingRenameIsRemovePlusAdd(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "before.txt")
	if err := os.WriteFile(old, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := NewPolling(pollInterval)
	defer w.Close()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := os.Rename(old, filepath.Join(dir, "after.txt")); err != nil {
		t.Fatal(err)
	}
	n := collect(t, w, id, 5*time.Second)
	var sawAdd, sawRemove bool
	for _, e := range n.Events {
		switch {
		case e.Action == Added && e.Name == "after.txt":
			sawAdd = true
		case e.Action == Removed && e.Name == "before.txt":
			sawRemove = true
		}
	}
	if !sawAdd || !sawRemove {
		t.Fatalf("rename reported as %v, want both halves", eventNames(n))
	}
}

// TestPollingReportsGone checks that a watched directory that disappears ends the
// watch instead of being polled forever.
func TestPollingReportsGone(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "watched")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	w := NewPolling(pollInterval)
	defer w.Close()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	n := collect(t, w, id, 5*time.Second)
	if !n.Gone {
		t.Fatalf("the removed directory was reported as %v, not gone", eventNames(n))
	}
	// And it is reported once, not on every sweep.
	quietFor(t, w, pollInterval/2)
	expectAbsentDir(t, w, id, 3*pollInterval)
}

// expectAbsentDir asserts no notification arrives for id in the window.
func expectAbsentDir(t *testing.T, w Watcher, id ID, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case n, ok := <-w.Events():
			if !ok {
				return
			}
			if n.ID == id {
				t.Fatalf("the gone directory was reported again: %+v", n)
			}
		case <-deadline:
			return
		}
	}
}

// TestPollingOverflowIsUnattributable checks the bound on a single sweep: a change
// too large to describe is reported as "re-enumerate" rather than as an
// unbounded event list.
func TestPollingOverflowIsUnattributable(t *testing.T) {
	dir := t.TempDir()
	// The sweeper is driven by hand here: with a one-hour interval no sweep of
	// its own can run, so the one below is guaranteed to see the complete set of
	// changes and the overflow becomes deterministic rather than a race against
	// the ticker.
	w := newPolling(time.Hour)
	defer w.Close()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	for i := range maxPollEvents + 10 {
		name := filepath.Join(dir, fmt.Sprintf("entry-%05d", i))
		if err := os.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w.sweep()
	n := collect(t, w, id, 10*time.Second)
	if n.Gone {
		t.Fatal("the directory is still there")
	}
	if n.Events != nil {
		t.Fatalf("a sweep of %d changes produced %d events, want an unattributable report",
			maxPollEvents+10, len(n.Events))
	}
}

// TestPollingQuietDirectoryIsQuiet is the negative case: nothing changed, so
// nothing is reported. Without it a watcher that fires on every sweep would
// still pass every other test here.
func TestPollingQuietDirectoryIsQuiet(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "steady"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := NewPolling(pollInterval)
	defer w.Close()
	id, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	expectAbsentDir(t, w, id, 6*pollInterval)
}

// TestPollingSharesOneWatchPerPath mirrors the shared-watch behaviour of the
// native backends, because the protocol layer relies on it being the same
// everywhere.
func TestPollingSharesOneWatchPerPath(t *testing.T) {
	dir := t.TempDir()
	w := NewPolling(pollInterval)
	defer w.Close()
	first, err := w.Add(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.Add(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("two Add calls returned %d and %d", first, second)
	}
	if err := w.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "watched"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if n := collect(t, w, second, 5*time.Second); len(n.Events) != 1 {
		t.Fatalf("after one of two removes the watch reported %v", eventNames(n))
	}
	quietFor(t, w, pollInterval/2)
	if err := w.Remove(second); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	expectAbsentDir(t, w, second, 4*pollInterval)
}

// TestPollingCloseStopsTheSweeper checks that closing ends the goroutine and the
// notification channel, so a consumer ranging over it is not left blocked.
func TestPollingCloseStopsTheSweeper(t *testing.T) {
	w := NewPolling(pollInterval)
	if _, err := w.Add(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
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

// TestPollingAddFailureIsReported checks that a missing directory fails at Add
// and does not start the sweeper.
func TestPollingAddFailureIsReported(t *testing.T) {
	w := NewPolling(pollInterval)
	defer w.Close()
	if _, err := w.Add(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("watching a missing directory must fail")
	}
	if _, err := w.Add(t.TempDir()); err != nil {
		t.Fatalf("Add after a failure: %v", err)
	}
}

// TestPollingDefaultInterval checks the constant the platforms without a native
// facility run at, and that an explicit interval is honoured.
func TestPollingDefaultInterval(t *testing.T) {
	if DefaultPollInterval <= 0 {
		t.Fatalf("DefaultPollInterval = %v", DefaultPollInterval)
	}
	if p, ok := NewPolling(0).(*pollWatcher); !ok || p.interval != DefaultPollInterval {
		t.Fatal("a zero interval must select the default")
	}
	if p, ok := NewPolling(-time.Second).(*pollWatcher); !ok || p.interval != DefaultPollInterval {
		t.Fatal("a negative interval must select the default")
	}
	if p, ok := NewPolling(time.Second).(*pollWatcher); !ok || p.interval != time.Second {
		t.Fatal("an explicit interval must be kept")
	}
}

// TestDiffListing pins the comparison the sweeper is built on, including the
// case that two identical listings produce nothing.
func TestDiffListing(t *testing.T) {
	old := map[string]pollStamp{
		"same":      {size: 1, mtime: 1},
		"grew":      {size: 1, mtime: 1},
		"touched":   {size: 1, mtime: 1},
		"removed":   {size: 1, mtime: 1},
		"becameDir": {size: 0, mtime: 1, dir: false},
	}
	cur := map[string]pollStamp{
		"same":      {size: 1, mtime: 1},
		"grew":      {size: 2, mtime: 1},
		"touched":   {size: 1, mtime: 2},
		"added":     {size: 1, mtime: 1},
		"becameDir": {size: 0, mtime: 1, dir: true},
	}
	events, overflow := diffListing(old, cur)
	if overflow {
		t.Fatal("a small diff must not overflow")
	}
	got := map[string]Action{}
	for _, e := range events {
		got[e.Name] = e.Action
	}
	want := map[string]Action{
		"grew":      Modified,
		"touched":   Modified,
		"becameDir": Modified,
		"added":     Added,
		"removed":   Removed,
	}
	if len(got) != len(want) {
		t.Fatalf("diff produced %v, want %v", got, want)
	}
	for name, action := range want {
		if got[name] != action {
			t.Fatalf("diff reported %q as %d, want %d", name, got[name], action)
		}
	}
	// Identical listings say nothing at all.
	if events, overflow := diffListing(old, old); len(events) != 0 || overflow {
		t.Fatalf("identical listings produced %v (overflow %v)", events, overflow)
	}
}

// TestDiffListingOverflow pins the bound: past maxPollEvents the diff reports the
// overflow instead of an event list nobody asked for.
func TestDiffListingOverflow(t *testing.T) {
	cur := make(map[string]pollStamp, maxPollEvents+5)
	for i := range maxPollEvents + 5 {
		cur[fmt.Sprintf("f%d", i)] = pollStamp{size: 1, mtime: 1}
	}
	events, overflow := diffListing(nil, cur)
	if !overflow {
		t.Fatalf("a diff of %d entries did not overflow", len(cur))
	}
	if len(events) != maxPollEvents {
		t.Fatalf("the bounded diff carried %d events, want %d", len(events), maxPollEvents)
	}
}
