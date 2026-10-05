package samba

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// setLimits shortens the per-client resource limits for one test and restores
// them afterwards. The limits are package variables precisely so tests can
// exercise the refusal paths without allocating tens of thousands of real
// resources.
func setLimits(t *testing.T, apply func()) {
	t.Helper()
	oldRx, oldSess, oldHandles := maxQueuedRxBytes, maxSessionsPerConn, maxHandlesPerSession
	oldTrees, oldWatches := maxTreesPerSession, maxNotifyWatchesPerConn
	oldLeaseFile, oldLeaseTotal := maxLeasesPerFile, maxLeasesTotal
	apply()
	t.Cleanup(func() {
		maxQueuedRxBytes, maxSessionsPerConn, maxHandlesPerSession = oldRx, oldSess, oldHandles
		maxTreesPerSession, maxNotifyWatchesPerConn = oldTrees, oldWatches
		maxLeasesPerFile, maxLeasesTotal = oldLeaseFile, oldLeaseTotal
	})
}

func TestBudgetAcquireAndRelease(t *testing.T) {
	b := newBudget(100)
	if !b.Acquire(60, nil) {
		t.Fatal("60 of 100 must be granted")
	}
	if b.Used() != 60 {
		t.Fatalf("used = %d, want 60", b.Used())
	}
	if !b.Acquire(40, nil) {
		t.Fatal("the remaining 40 must be granted")
	}

	// The budget is full: another request must block, not fail.
	got := make(chan bool, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		got <- b.Acquire(10, nil)
	}()
	select {
	case <-got:
		t.Fatal("acquire must block while the budget is full")
	case <-time.After(50 * time.Millisecond):
	}
	b.Release(50)
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("acquire must succeed once space is freed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquire did not wake after a release")
	}
	wg.Wait()
	b.Release(60) // 50 handed back earlier, 10 by the goroutine, 60 still held
	if b.Used() != 0 {
		t.Fatalf("used = %d after releasing everything", b.Used())
	}
}

func TestBudgetAllowsAnOversizedRequestWhenEmpty(t *testing.T) {
	b := newBudget(100)
	// A single frame larger than the whole budget must still make progress,
	// otherwise a legitimate maximum-size write could never be served.
	if !b.Acquire(500, nil) {
		t.Fatal("an oversized request must be granted when nothing else is held")
	}
	// But not while anything else is held.
	got := make(chan bool, 1)
	go func() { got <- b.Acquire(1, nil) }()
	select {
	case <-got:
		t.Fatal("a second request must not be granted while the oversized one is held")
	case <-time.After(50 * time.Millisecond):
	}
	b.Release(500)
	if ok := <-got; !ok {
		t.Fatal("the queued request must proceed once the oversized one is released")
	}
}

func TestBudgetGiveUp(t *testing.T) {
	b := newBudget(100)
	if !b.Acquire(100, nil) {
		t.Fatal("acquire failed")
	}
	// A caller whose connection is closing must be released immediately rather
	// than parked forever.
	if b.Acquire(50, func() bool { return true }) {
		t.Fatal("acquire must report failure when the caller gives up")
	}
	// One that still wants to proceed must block, and then succeed once there is
	// room again.
	got := make(chan bool, 1)
	go func() { got <- b.Acquire(50, func() bool { return false }) }()
	select {
	case <-got:
		t.Fatal("acquire must not grant a request while the budget is full")
	case <-time.After(50 * time.Millisecond):
	}
	b.Release(100)
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("acquire must succeed once space is freed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquire did not wake after a release")
	}
}

func TestBudgetShutdownReleasesWaiters(t *testing.T) {
	b := newBudget(100)
	if !b.Acquire(100, nil) {
		t.Fatal("acquire failed")
	}
	got := make(chan bool, 1)
	go func() { got <- b.Acquire(50, nil) }()
	select {
	case <-got:
		t.Fatal("acquire must block before the shutdown")
	case <-time.After(50 * time.Millisecond):
	}
	// Shutting down hands back the outstanding bytes and wakes every waiter, so
	// a connection teardown can never leave a goroutine parked.
	b.Shutdown(100)
	select {
	case ok := <-got:
		if ok {
			t.Fatal("acquire must fail once the budget is shut down")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not wake the waiter")
	}
	if b.Used() != 0 {
		t.Fatalf("used = %d after shutdown", b.Used())
	}
	if b.Acquire(1, nil) {
		t.Fatal("acquire must fail on a closed budget")
	}
}

func TestBudgetReleaseIsDefensive(t *testing.T) {
	b := newBudget(10)
	b.Release(0)
	b.Release(-5)
	// Over-releasing must not make the budget look like it has credit.
	b.Release(1000)
	if b.Used() != 0 {
		t.Fatalf("used = %d after over-release", b.Used())
	}
	if !b.Acquire(10, nil) {
		t.Fatal("the full budget must still be available")
	}
}

func TestConnLimiter(t *testing.T) {
	l := newConnLimiter(2)
	for i := range 2 {
		if !l.Acquire() {
			t.Fatalf("connection %d must be allowed", i+1)
		}
	}
	if l.Acquire() {
		t.Fatal("the third connection must be refused")
	}
	if l.Count() != 2 {
		t.Fatalf("count = %d, want 2", l.Count())
	}
	l.Release()
	if !l.Acquire() {
		t.Fatal("a released slot must be reusable")
	}
	if l.Count() != 2 {
		t.Fatalf("count = %d, want 2", l.Count())
	}
	l.Release()
	l.Release()
	if l.Count() != 0 {
		t.Fatalf("count = %d, want 0", l.Count())
	}
	// An unmatched release must not open the gate permanently.
	l.Release()
	if l.Count() != 0 {
		t.Fatalf("count = %d after an unmatched release", l.Count())
	}
	for i := range 2 {
		if !l.Acquire() {
			t.Fatalf("slot %d must still be available", i+1)
		}
	}

	unlimited := newConnLimiter(-1)
	for range 100 {
		if !unlimited.Acquire() {
			t.Fatal("a negative limit means unlimited")
		}
	}
	var nilLimiter *connLimiter
	if !nilLimiter.Acquire() || nilLimiter.Count() != 0 {
		t.Fatal("a nil limiter must behave as unlimited")
	}
	nilLimiter.Release()
}

func TestWarnRateLimit(t *testing.T) {
	// Drain the bucket: a burst is allowed, then messages are suppressed.
	allowed := 0
	for range 10000 {
		if warnAllowed() {
			allowed++
			continue
		}
		break
	}
	if allowed == 0 {
		t.Fatal("the first messages of a burst must be allowed")
	}
	if warnAllowed() {
		t.Fatal("the bucket must eventually empty")
	}
	// It refills with time, so a long-running server keeps logging.
	time.Sleep(60 * time.Millisecond)
	if !warnAllowed() {
		t.Fatal("the bucket must refill")
	}
}

func TestOpenFileReferenceCounting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	of := &OpenFile{File: f, Path: path}

	// A read takes a reference and releases the session lock; a CLOSE on another
	// channel must not close the descriptor underneath it.
	inUse := of.use()
	if inUse == nil {
		t.Fatal("use must return the file")
	}
	of.close()
	buf := make([]byte, 4)
	if _, err := inUse.ReadAt(buf, 0); err != nil {
		t.Fatalf("the descriptor was closed under an in-flight reference: %v", err)
	}
	// A new operation on a closed handle must be refused, not handed the file.
	if of.use() != nil {
		t.Fatal("use after close must report the handle closed")
	}
	// The last release closes it exactly once.
	of.release()
	if _, err := inUse.ReadAt(buf, 0); err == nil {
		t.Fatal("the descriptor must be closed once the last reference goes")
	}
	of.release() // idempotent: must not double-close or panic
	of.close()

	// Closing without any reference closes immediately.
	f2, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	of2 := &OpenFile{File: f2, Path: path}
	of2.close()
	if _, err := f2.ReadAt(buf, 0); err == nil {
		t.Fatal("close without references must close the descriptor")
	}
}

func TestConnGuardRecoversAndCloses(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	c := &conn{done: make(chan struct{}), nc: left, w: &worker{id: 1}}
	c.guard("test", func() { panic("boom") })
	if !c.closing() {
		t.Fatal("a panic must tear the connection down")
	}
	select {
	case <-c.done:
	default:
		t.Fatal("a panic must close the connection's done channel")
	}
	// The recovery path must not depend on a fully built connection either.
	bare := &conn{done: make(chan struct{}), nc: left}
	bare.guard("bare", func() { panic("bare boom") })
	if !bare.closing() {
		t.Fatal("a panic must be contained even without a worker")
	}

	// And a panic inside a nested call is contained too.
	c2 := &conn{done: make(chan struct{}), nc: left, w: &worker{id: 2}}
	c2.guard("test2", func() { c2.guard("inner", func() { panic("inner boom") }) })
	if !c2.closing() {
		t.Fatal("a nested panic must be contained")
	}
}

func TestDropFrames(t *testing.T) {
	backlog := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	got := dropFrames(backlog, 1)
	if len(got) != 2 || string(got[0]) != "b" || string(got[1]) != "c" {
		t.Fatalf("dropFrames(1) = %q", got)
	}
	if got := dropFrames(backlog, 3); len(got) != 0 {
		t.Fatalf("dropFrames(all) = %q", got)
	}
	if got := dropFrames(backlog, 5); len(got) != 0 {
		t.Fatalf("dropFrames(beyond) = %q", got)
	}
}
