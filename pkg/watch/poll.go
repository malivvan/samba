package watch

import (
	"os"
	"sync"
	"time"
)

// The polling watcher is the portable fallback: it re-reads each watched
// directory every interval and diffs the listing against the previous one.
//
// It is a real implementation, not a degradation to nothing, and it is what
// platforms with no native change-notification facility actually run. Its
// limits are stated where operators will read them (README support table):
//
//   - Latency is up to one interval.
//   - A rename is reported as a removal plus an addition, because two listings
//     a second apart cannot be told apart from a delete and a create.
//   - A change that leaves the name, size and modification time of every entry
//     identical is invisible. Writing the same bytes again is not reported.
//
// It has one advantage over a kernel watch: it sees changes made by *any* means,
// including on filesystems whose change notification is unreliable.

// maxPollEvents bounds the events one sweep may carry. A directory whose
// thousands of entries all changed at once would otherwise build a notification
// far beyond anything a client asked for, so past this point the diff is
// reported as unattributable and the client re-enumerates instead.
const maxPollEvents = 1024

// pollStamp is what is compared between sweeps.
type pollStamp struct {
	size  int64
	mtime int64
	dir   bool
}

// pollWatcher implements Watcher by polling.
type pollWatcher struct {
	interval time.Duration
	catalog  *catalog
	events   chan Notification
	stop     chan struct{}
	closeOne sync.Once
	// mu orders start against Close, exactly as the native backends' mutexes do:
	// either the sweeper is running and Close stops it, or Close won and nothing
	// is ever started. Getting that wrong means the event channel is closed
	// twice, which is a panic rather than a missed notification.
	mu      sync.Mutex
	closed  bool
	started bool
}

// NewPolling returns the polling watcher with the given interval (a zero or
// negative interval selects DefaultPollInterval).
//
// It is exported for two reasons: the platforms without a native facility use it
// through New, and it can be selected explicitly so that its behaviour is
// testable everywhere instead of only on the platforms that depend on it.
func NewPolling(interval time.Duration) Watcher {
	return newPolling(interval)
}

func newPolling(interval time.Duration) *pollWatcher {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	return &pollWatcher{
		interval: interval,
		catalog:  newCatalog(),
		events:   make(chan Notification, eventBuffer),
		stop:     make(chan struct{}),
	}
}

func (p *pollWatcher) Add(dir string) (ID, error) {
	if err := p.start(); err != nil {
		return 0, err
	}
	e, err := p.catalog.acquire(dir, func(id ID) (any, error) {
		return p.list(dir)
	})
	if err != nil {
		return 0, err
	}
	return e.id, nil
}

// start launches the sweeper on the first Add, so a caller that never watches
// anything costs no goroutine and no timer. It reports ErrClosed once the watcher
// is closed, which is also what makes the ordering with Close race-free.
func (p *pollWatcher) start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	if !p.started {
		p.started = true
		go p.run()
	}
	return nil
}

// Remove drops one reference to a watch, holding p.mu so that it is ordered
// against Close exactly as the native backends' removals are.
func (p *pollWatcher) Remove(id ID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.catalog.release(id)
	return nil
}

func (p *pollWatcher) Events() <-chan Notification { return p.events }

func (p *pollWatcher) Close() error {
	p.closeOne.Do(func() {
		p.mu.Lock()
		p.closed = true
		started := p.started
		p.mu.Unlock()
		close(p.stop)
		if !started {
			// Nothing else will close the channel: the sweeper that closes it
			// never ran.
			close(p.events)
		}
	})
	return nil
}

// run sweeps the watched directories until the watcher is closed, then closes
// the notification channel so a consumer ranging over it finishes.
func (p *pollWatcher) run() {
	defer close(p.events)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.sweep()
		}
	}
}

// sweep diffs every watched directory and reports what changed.
func (p *pollWatcher) sweep() {
	for _, e := range p.catalog.snapshot() {
		select {
		case <-p.stop:
			return
		default:
		}
		entries, err := p.list(e.path)
		old, _ := e.handle.(map[string]pollStamp)
		if err != nil {
			// A directory that is gone is reported once, and the watch is dropped
			// so it is not reported again. Any other error is transient —
			// permissions, a mount that is briefly unresponsive — and is retried
			// on the next sweep rather than tearing the watch down.
			if os.IsNotExist(err) {
				p.catalog.forget(e.id)
				p.send(Notification{ID: e.id, Gone: true})
			}
			continue
		}
		p.catalog.mu.Lock()
		live := p.catalog.byID[e.id] != nil
		p.catalog.mu.Unlock()
		if !live {
			continue // removed while the listing was in flight
		}
		e.handle = entries
		events, overflow := diffListing(old, entries)
		if len(events) == 0 && !overflow {
			continue
		}
		if overflow {
			events = nil
		}
		p.send(Notification{ID: e.id, Events: events})
	}
}

// send hands a notification to the consumer, giving up if the watcher closes
// first so a consumer that stopped draining cannot pin this goroutine.
func (p *pollWatcher) send(n Notification) {
	select {
	case p.events <- n:
	case <-p.stop:
	}
}

// list reads a directory's entries as a comparable snapshot.
func (p *pollWatcher) list(dir string) (map[string]pollStamp, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]pollStamp, len(ents))
	for _, ent := range ents {
		fi, err := ent.Info()
		if err != nil {
			// An entry that vanished between the listing and the stat is simply
			// not part of this snapshot; the next sweep sees it as removed.
			continue
		}
		out[ent.Name()] = pollStamp{size: fi.Size(), mtime: fi.ModTime().UnixNano(), dir: fi.IsDir()}
	}
	return out, nil
}

// diffListing reports what changed between two listings, and whether there was
// more of it than a notification can carry.
func diffListing(old, cur map[string]pollStamp) ([]Event, bool) {
	var events []Event
	overflow := false
	add := func(a Action, name string) {
		if len(events) >= maxPollEvents {
			overflow = true
			return
		}
		events = append(events, Event{Action: a, Name: name})
	}
	for name, c := range cur {
		o, ok := old[name]
		switch {
		case !ok:
			add(Added, name)
		case o.size != c.size || o.mtime != c.mtime || o.dir != c.dir:
			add(Modified, name)
		}
	}
	for name := range old {
		if _, ok := cur[name]; !ok {
			add(Removed, name)
		}
	}
	return events, overflow
}
