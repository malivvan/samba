package reuseport

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests run on every platform and assert the *documented* behaviour of
// each, including the platforms that deliberately do not set a reuse option: on
// those, Listeners must hand back a single shared socket rather than pretending
// the facility exists.

// wantAvailable is what the capability report must say on the running platform.
func wantAvailable() bool {
	switch runtime.GOOS {
	case "windows", "plan9", "js", "wasip1":
		// Windows has no SO_REUSEPORT, and the option it does have lets another
		// process take the port over.
		return false
	}
	return true
}

func TestAvailableMatchesThePlatform(t *testing.T) {
	if got := Available(); got != wantAvailable() {
		t.Fatalf("Available() = %v on %s, want %v", got, runtime.GOOS, wantAvailable())
	}
}

// freePort returns an address nothing is listening on. The socket is closed
// before returning, so the caller has to bind it quickly; SO_REUSEADDR (and the
// fact that nothing was ever connected) keeps that reliable.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot find a free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestListenersShareOneAddress(t *testing.T) {
	addr := freePort(t)
	lns, err := Listeners(4, "tcp", addr)
	if err != nil {
		t.Fatalf("Listeners: %v", err)
	}
	defer closeAll(lns)
	if !Available() {
		if len(lns) != 1 {
			t.Fatalf("a platform without a reuse option returned %d sockets, want 1", len(lns))
		}
		return
	}
	if len(lns) != 4 {
		t.Fatalf("Listeners(4) returned %d sockets", len(lns))
	}
	for i, ln := range lns {
		if got := ln.Addr().String(); got != addr {
			t.Fatalf("listener %d is on %s, want %s", i, got, addr)
		}
	}
}

// TestListenersReuseThePort is the property the workers depend on: several
// sockets on one port, and a second batch after them once the first is closed.
func TestListenersReuseThePort(t *testing.T) {
	addr := freePort(t)
	first, err := Listeners(2, "tcp", addr)
	if err != nil {
		t.Fatalf("Listeners: %v", err)
	}
	if Available() {
		second, err := Listeners(2, "tcp", addr)
		if err != nil {
			closeAll(first)
			t.Fatalf("a second batch on the same port: %v", err)
		}
		closeAll(second)
	} else if _, err := Listeners(2, "tcp", addr); err == nil {
		// The port is already bound and this platform cannot share it, so the
		// bind must fail rather than silently take over.
		t.Fatal("a second bind on a platform without reuse must fail")
	}
	closeAll(first)
	// And the address is free again afterwards.
	again, err := Listeners(1, "tcp", addr)
	if err != nil {
		t.Fatalf("rebinding after close: %v", err)
	}
	closeAll(again)
}

// TestListenersAcceptTogether checks that the sockets a worker set is built from
// really do carry connections, whichever socket each one lands on.
func TestListenersAcceptTogether(t *testing.T) {
	addr := freePort(t)
	lns, err := Listeners(3, "tcp", addr)
	if err != nil {
		t.Fatalf("Listeners: %v", err)
	}
	defer closeAll(lns)

	// Every listener accepts in a loop, exactly as a worker does. Which socket
	// the kernel picks is its business — with SO_REUSEPORT it distributes by
	// hash rather than round-robin — so the test counts what arrives rather than
	// predicting where.
	var accepted atomic.Int64
	stop := make(chan struct{})
	var draining sync.WaitGroup
	for _, ln := range lns {
		draining.Add(1)
		go func(ln net.Listener) {
			defer draining.Done()
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				c.Close()
			}
		}(ln)
	}
	defer func() {
		close(stop)
		closeAll(lns)
		draining.Wait()
	}()
	_ = stop

	const dials = 5
	for range dials {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		c.Close()
	}
	deadline := time.Now().Add(10 * time.Second)
	for accepted.Load() < dials && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := accepted.Load(); got != dials {
		t.Fatalf("%d of %d connections were accepted", got, dials)
	}
}

func TestListenersCountIsAtLeastOne(t *testing.T) {
	addr := freePort(t)
	for _, n := range []int{0, -1} {
		lns, err := Listeners(n, "tcp", addr)
		if err != nil {
			t.Fatalf("Listeners(%d): %v", n, err)
		}
		if len(lns) != 1 {
			t.Fatalf("Listeners(%d) returned %d sockets, want 1", n, len(lns))
		}
		closeAll(lns)
	}
}

func TestListenReportsBadInput(t *testing.T) {
	if _, err := Listen("tcp", "this is not an address"); err == nil {
		t.Fatal("an unusable address must be reported")
	}
	if _, err := Listeners(2, "tcp", "this is not an address"); err == nil {
		t.Fatal("an unusable address must be reported")
	}
}
