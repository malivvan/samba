//go:build unix

package zerocopy

import (
	"errors"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// The sendfile pump's accounting is the part of that path that is easy to get
// wrong and hard to notice: its bytes live nowhere the pump can count them, so
// the syscall's return value is the only record of what reached the socket. These
// tests drive it with fake senders instead of a kernel, which means the behaviour
// of macOS's sendfile(2) — partial progress reported *together with* EAGAIN — is
// checked on every platform rather than only on the one whose syscall does it.

// fakeSender records what it was asked for and hands back a scripted answer per
// call, so a test can assert that the offsets the pump used tile the file exactly.
type fakeSender struct {
	calls   []call // "off:count" per call, for the tiling assertion
	sent    int    // bytes the fake claims to have delivered
	answers []answer
	i       int
}

type call struct {
	off, count, delivered int
}

type answer struct {
	k   int
	err error
}

// String renders a call the way the assertions report it.
func (c call) String() string {
	return strconv.Itoa(c.off) + "+" + strconv.Itoa(c.count) + "->" + strconv.Itoa(c.delivered)
}

func (f *fakeSender) chunk(off int64, count int) (int, error) {
	if f.i >= len(f.answers) {
		// Past the script: refuse to move anything, as a full socket would.
		f.calls = append(f.calls, call{off: int(off), count: count})
		return 0, syscall.EAGAIN
	}
	a := f.answers[f.i]
	f.i++
	// The recorded figure is what the pump was told, which may be an impossible
	// count — one test relies on that.
	f.calls = append(f.calls, call{off: int(off), count: count, delivered: a.k})
	if a.k > 0 {
		f.sent += a.k
	}
	return a.k, a.err
}

// noWait is the "the socket is writable" answer for tests that must not sleep.
func noWait() error { return nil }

// TestPumpChunksCountsProgressReportedWithAnError is the macOS case: sendfile
// queues what fits and answers EAGAIN for the rest, with the in/out length set to
// what it queued. Losing that count would desynchronize the transfer, so the
// assertion is not just "it finished" — it is that the offsets the pump handed to
// the kernel tile the file exactly, with no byte sent twice and none skipped.
func TestPumpChunksCountsProgressReportedWithAnError(t *testing.T) {
	const n = 300 << 10
	// Every call queues a little and reports EAGAIN, exactly as a non-blocking
	// sendfile against a small socket buffer does.
	var answers []answer
	for done := 0; done < n; {
		k := min(4096, n-done)
		answers = append(answers, answer{k: k, err: syscall.EAGAIN})
		done += k
	}
	// A last call that finds the file drained.
	answers = append(answers, answer{})
	f := &fakeSender{answers: answers}

	sent, err := pumpChunks(0, n, 5*time.Second, noWait, f.chunk)
	if err != nil {
		t.Fatalf("pump: %v", err)
	}
	if sent != n {
		t.Fatalf("sent %d of %d bytes", sent, n)
	}
	if f.sent != n {
		t.Fatalf("the fake delivered %d bytes but the pump asked for %d", f.sent, n)
	}
	// The offsets must tile the file: each call starts exactly where the bytes
	// delivered so far ended, so nothing is sent twice and nothing is skipped —
	// which is the property the partial-with-error case threatens.
	at := 0
	for i, c := range f.calls {
		if c.off != at {
			t.Fatalf("call %d used offset %d, want %d (calls: %v)", i, c.off, at, f.calls)
		}
		if c.count <= 0 || c.count > maxChunk {
			t.Fatalf("call %d asked for %d bytes (calls: %v)", i, c.count, f.calls)
		}
		at += c.delivered
	}
	if at != n {
		t.Fatalf("the calls delivered %d bytes in total, want %d", at, n)
	}
}

// TestPumpChunksTilesEveryStep checks the ordinary path: a sender that reports
// success and progress, in chunks of different sizes, still lands exactly on the
// requested byte count.
func TestPumpChunksTilesEveryStep(t *testing.T) {
	const n = 5000
	f := &fakeSender{answers: []answer{{k: 1}, {k: 4998}, {k: 1}}}
	sent, err := pumpChunks(100, n, 5*time.Second, noWait, f.chunk)
	if err != nil {
		t.Fatalf("pump: %v", err)
	}
	if sent != n {
		t.Fatalf("sent %d of %d", sent, n)
	}
	want := []string{"100+5000->1", "101+4999->4998", "5099+1->1"}
	if len(f.calls) != len(want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	for i := range want {
		if f.calls[i].String() != want[i] {
			t.Fatalf("call %d = %s, want %s", i, f.calls[i], want[i])
		}
	}
}

// TestPumpChunksReportsAStall checks that a peer which never lets the kernel make
// progress is given up on within the stall budget rather than pinning the
// transfer.
func TestPumpChunksReportsAStall(t *testing.T) {
	f := &fakeSender{} // past the script: always EAGAIN, never any progress
	start := time.Now()
	sent, err := pumpChunks(0, 1<<20, 50*time.Millisecond, noWait, f.chunk)
	if !errors.Is(err, ErrStalled) {
		t.Fatalf("error = %v, want ErrStalled", err)
	}
	if sent != 0 {
		t.Fatalf("sent %d bytes of a stalled transfer", sent)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the stall budget did not fire promptly (%v)", elapsed)
	}
}

// TestPumpChunksReportsAShortFile checks that a file which ends before the
// promised count is reported rather than silently truncating the response.
func TestPumpChunksReportsAShortFile(t *testing.T) {
	// Success with no progress, repeatedly: the socket is writable and has
	// nothing left to send.
	f := &fakeSender{answers: []answer{{}, {}, {}}}
	sent, err := pumpChunks(0, 4096, time.Second, noWait, f.chunk)
	if !errors.Is(err, ErrShort) {
		t.Fatalf("error = %v, want ErrShort", err)
	}
	if sent != 0 {
		t.Fatalf("sent %d bytes of an empty file", sent)
	}
}

// TestPumpChunksDoesNotCountProgressWithAFatalError pins the line between the two
// kinds of error. A busy error may carry a count, because the kernel documents
// that it wrote one; a fatal error may leave the length untouched, so its value
// could be the count that went in. Believing that would fabricate a transfer that
// never happened — the client would be told a response was delivered and would
// never receive it.
func TestPumpChunksDoesNotCountProgressWithAFatalError(t *testing.T) {
	f := &fakeSender{answers: []answer{{k: 8, err: syscall.EIO}}}
	sent, err := pumpChunks(0, 4096, time.Second, noWait, f.chunk)
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("error = %v, want EIO", err)
	}
	if sent != 0 {
		t.Fatalf("sent %d bytes from a call that failed fatally", sent)
	}
}

// TestPumpChunksCountsAFullChunkWithABusyError is the other end of the same
// question: on macOS and the BSDs a call can report EAGAIN having sent
// *everything* it was asked for, having checked the socket buffer before noticing
// it had run out of bytes. Treating that as "make no progress" would re-send the
// same bytes from the same offset.
func TestPumpChunksCountsAFullChunkWithABusyError(t *testing.T) {
	f := &fakeSender{answers: []answer{
		{k: 4096, err: syscall.EAGAIN}, // everything asked for, plus a busy error
		{k: 96},
	}}
	sent, err := pumpChunks(0, 4192, time.Second, noWait, f.chunk)
	if err != nil {
		t.Fatalf("pump: %v", err)
	}
	if sent != 4192 {
		t.Fatalf("sent %d of 4192", sent)
	}
	if len(f.calls) != 2 || f.calls[0].off != 0 || f.calls[1].off != 4096 {
		t.Fatalf("calls = %v, want offsets 0 and 4096", f.calls)
	}
}

// TestPumpChunksRetriesAnInterruptedCall checks EINTR: a signal must not end the
// transfer.
func TestPumpChunksRetriesAnInterruptedCall(t *testing.T) {
	f := &fakeSender{answers: []answer{{err: syscall.EINTR}, {k: 64}}}
	sent, err := pumpChunks(0, 64, time.Second, noWait, f.chunk)
	if err != nil {
		t.Fatalf("pump: %v", err)
	}
	if sent != 64 {
		t.Fatalf("sent %d of 64", sent)
	}
}

// TestPumpChunksPropagatesAFatalError checks that anything that is not "busy" or
// "interrupted" stops the transfer with the kernel's own error.
func TestPumpChunksPropagatesAFatalError(t *testing.T) {
	f := &fakeSender{answers: []answer{{k: 32}, {err: syscall.EIO}}}
	sent, err := pumpChunks(0, 4096, time.Second, noWait, f.chunk)
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("error = %v, want EIO", err)
	}
	if sent != 32 {
		t.Fatalf("sent %d, want the 32 that were delivered first", sent)
	}
}

// TestPumpChunksIgnoresAnImpossibleCount checks the sanity bound: a count larger
// than the call asked for cannot be honoured, because advancing by it would skip
// bytes that never left — the one input that could turn into missing data inside
// a response whose length is already promised.
func TestPumpChunksIgnoresAnImpossibleCount(t *testing.T) {
	// Claims to have sent 1<<20 when asked for 16, on every call, with an error
	// that is not a wait condition: the pump must not count it.
	f := &fakeSender{answers: []answer{{k: 1 << 20, err: syscall.EIO}, {k: 1 << 20, err: syscall.EIO}}}
	sent, err := pumpChunks(0, 16, time.Second, noWait, f.chunk)
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("error = %v, want EIO", err)
	}
	if sent != 0 {
		t.Fatalf("sent %d bytes for a count the call never asked for", sent)
	}
}
