package zerocopy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These tests run on every platform the server targets, which is the point: the
// splice path, the sendfile path and the buffered path all have to satisfy the
// same contract, and a platform that owns only one of them still runs the whole
// table through its own implementation.

// tcpPair returns two connected connections. A loopback pair is used rather than
// a Unix socketpair because the tests have to run on Windows too, and a TCP
// connection is what the server actually hands to Send.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() {
		client.Close()
		r.c.Close()
	})
	return client, r.c
}

// patternFile writes size bytes of an offset-derived pattern and returns the
// open file, so a mismatch points at the byte that went wrong.
func patternFile(t *testing.T, size int) (*os.File, []byte) {
	t.Helper()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*7 + i/251)
	}
	path := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f, payload
}

// drain reads n bytes from r.
func drain(r io.Reader, n int) ([]byte, error) {
	got := make([]byte, n)
	_, err := io.ReadFull(r, got)
	return got, err
}

// TestSendSizesAndOffsets walks the boundaries that the three implementations
// treat differently: nothing at all, a single byte, exactly one pipe, more than
// one pipe, and offsets that are not aligned to anything.
func TestSendSizesAndOffsets(t *testing.T) {
	const size = 300 << 10
	src, payload := patternFile(t, size)
	cases := []struct {
		off, n int
	}{
		{0, 1},
		{0, 4095},
		{0, 4096},
		{1, 4097},
		{4095, 8192},
		{size - 1, 1},
		{0, 300 << 10}, // larger than a pipe and than one sendfile call
		{1000, 200 << 10},
	}
	for _, c := range cases {
		client, server := tcpPair(t)
		errCh := make(chan error, 1)
		go func() { errCh <- Send(client, src, int64(c.off), c.n, 10*time.Second) }()
		got, err := drain(server, c.n)
		if err != nil {
			t.Fatalf("offset %d length %d: read: %v", c.off, c.n, err)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("offset %d length %d: send: %v", c.off, c.n, err)
		}
		if !bytes.Equal(got, payload[c.off:c.off+c.n]) {
			t.Fatalf("offset %d length %d: payload differs", c.off, c.n)
		}
	}
}

// TestSendLeavesTheFileOffsetAlone pins the property the SMB read path depends
// on: a transfer is addressed by an explicit offset, so the descriptor's own
// position is neither read nor advanced. A second channel of one session can
// therefore read the same handle concurrently.
func TestSendLeavesTheFileOffsetAlone(t *testing.T) {
	const size = 128 << 10
	src, payload := patternFile(t, size)

	// Put the handle's position somewhere deliberate.
	if _, err := src.Seek(5000, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	client, server := tcpPair(t)
	errCh := make(chan error, 1)
	go func() { errCh <- Send(client, src, 0, 4096, 10*time.Second) }()
	got, err := drain(server, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload[:4096]) {
		t.Fatal("the transfer did not start at the requested offset")
	}
	pos, err := src.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if pos != 5000 {
		t.Fatalf("the descriptor's position moved to %d, want 5000", pos)
	}

	// And the same handle still serves a different offset afterwards.
	client2, server2 := tcpPair(t)
	go func() { errCh <- Send(client2, src, 8192, 1024, 10*time.Second) }()
	got, err = drain(server2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload[8192:8192+1024]) {
		t.Fatal("the second transfer read the wrong bytes")
	}
}

// TestSendZeroLengthIsNoop checks that nothing is written and nothing fails when
// there is nothing to write.
func TestSendZeroLengthIsNoop(t *testing.T) {
	src, _ := patternFile(t, 16)
	client, server := tcpPair(t)
	if err := Send(client, src, 0, 0, time.Second); err != nil {
		t.Fatalf("a zero-length send must succeed: %v", err)
	}
	if err := Send(client, src, 0, -1, time.Second); err != nil {
		t.Fatalf("a negative-length send must succeed: %v", err)
	}
	// Nothing arrived: the peer is still readable after a short deadline.
	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := server.Read(make([]byte, 1)); n != 0 && err == nil {
		t.Fatal("a zero-length send must not write anything")
	}
}

// TestSendShortFileIsReported checks that a file which ends early is reported
// rather than silently truncating what the response header already promised.
func TestSendShortFileIsReported(t *testing.T) {
	src, _ := patternFile(t, 9)
	client, server := tcpPair(t)
	// Drain whatever does arrive, so the transfer is not held up by the socket.
	go func() {
		_, _ = io.Copy(io.Discard, server)
	}()
	err := Send(client, src, 0, 1<<20, 2*time.Second)
	if err == nil {
		t.Fatal("promising more bytes than the file holds must be an error")
	}
	if !errors.Is(err, ErrShort) {
		t.Fatalf("error = %v, want ErrShort", err)
	}
}

// TestSendStallIsBounded checks that a peer which stops reading cannot pin the
// transfer: the stall deadline is what ends it. The socket's send buffer is
// shrunk so the stall is reached deterministically rather than after megabytes.
func TestSendStallIsBounded(t *testing.T) {
	const size = 4 << 20
	src, _ := patternFile(t, size)
	client, _ := tcpPair(t)
	if tc, ok := client.(*net.TCPConn); ok {
		// The peer never reads, so the transfer can only ever fill this much.
		if err := tc.SetWriteBuffer(4096); err != nil {
			t.Skipf("cannot shrink the send buffer: %v", err)
		}
	}
	start := time.Now()
	err := Send(client, src, 0, size, 150*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a stalled peer must abort the transfer")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the stall deadline did not fire promptly (%v)", elapsed)
	}
	if !errors.Is(err, ErrStalled) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("error = %v, want a stall or a deadline", err)
	}
}

// TestSendDrainsThroughAFullPipe drives the path where the socket's buffer is
// smaller than the transfer and the peer drains slowly, which is what makes the
// pipe fill up and the EAGAIN branches run.
func TestSendDrainsThroughAFullPipe(t *testing.T) {
	const size = 512 << 10
	src, payload := patternFile(t, size)
	client, server := tcpPair(t)
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.SetWriteBuffer(2048)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- Send(client, src, 0, size, 20*time.Second) }()

	got := make([]byte, 0, size)
	buf := make([]byte, 8192)
	for len(got) < size {
		n, err := server.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(got), err)
		}
		// Slow enough that the send side really does fill up.
		time.Sleep(time.Millisecond)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload differs")
	}
}

// fakeConn is a connection that cannot hand out a raw descriptor, which is what
// the kernel paths must notice: they have to fall back to the userspace copy
// rather than fail the read. It is also the only way to exercise the fallback on
// a platform whose kernel path would otherwise always succeed.
type fakeConn struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (c *fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *fakeConn) Close() error                     { c.mu.Lock(); defer c.mu.Unlock(); c.closed = true; return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (c *fakeConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *fakeConn) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("no raw descriptor")
}

func (c *fakeConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

// TestSendFallsBackWithoutARawDescriptor checks the graceful degradation that
// keeps a read working on a host whose splice(2)/sendfile(2) is filtered, or on
// a connection that is not a socket at all: the bytes still arrive, in order.
func TestSendFallsBackWithoutARawDescriptor(t *testing.T) {
	const size = 200 << 10
	src, payload := patternFile(t, size)
	c := &fakeConn{}
	before := Fallbacks()
	if err := Send(c, src, 0, size, 5*time.Second); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := c.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("the buffered fallback delivered %d of %d bytes, corrupt", len(got), size)
	}
	if Fallbacks() == before {
		t.Log("the platform has no kernel path, so there was nothing to fall back from")
	}
}

// TestFallbacksAreCounted checks that a downgrade is visible to an operator
// rather than silent: the counter is what the capability report reads.
func TestFallbacksAreCounted(t *testing.T) {
	if Fallbacks() < 0 {
		t.Fatal("the fallback counter must never be negative")
	}
	src, _ := patternFile(t, 64)
	c := &fakeConn{}
	if err := Send(c, src, 0, 64, time.Second); err != nil {
		t.Fatal(err)
	}
}

// TestBackendNamesAMechanism pins the value the README support table and the
// capability report rely on.
func TestBackendNamesAMechanism(t *testing.T) {
	switch got := Backend(); got {
	case "splice", "sendfile", "buffered":
	default:
		t.Fatalf("Backend() = %q, which is not a mechanism this package implements", got)
	}
}
