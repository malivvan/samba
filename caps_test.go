package samba

import (
	"testing"
)

// Protocol-level tests for the per-client resource limits: each one must be
// refused with a protocol error rather than allowed to grow without bound.

// sessionSetupEmpty builds an anonymous SESSION_SETUP, which establishes a guest
// session and therefore allocates one.
func sessionSetupEmpty(msgID uint64) []byte {
	f := reqHdr(CmdSessionSetup, msgID, 0, 0)
	f.U16(25)
	f.U8(0) // flags
	f.U8(1) // security mode: signing enabled
	f.U32(0)
	f.U32(0)
	f.U16(88) // security buffer offset
	f.U16(0)  // no security buffer → anonymous
	f.U64(0)
	return f.Bytes()
}

func TestSessionPerConnectionCap(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	setLimits(t, func() { maxSessionsPerConn = 2 })
	pc := NewProtoConn(srv, 0, 0, 1)

	for i := range 2 {
		r := roundtrip(t, srv, pc, sessionSetupEmpty(uint64(i+1)))
		if r.status != StatusSuccess {
			t.Fatalf("session %d status %#x", i+1, r.status)
		}
	}
	if got := len(pc.Channels); got != 2 {
		t.Fatalf("connection holds %d sessions, want 2", got)
	}
	r := roundtrip(t, srv, pc, sessionSetupEmpty(3))
	if r.status != StatusInsufficientResources {
		t.Fatalf("status beyond the per-connection limit = %#x, want INSUFFICIENT_RESOURCES", r.status)
	}
	if got := len(pc.Channels); got != 2 {
		t.Fatalf("a refused session must not be recorded: %d", got)
	}
}

func TestSessionTotalCap(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	srv.sessions.limit = 1
	pc := NewProtoConn(srv, 0, 0, 1)

	if r := roundtrip(t, srv, pc, sessionSetupEmpty(1)); r.status != StatusSuccess {
		t.Fatalf("first session status %#x", r.status)
	}
	if r := roundtrip(t, srv, pc, sessionSetupEmpty(2)); r.status != StatusInsufficientResources {
		t.Fatalf("status beyond the server session limit = %#x, want INSUFFICIENT_RESOURCES", r.status)
	}
}

func TestTreeConnectCap(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	setLimits(t, func() { maxTreesPerSession = 1 })
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, _ := establish(t, srv, pc)

	path := UTF16LE(`\\srv\t`)
	f := reqHdr(CmdTreeConnect, 4, 0, sess)
	f.U16(9)
	f.U16(0)
	f.U16(72)
	f.U16(uint16(len(path)))
	f.Bytes8(path)
	if r := roundtrip(t, srv, pc, f.Bytes()); r.status != StatusInsufficientResources {
		t.Fatalf("status beyond the tree limit = %#x, want INSUFFICIENT_RESOURCES", r.status)
	}
}

func TestHandleCap(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	setLimits(t, func() { maxHandlesPerSession = 1 })
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)

	st, fid := createFile(t, srv, pc, sess, tree, "one.txt", fileOverwriteIf, 0x40, 0x1000_0000)
	if st != StatusSuccess {
		t.Fatalf("first create status %#x", st)
	}
	if st, _ = createFile(t, srv, pc, sess, tree, "two.txt", fileOverwriteIf, 0x40, 0x1000_0000); st != StatusInsufficientResources {
		t.Fatalf("status beyond the handle limit = %#x, want INSUFFICIENT_RESOURCES", st)
	}
	// Closing the first handle makes room again.
	cl := reqHdr(CmdClose, 30, tree, sess)
	cl.U16(24)
	cl.U16(1)
	cl.U32(0)
	cl.U64(fid)
	cl.U64(fid)
	if r := roundtrip(t, srv, pc, cl.Bytes()); r.status != StatusSuccess {
		t.Fatalf("close status %#x", r.status)
	}
	if st, _ = createFile(t, srv, pc, sess, tree, "two.txt", fileOverwriteIf, 0x40, 0x1000_0000); st != StatusSuccess {
		t.Fatalf("closing a handle must make room, got %#x", st)
	}
}

func TestNotifyWatchCap(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	setLimits(t, func() { maxNotifyWatchesPerConn = 1 })
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)

	st, dfid := createFile(t, srv, pc, sess, tree, "", fileOpen, 0x1, 0x8000_0000)
	if st != StatusSuccess {
		t.Fatalf("open root status %#x", st)
	}
	notify := func(msgID uint64) uint32 {
		f := reqHdr(CmdChangeNotify, msgID, tree, sess)
		f.U16(32)
		f.U16(0)
		f.U32(65536)
		f.U64(dfid)
		f.U64(dfid)
		f.U32(0x1F)
		return roundtrip(t, srv, pc, f.Bytes()).status
	}
	if st := notify(20); st != StatusPending {
		t.Fatalf("first change notify status %#x, want PENDING", st)
	}
	if st := notify(21); st != StatusInsufficientResources {
		t.Fatalf("status beyond the watch limit = %#x, want INSUFFICIENT_RESOURCES", st)
	}
	// Cancelling the pending one frees the slot. A CANCEL carries no response of
	// its own: the *pended* operation completes with STATUS_CANCELLED.
	aid := pc.NotifyActive[0][1]
	cancel := reqHdr(CmdCancel, 22, 0, 0)
	cb := cancel.Bytes()
	put32(cb[16:20], FlagAsync) // the header carries AsyncId/SessionId instead
	put64(cb[32:40], aid)
	put64(cb[40:48], sess)
	cancel.U16(4) // StructureSize
	cancel.U16(0)
	tx := NewWriter(0)
	if act, _ := ProcessFrame(srv, pc, cancel.Bytes(), tx); act != actionRespond {
		t.Fatal("a cancel must not close the connection")
	}
	if tx.Len() != 0 {
		t.Fatalf("a cancel has no response of its own, got %d bytes", tx.Len())
	}
	if len(pc.NotifyDone) != 1 || pc.NotifyDone[0].Status != StatusCancelled {
		t.Fatalf("the cancel must complete the pending notify: %+v", pc.NotifyDone)
	}
	if len(pc.NotifyActive) != 0 {
		t.Fatalf("the cancel must release the pending slot: %+v", pc.NotifyActive)
	}
	if st := notify(23); st != StatusPending {
		t.Fatalf("change notify after cancel status %#x", st)
	}
}

func TestSearchPatternTooLong(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)
	st, dfid := createFile(t, srv, pc, sess, tree, "", fileOpen, 0x1, 0x8000_0000)
	if st != StatusSuccess {
		t.Fatalf("open root status %#x", st)
	}

	long := make([]rune, maxSearchPatternRunes+1)
	for i := range long {
		long[i] = 'a'
	}
	pat := UTF16LE(string(long))
	f := reqHdr(CmdQueryDirectory, 20, tree, sess)
	f.U16(33)
	f.U8(fileIDBothDirectoryInformation)
	f.U8(0)
	f.U32(0)
	f.U64(dfid)
	f.U64(dfid)
	f.U16(96)
	f.U16(uint16(len(pat)))
	f.U32(65536)
	f.Bytes8(pat)
	if r := roundtrip(t, srv, pc, f.Bytes()); r.status != StatusObjectNameInvalid {
		t.Fatalf("status for an oversized pattern = %#x, want OBJECT_NAME_INVALID", r.status)
	}
}

func TestLeaseTableCaps(t *testing.T) {
	setLimits(t, func() { maxLeasesPerFile = 1 })
	tbl := NewLeaseTable()
	key := fileKey{ShareIdx: 0, Ino: 1}
	if !tbl.Grant(key, testGrant(0xAA, 0, 1, 1)) {
		t.Fatal("the first lease must be granted")
	}
	if tbl.Grant(key, testGrant(0xBB, 0, 1, 1)) {
		t.Fatal("a second lease on the same file must be refused at the cap")
	}
	// Refreshing an existing key is always allowed.
	if !tbl.Grant(key, testGrant(0xAA, 0, 1, 1)) {
		t.Fatal("refreshing an existing lease must be allowed")
	}
	// Releasing makes room.
	tbl.Release(key, [16]byte{0xAA})
	if !tbl.Grant(key, testGrant(0xBB, 0, 1, 1)) {
		t.Fatal("a lease must be grantable after a release")
	}

	// And a global cap is enforced across files.
	setLimits(t, func() { maxLeasesTotal = 2 })
	tbl2 := NewLeaseTable()
	if !tbl2.Grant(fileKey{0, 1}, testGrant(0x01, 0, 1, 1)) ||
		!tbl2.Grant(fileKey{0, 2}, testGrant(0x02, 0, 1, 1)) {
		t.Fatal("the first two leases must be granted")
	}
	if tbl2.Grant(fileKey{0, 3}, testGrant(0x03, 0, 1, 1)) {
		t.Fatal("the total lease cap must be enforced")
	}
	// A break returns the lease.
	tbl2.BreakConflicts(fileKey{0, 1}, nil)
	if !tbl2.Grant(fileKey{0, 3}, testGrant(0x03, 0, 1, 1)) {
		t.Fatal("a broken lease must free its slot")
	}
	// Connection teardown returns them too.
	tbl2.ReleaseConn(0, 1, 1)
	if !tbl2.Grant(fileKey{0, 4}, testGrant(0x04, 0, 1, 1)) {
		t.Fatal("a released connection must free its slots")
	}
}

// TestCreateWithoutLeaseWhenTableIsFull checks that a CREATE still succeeds when
// the lease table is full: the client simply does not get to cache.
func TestCreateWithoutLeaseWhenTableIsFull(t *testing.T) {
	setLimits(t, func() { maxLeasesPerFile = 0 })
	dir := t.TempDir()
	srv := testSrv(t, dir, nil)
	srv.cfg.Oplocks = true
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)

	var key [16]byte
	key[0] = 0x5A
	data := NewWriter(0)
	data.Bytes8(key[:])
	data.U32(LeaseReadCaching | LeaseHandleCaching)
	data.U32(0)
	data.U64(0)

	n := UTF16LE("leased.txt")
	f := reqHdr(CmdCreate, 20, tree, sess)
	f.U16(57)
	f.U8(0)
	f.U8(OplockLease) // a lease is requested via RqLs
	f.U32(2)
	f.U64(0)
	f.U64(0)
	f.U32(0x1000_0000)
	f.U32(0)
	f.U32(7)
	f.U32(fileOpenIf)
	f.U32(0)
	f.U16(120)
	f.U16(uint16(len(n)))
	ctx := rqlsCtx(data.Bytes())
	f.U32(64 + 56 + uint32(len(n)))
	f.U32(uint32(len(ctx)))
	f.Bytes8(n)
	f.Bytes8(ctx)

	r := roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("create status %#x, want SUCCESS without a lease", r.status)
	}
	if oplock := r.body[2]; oplock != OplockNone {
		t.Fatalf("granted oplock = %#x, want none when the table is full", oplock)
	}
}
