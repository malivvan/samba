package samba

import (
	"testing"
	"time"
)

func testBreakMsg() BreakMsg {
	return BreakMsg{
		Wid:       0,
		ConnIdx:   3,
		ConnGen:   7,
		LeaseKey:  [16]byte{0x5A},
		CurState:  1,
		NewState:  0,
		Epoch:     1,
		SessionID: 0xDEAD_BEEF,
	}
}

func TestMailboxPostThenDrainRoundtrips(t *testing.T) {
	mb := NewMailbox()
	if got := mb.Drain(); len(got) != 0 {
		t.Fatalf("fresh mailbox has %d entries", len(got))
	}
	mb.Post(testBreakMsg())
	mb.Post(testBreakMsg())
	got := mb.Drain()
	if len(got) != 2 {
		t.Fatalf("drained %d, want 2", len(got))
	}
	if got[0].ConnIdx != 3 || got[0].SessionID != 0xDEAD_BEEF {
		t.Fatalf("unexpected message: %+v", got[0])
	}
	if len(mb.Drain()) != 0 {
		t.Fatal("drained queue must be empty again")
	}
}

func TestMailboxPostSignals(t *testing.T) {
	mb := NewMailbox()
	mb.Post(testBreakMsg())
	mb.Post(testBreakMsg())
	select {
	case <-mb.EventFd():
		// The wake channel fired (the eventfd equivalent).
	case <-time.After(time.Second):
		t.Fatal("post must wake the owner")
	}
	// The wake channel is edge-triggered: a single signal covers the batch.
	select {
	case <-mb.EventFd():
		t.Fatal("only one wake signal should be pending")
	default:
	}
	if mb.Len() != 2 {
		t.Fatalf("queued %d, want 2", mb.Len())
	}
}

func testGrant(lk byte, wid, idx int, gen uint16) LeaseGrant {
	return LeaseGrant{
		LeaseKey:  [16]byte{lk},
		State:     1,
		Epoch:     0,
		SessionID: 9,
		Wid:       wid,
		ConnIdx:   idx,
		ConnGen:   gen,
	}
}

func TestLeaseTableGrantBreakRelease(t *testing.T) {
	tbl := NewLeaseTable()
	key := fileKey{ShareIdx: 0, Ino: 42}
	tbl.Grant(key, testGrant(0xAA, 0, 2, 5))
	tbl.Grant(key, testGrant(0xBB, 1, 3, 6))

	// A write from the holder of key 0xAA breaks only the other key (0xBB).
	writer := [16]byte{0xAA}
	breaks := tbl.BreakConflicts(key, &writer)
	if len(breaks) != 1 {
		t.Fatalf("breaks = %d, want 1", len(breaks))
	}
	if breaks[0].LeaseKey != [16]byte{0xBB} {
		t.Fatalf("broke the wrong key: %x", breaks[0].LeaseKey)
	}
	if breaks[0].Wid != 1 || breaks[0].NewState != 0 || breaks[0].Epoch != 1 {
		t.Fatalf("unexpected break: %+v", breaks[0])
	}
	// The writer's own lease remains; releasing it empties the table.
	tbl.Release(key, [16]byte{0xAA})
	if got := tbl.BreakConflicts(key, nil); len(got) != 0 {
		t.Fatalf("table should be empty, got %+v", got)
	}
}

func TestLeaseTableUnleasedWriterBreaksAll(t *testing.T) {
	tbl := NewLeaseTable()
	key := fileKey{ShareIdx: 0, Ino: 7}
	tbl.Grant(key, testGrant(0xAA, 0, 1, 1))
	tbl.Grant(key, testGrant(0xBB, 0, 2, 1))
	// A writer with no lease key breaks every holder.
	if got := tbl.BreakConflicts(key, nil); len(got) != 2 {
		t.Fatalf("unleased writer broke %d leases, want 2", len(got))
	}
}

func TestLeaseTableReleaseConn(t *testing.T) {
	tbl := NewLeaseTable()
	tbl.Grant(fileKey{0, 10}, testGrant(0xAA, 0, 2, 5))
	tbl.Grant(fileKey{0, 11}, testGrant(0xAA, 0, 2, 5))
	tbl.Grant(fileKey{0, 11}, testGrant(0xCC, 1, 4, 9))
	// Connection (0,2,5) drops: its two grants go, the other stays.
	tbl.ReleaseConn(0, 2, 5)
	if got := tbl.BreakConflicts(fileKey{0, 10}, nil); len(got) != 0 {
		t.Fatalf("file 10 should be empty, got %+v", got)
	}
	got := tbl.BreakConflicts(fileKey{0, 11}, nil)
	if len(got) != 1 || got[0].LeaseKey != [16]byte{0xCC} {
		t.Fatalf("file 11 = %+v", got)
	}
}

func TestLeaseTableGrantRefreshes(t *testing.T) {
	tbl := NewLeaseTable()
	key := fileKey{0, 1}
	tbl.Grant(key, testGrant(0xAA, 0, 1, 1))
	g := testGrant(0xAA, 0, 2, 1)
	g.State = 3
	tbl.Grant(key, g)
	breaks := tbl.BreakConflicts(key, nil)
	if len(breaks) != 1 {
		t.Fatalf("re-grant must replace, not duplicate: %+v", breaks)
	}
	if breaks[0].ConnIdx != 2 || breaks[0].CurState != 3 {
		t.Fatalf("refresh did not take effect: %+v", breaks[0])
	}
}
