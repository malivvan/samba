//go:build linux

package watch

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// The inotify decoder is the one part of the Linux backend that parses a kernel
// structure, so it is tested against a hand-built buffer as well as through the
// watcher: a truncated record must not be read past, and every mask the server
// asks for must map onto the protocol action the client expects.

// inotifyRecord appends one raw inotify event record to buf.
func inotifyRecord(buf []byte, wd int32, mask uint32, name string) []byte {
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(wd))
	binary.LittleEndian.PutUint32(hdr[4:8], mask)
	// cookie, unused by this server
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(name)+1))
	buf = append(buf, hdr[:]...)
	buf = append(buf, name...)
	return append(buf, 0)
}

func TestParseInotifyEvents(t *testing.T) {
	var buf []byte
	buf = inotifyRecord(buf, 1, unix.IN_CREATE, "created.txt")
	buf = inotifyRecord(buf, 1, unix.IN_MOVED_TO, "arrived.txt")
	buf = inotifyRecord(buf, 2, unix.IN_DELETE, "gone.txt")
	buf = inotifyRecord(buf, 2, unix.IN_ATTRIB, "")      // no name
	buf = inotifyRecord(buf, 3, unix.IN_DELETE_SELF, "") // the directory itself
	buf = inotifyRecord(buf, 4, unix.IN_IGNORED, "")
	buf = inotifyRecord(buf, 5, unix.IN_UNMOUNT, "")

	groups, gone := parseInotifyEvents(buf)
	if events := groups[1]; len(events) != 2 {
		t.Fatalf("watch 1 has %d events: %+v", len(events), events)
	} else {
		if events[0].Name != "created.txt" || events[0].Action != Added {
			t.Fatalf("first event = %+v", events[0])
		}
		if events[1].Action != RenamedNew {
			t.Fatalf("second event action = %d", events[1].Action)
		}
	}
	if got, ok := groups[2]; !ok {
		t.Fatal("a nameless event must still be reported")
	} else if len(got) != 1 || got[0].Action != Removed {
		t.Fatalf("watch 2 = %+v", got)
	}
	if len(gone) != 3 {
		t.Fatalf("self-gone watches = %v", gone)
	}
	// A truncated buffer must not panic or read past the end.
	for i := range len(buf) {
		_, _ = parseInotifyEvents(buf[:i])
	}
	// Nor must a record whose name length runs past the buffer.
	truncated := append([]byte(nil), buf...)
	binary.LittleEndian.PutUint32(truncated[12:16], 1<<20)
	groups, gone = parseInotifyEvents(truncated)
	if len(groups) != 0 || len(gone) != 0 {
		t.Fatalf("a record past the end of the buffer produced %v / %v", groups, gone)
	}
}

func TestParseInotifyEventActions(t *testing.T) {
	cases := []struct {
		mask uint32
		want Action
	}{
		{unix.IN_CREATE, Added},
		{unix.IN_DELETE, Removed},
		{unix.IN_MOVED_FROM, RenamedOld},
		{unix.IN_MOVED_TO, RenamedNew},
		{unix.IN_MODIFY, Modified},
		{unix.IN_CLOSE_WRITE, Modified},
		{unix.IN_ATTRIB, Modified},
	}
	for _, c := range cases {
		buf := inotifyRecord(nil, 7, c.mask, "name")
		groups, _ := parseInotifyEvents(buf)
		if got := groups[7]; len(got) != 1 || got[0].Action != c.want {
			t.Errorf("mask %#x produced %+v, want action %d", c.mask, got, c.want)
		}
		if got := groups[7]; len(got) == 1 && got[0].Name != "name" {
			t.Errorf("mask %#x lost the name", c.mask)
		}
	}
}

// TestInotifyMaskCoversTheProtocolActions checks that every action code the
// protocol can send has an inotify event behind it, so a change the client
// expects to hear about cannot go unnoticed.
func TestInotifyMaskCoversTheProtocolActions(t *testing.T) {
	wanted := []struct {
		name string
		mask uint32
	}{
		{"create", unix.IN_CREATE},
		{"delete", unix.IN_DELETE},
		{"modify contents", unix.IN_MODIFY},
		{"change attributes", unix.IN_ATTRIB},
		{"close after write", unix.IN_CLOSE_WRITE},
		{"rename away", unix.IN_MOVED_FROM},
		{"rename here", unix.IN_MOVED_TO},
		{"the directory itself", unix.IN_DELETE_SELF},
	}
	for _, want := range wanted {
		if inMask&want.mask == 0 {
			t.Errorf("the watch mask does not ask for %s (%#x)", want.name, want.mask)
		}
	}
}
