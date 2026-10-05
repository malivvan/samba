package samba

import (
	"bytes"
	"testing"
)

// rqlsCtx builds one SMB2_CREATE_CONTEXT carrying an RqLs lease request.
func rqlsCtx(data []byte) []byte {
	const (
		nameOff = 16
		dataOff = 24
	)
	w := NewWriter(0)
	w.U32(0) // Next = 0 (last)
	w.U16(nameOff)
	w.U16(4) // NameLength
	w.U16(0) // Reserved
	w.U16(dataOff)
	w.U32(uint32(len(data)))
	w.Bytes8(CtxNameRQLS) // at offset 16
	w.Zeros(4)            // pad to offset 24
	w.Bytes8(data)        // at offset 24
	return w.Bytes()
}

func TestLeaseCtxV1(t *testing.T) {
	w := NewWriter(0)
	key := [16]byte{0xAB}
	w.Bytes8(key[:])
	w.U32(LeaseReadCaching | LeaseHandleCaching)
	w.U32(0) // flags
	w.U64(0) // duration
	if w.Len() != 32 {
		t.Fatalf("v1 lease data is %d bytes, want 32", w.Len())
	}
	l, ok := parseLeaseCtx(rqlsCtx(w.Bytes()))
	if !ok {
		t.Fatal("v1 lease must parse")
	}
	if l.Key != key {
		t.Fatalf("key = %x", l.Key)
	}
	if l.State != LeaseReadCaching|LeaseHandleCaching {
		t.Fatalf("state = %#x", l.State)
	}
	if l.V2 {
		t.Fatal("a 32-byte lease request is v1")
	}
}

func TestLeaseCtxV2(t *testing.T) {
	w := NewWriter(0)
	key := [16]byte{0x11}
	parent := [16]byte{0x22}
	w.Bytes8(key[:])
	w.U32(LeaseReadCaching | LeaseWriteCaching | LeaseHandleCaching)
	w.U32(0) // flags
	w.U64(0) // duration
	w.Bytes8(parent[:])
	w.U16(7) // epoch
	w.U16(0) // reserved
	if w.Len() != 52 {
		t.Fatalf("v2 lease data is %d bytes, want 52", w.Len())
	}
	l, ok := parseLeaseCtx(rqlsCtx(w.Bytes()))
	if !ok {
		t.Fatal("v2 lease must parse")
	}
	if l.Key != key || !l.V2 || l.Parent != parent || l.Epoch != 7 {
		t.Fatalf("parsed v2 lease = %+v", l)
	}
}

func TestNoLeaseCtx(t *testing.T) {
	// A non-RqLs context (name "MxAc") must yield nothing.
	w := NewWriter(0)
	w.U32(0)
	w.U16(16)
	w.U16(4)
	w.U16(0)
	w.U16(0) // data offset
	w.U32(0) // data length
	w.Bytes8([]byte("MxAc"))
	l, ok := parseLeaseCtx(w.Bytes())
	if ok || l != nil {
		t.Fatalf("non-RqLs context must not parse as a lease: %+v", l)
	}
}

func TestParseLeaseCtxTruncated(t *testing.T) {
	if _, ok := parseLeaseCtx(nil); ok {
		t.Fatal("empty context list must not parse")
	}
	if _, ok := parseLeaseCtx([]byte{1, 2, 3}); ok {
		t.Fatal("a short context list must not parse")
	}
	// A self-referencing Next offset must not loop forever.
	w := NewWriter(0)
	w.U32(4) // Next == 4 < len(buf): walk forward without progress
	w.U16(16)
	w.U16(4)
	w.U16(0)
	w.U16(24)
	w.U32(0)
	w.Bytes8([]byte("RqLs"))
	if _, ok := parseLeaseCtx(w.Bytes()); ok {
		t.Fatal("a context with no lease data must not parse as a v1 lease")
	}
}

func TestBuildLeaseBreakShape(t *testing.T) {
	key := [16]byte{0x5A}
	sign := &SignCtx{Alg: SignAesCmac, Key: [16]byte{1}}
	frame := BuildLeaseBreak(&key, 1, 0, 3, 0xABCD, sign)
	nbt := int(frame[1])<<16 | int(frame[2])<<8 | int(frame[3])
	if nbt != len(frame)-4 {
		t.Fatalf("NBT length %d != %d", nbt, len(frame)-4)
	}
	h := frame[4:]
	if got := le16(h[12:14]); got != CmdOplockBreak {
		t.Fatalf("command = %d", got)
	}
	if got := le64(h[24:32]); got != ^uint64(0) {
		t.Fatalf("MessageId = %#x, want the notification sentinel", got)
	}
	if got := le64(h[40:48]); got != 0xABCD {
		t.Fatalf("session id = %#x", got)
	}
	// The signature is set (the frame is signed when a signing context exists).
	if le32(h[16:20])&FlagSigned == 0 {
		t.Fatal("frame must be signed")
	}
	body := h[64:]
	if got := le16(body[0:2]); got != 44 {
		t.Fatalf("body StructureSize = %d", got)
	}
	if got := le16(body[2:4]); got != 3 {
		t.Fatalf("NewEpoch = %d", got)
	}
	if !bytes.Equal(body[8:24], key[:]) {
		t.Fatalf("lease key = % x", body[8:24])
	}
	if got := le32(body[24:28]); got != 1 {
		t.Fatalf("CurrentLeaseState = %d", got)
	}
	if got := le32(body[28:32]); got != 0 {
		t.Fatalf("NewLeaseState = %d", got)
	}
}

func TestBuildNotifyFinalDegradesToReenumerate(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	pc := NewProtoConn(srv, 0, 0, 1)
	meta := &AsyncMeta{MsgID: 7, SessionID: 0x1234, AsyncID: 9}

	// Success with no events degrades to STATUS_NOTIFY_ENUM_DIR.
	frame := BuildNotifyFinal(pc, meta, StatusSuccess, nil, 4096)
	if got := le32(frame[4+8 : 4+12]); got != StatusNotifyEnumDir {
		t.Fatalf("status = %#x, want NOTIFY_ENUM_DIR", got)
	}
	if got := le32(frame[4+16 : 4+20]); got != FlagResponse|FlagAsync {
		t.Fatalf("flags = %#x", got)
	}

	// Success with events that do not fit the client buffer degrades too.
	events := make([]DirEvent, 0, 64)
	for i := range 64 {
		events = append(events, DirEvent{Action: fileActionAdded, Name: "some-name"})
		_ = i
	}
	frame = BuildNotifyFinal(pc, meta, StatusSuccess, events, 8)
	if got := le32(frame[4+8 : 4+12]); got != StatusNotifyEnumDir {
		t.Fatalf("overflow status = %#x", got)
	}

	// A failure status is passed through.
	frame = BuildNotifyFinal(pc, meta, StatusCancelled, nil, 4096)
	if got := le32(frame[4+8 : 4+12]); got != StatusCancelled {
		t.Fatalf("cancel status = %#x", got)
	}

	// Success with events that fit carries them.
	frame = BuildNotifyFinal(pc, meta, StatusSuccess, []DirEvent{{Action: fileActionAdded, Name: "x"}}, 4096)
	if got := le32(frame[4+8 : 4+12]); got != StatusSuccess {
		t.Fatalf("status = %#x", got)
	}
	if !bytes.Contains(frame, UTF16LE("x")) {
		t.Fatal("the event name must be present")
	}
}
