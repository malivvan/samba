package samba

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"testing"
)

func TestParseHdrRejectsMalformed(t *testing.T) {
	valid := reqHdr(CmdEcho, 42, 7, 99).Bytes()
	if _, ok := ParseHdr(valid); !ok {
		t.Fatal("a well-formed header must parse")
	}
	// Every truncation of a valid header must fail cleanly rather than panic.
	for n := range len(valid) {
		if _, ok := ParseHdr(valid[:n]); ok {
			t.Fatalf("a %d-byte prefix must not parse", n)
		}
	}
	// A wrong magic, structure size, or an empty frame.
	bad := append([]byte{}, valid...)
	bad[0] = 0xFF
	if _, ok := ParseHdr(bad); ok {
		t.Fatal("a wrong magic must not parse")
	}
	bad = append([]byte{}, valid...)
	put16(bad[4:6], 63)
	if _, ok := ParseHdr(bad); ok {
		t.Fatal("a wrong structure size must not parse")
	}
	if _, ok := ParseHdr(nil); ok {
		t.Fatal("an empty frame must not parse")
	}
}

func TestParseHdrAsyncVariant(t *testing.T) {
	h := reqHdr(CmdCancel, 7, 0, 0)
	b := h.Bytes()
	put32(b[16:20], FlagAsync)
	put64(b[32:40], 0xABCD)
	put64(b[40:48], 0x1234)
	got, ok := ParseHdr(b)
	if !ok {
		t.Fatal("an async header must parse")
	}
	if got.AsyncID == nil || *got.AsyncID != 0xABCD {
		t.Fatalf("async id = %v", got.AsyncID)
	}
	if got.SessionID != 0x1234 || got.TreeID != 0 {
		t.Fatalf("session %#x tree %#x", got.SessionID, got.TreeID)
	}
	if got.Flags&FlagAsync == 0 || got.MsgID != 7 || got.Command != CmdCancel {
		t.Fatalf("header = %+v", got)
	}
	// Truncated async headers fail too.
	for n := range len(b) {
		if _, ok := ParseHdr(b[:n]); ok {
			t.Fatalf("a %d-byte async prefix must not parse", n)
		}
	}
}

func TestCmdName(t *testing.T) {
	cases := map[uint16]string{
		CmdNegotiate:      "NEGOTIATE",
		CmdSessionSetup:   "SESSION_SETUP",
		CmdLogoff:         "LOGOFF",
		CmdTreeConnect:    "TREE_CONNECT",
		CmdTreeDisconnect: "TREE_DISCONNECT",
		CmdCreate:         "CREATE",
		CmdClose:          "CLOSE",
		CmdFlush:          "FLUSH",
		CmdRead:           "READ",
		CmdWrite:          "WRITE",
		CmdLock:           "LOCK",
		CmdIoctl:          "IOCTL",
		CmdCancel:         "CANCEL",
		CmdEcho:           "ECHO",
		CmdQueryDirectory: "QUERY_DIRECTORY",
		CmdChangeNotify:   "CHANGE_NOTIFY",
		CmdQueryInfo:      "QUERY_INFO",
		CmdSetInfo:        "SET_INFO",
		0x7FFF:            "command 32767",
	}
	for cmd, want := range cases {
		if got := cmdName(cmd); got != want {
			t.Errorf("cmdName(%d) = %q, want %q", cmd, got, want)
		}
	}
}

func TestBuildReadErrShape(t *testing.T) {
	plan := &ZcReadPlan{Length: 4096, MinCount: 1, MsgID: 3, Credits: 8, TreeID: 1, SessionID: 2}
	tx := NewWriter(0)
	BuildReadErr(plan, StatusEndOfFile, tx)
	b := tx.Bytes()
	nbt := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if nbt != len(b)-4 {
		t.Fatalf("NBT length %d != %d", nbt, len(b)-4)
	}
	h := b[4:]
	if le32(h[8:12]) != StatusEndOfFile {
		t.Fatalf("status = %#x", le32(h[8:12]))
	}
	if cmd := le16(h[12:14]); cmd != CmdRead {
		t.Fatalf("command = %d", cmd)
	}
	if sid := le64(h[40:48]); sid != 2 {
		t.Fatalf("session = %#x", sid)
	}
	// The error body is the 9-byte SMB2 ERROR structure.
	if got := len(h) - 64; got != 9 {
		t.Fatalf("body is %d bytes, want 9", got)
	}
	if ss := le16(h[64:66]); ss != 9 {
		t.Fatalf("StructureSize = %d", ss)
	}
}

func TestBuildNotifyFinalSigned(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	pc := NewProtoConn(srv, 0, 0, 1)
	sc := &SignCtx{Alg: SignAesCmac, Key: [16]byte{7}}
	pc.Channels[0x1234] = &ChannelState{Sign: sc}
	meta := &AsyncMeta{MsgID: 9, SessionID: 0x1234, AsyncID: 3, WantSign: true}

	frame := BuildNotifyFinal(pc, meta, StatusSuccess, []DirEvent{{Action: fileActionAdded, Name: "a"}}, 4096)
	if frame[0] != 0 {
		t.Fatalf("the NBT prefix must be zero: %#x", frame[0])
	}
	h := frame[4:]
	if le32(h[16:20])&FlagSigned == 0 {
		t.Fatal("a signed session's completion must be signed")
	}
	if !verifySignature(h, sc) {
		t.Fatal("the signature must verify")
	}
	// Without a signing context the frame goes out unsigned rather than failing.
	pc2 := NewProtoConn(srv, 0, 0, 1)
	meta2 := &AsyncMeta{MsgID: 9, SessionID: 0x1234, AsyncID: 3, WantSign: true}
	frame = BuildNotifyFinal(pc2, meta2, StatusCancelled, nil, 4096)
	if le32(frame[4+16:4+20])&FlagSigned != 0 {
		t.Fatal("unsigned session completions must not claim to be signed")
	}
}

func TestDeriveSignCtxPerDialect(t *testing.T) {
	key := [16]byte{3}
	var preauth [64]byte
	preauth[0] = 9

	// SMB 2.0.2 and 2.1 sign with HMAC-SHA256 over the raw session key.
	for _, dialect := range []uint16{0x0202, 0x0210} {
		sc := deriveSignCtx(dialect, &key, &preauth)
		if sc.Alg != SignHmacSha256 || sc.Key != key {
			t.Fatalf("dialect %#x sign ctx = %+v", dialect, sc)
		}
	}
	// 3.1.1 derives with the preauth hash.
	sc311 := deriveSignCtx(0x0311, &key, &preauth)
	if sc311.Alg != SignAesCmac || sc311.Key != kdf128(&key, []byte("SMBSigningKey\x00"), preauth[:]) {
		t.Fatalf("3.1.1 sign ctx = %+v", sc311)
	}
	// 3.0/3.0.2 use the legacy CMAC label.
	sc30 := deriveSignCtx(0x0302, &key, &preauth)
	if sc30.Alg != SignAesCmac || sc30.Key != kdf128(&key, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00")) {
		t.Fatalf("3.0.2 sign ctx = %+v", sc30)
	}
	if sc30.Key == sc311.Key {
		t.Fatal("the 3.1.1 and 3.0.2 derivations must differ")
	}
}

func TestSignAndVerifyRountrip(t *testing.T) {
	msg := make([]byte, 128)
	msg[0], msg[1], msg[2], msg[3] = 0xFE, 'S', 'M', 'B'
	sc := &SignCtx{Alg: SignAesCmac, Key: [16]byte{5}}
	tx := NewWriter(0)
	tx.Bytes8(msg)
	signInPlace(tx, 0, tx.Len(), sc)
	if le32(tx.Bytes()[16:20])&FlagSigned == 0 {
		t.Fatal("signing must set the SIGNED flag")
	}
	if !verifySignature(tx.Bytes(), sc) {
		t.Fatal("the signature must verify")
	}
	// Any change to the message breaks it.
	tampered := append([]byte{}, tx.Bytes()...)
	tampered[100] ^= 1
	if verifySignature(tampered, sc) {
		t.Fatal("a tampered message must not verify")
	}
	// A wrong key does not verify, and a truncated message is refused.
	wrong := &SignCtx{Alg: SignAesCmac, Key: [16]byte{6}}
	if verifySignature(tx.Bytes(), wrong) {
		t.Fatal("a wrong key must not verify")
	}
	if verifySignature(tx.Bytes()[:63], sc) {
		t.Fatal("a short message must not verify")
	}
	// HMAC-SHA256 sessions sign the same way.
	sc2 := &SignCtx{Alg: SignHmacSha256, Key: [16]byte{5}}
	tx2 := NewWriter(0)
	tx2.Bytes8(msg)
	signInPlace(tx2, 0, tx2.Len(), sc2)
	if !verifySignature(tx2.Bytes(), sc2) {
		t.Fatal("HMAC-SHA256 signing must verify")
	}
	if bytes.Equal(tx.Bytes()[48:64], tx2.Bytes()[48:64]) {
		t.Fatal("the two algorithms must produce different signatures")
	}
}

func TestZcReadPlanRelease(t *testing.T) {
	// A plan without an owner is harmless to release.
	(&ZcReadPlan{}).release()
	f, err := os.CreateTemp(t.TempDir(), "plan")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	of := &OpenFile{File: f}
	// A plan whose owner was acquired: use then release is balanced, and the
	// descriptor survives because the handle is still open.
	if of.use() == nil {
		t.Fatal("use must succeed")
	}
	plan := &ZcReadPlan{Owner: of}
	plan.release()
	if of.refs.Load() != 0 {
		t.Fatalf("refs = %d after a balanced release", of.refs.Load())
	}
	// Releasing an already-released plan is a no-op (the owner is cleared).
	plan.release()
	if _, err := f.ReadAt(make([]byte, 1), 0); errors.Is(err, fs.ErrClosed) {
		t.Fatalf("a live handle's file must stay open: %v", err)
	}
	of.close()
	if _, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("close must release the descriptor, got %v", err)
	}

	// An unmatched release on a closed handle must still close the descriptor
	// rather than leaving it open forever.
	f2, err := os.CreateTemp(t.TempDir(), "plan2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f2.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	of2 := &OpenFile{File: f2}
	of2.release()
	of2.close()
	if _, err := f2.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("a handle with a negative reference count must still close, got %v", err)
	}
}
