package samba

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// testSrv builds a shared server context for protocol tests.
func testSrv(t *testing.T, dir string, users []UserCfg) *Srv {
	t.Helper()
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Listen = "127.0.0.1:445"
	cfg.Workers = 1
	cfg.ServerName = "TESTSRV"
	cfg.LogLevel = LevelWarn
	cfg.Oplocks = false
	cfg.Shares = []ShareCfg{{Name: "t", Path: dir}}
	cfg.Users = users
	udb, err := cfg.UserDB()
	if err != nil {
		t.Fatal(err)
	}
	return &Srv{
		cfg:        *cfg,
		guid:       [16]byte{9},
		maxRead:    MaxReadTarget,
		users:      udb,
		allowGuest: cfg.GuestAllowed(),
		sessions:   NewRegistry(),
		mailboxes:  []*Mailbox{NewMailbox()},
		leases:     NewLeaseTable(),
	}
}

func reqHdr(cmd uint16, msgID uint64, tree uint32, sess uint64) *Writer {
	w := NewWriter(hdrLen)
	w.Bytes8([]byte{0xFE, 'S', 'M', 'B'})
	w.U16(64)
	w.U16(1) // credit charge
	w.U32(0) // status
	w.U16(cmd)
	w.U16(64) // credits requested
	w.U32(0)  // flags
	w.U32(0)  // next command
	w.U64(msgID)
	w.U32(0) // process id
	w.U32(tree)
	w.U64(sess)
	w.Zeros(16)
	return w
}

func processOnce(t *testing.T, srv *Srv, pc *ProtoConn, frame []byte) *Writer {
	t.Helper()
	tx := NewWriter(0)
	act, plan := ProcessFrame(srv, pc, frame, tx)
	switch act {
	case actionRespond:
	case actionZcRead:
		t.Fatalf("unexpected zero-copy plan (len %d)", plan.Length)
	case actionClose:
		t.Fatal("unexpected close")
	}
	return tx
}

type resp struct {
	status    uint32
	flags     uint32
	treeID    uint32
	sessionID uint64
	body      []byte
}

func roundtrip(t *testing.T, srv *Srv, pc *ProtoConn, frame []byte) resp {
	t.Helper()
	tx := processOnce(t, srv, pc, frame)
	b := tx.Bytes()
	if len(b) <= 68 {
		t.Fatalf("no response produced (%d bytes)", len(b))
	}
	nbt := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if nbt != len(b)-4 {
		t.Fatalf("NBT length %d != frame length %d", nbt, len(b)-4)
	}
	h := b[4:68]
	return resp{
		status:    le32(h[8:12]),
		flags:     le32(h[16:20]),
		treeID:    le32(h[36:40]),
		sessionID: le64(h[40:48]),
		body:      append([]byte{}, b[68:]...),
	}
}

// establish drives NEGOTIATE → SESSION_SETUP (guest) → TREE_CONNECT over the
// protocol entry point and returns the session and tree ids.
func establish(t *testing.T, srv *Srv, pc *ProtoConn) (uint64, uint32) {
	t.Helper()
	// NEGOTIATE offering 2.1 / 3.0 / 3.0.2.
	f := reqHdr(CmdNegotiate, 0, 0, 0)
	f.U16(36)
	f.U16(3) // dialect count
	f.U16(1) // security mode
	f.U16(0)
	f.U32(0)
	f.Zeros(16 + 8)
	f.U16(0x0210)
	f.U16(0x0300)
	f.U16(0x0302)
	r := roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("negotiate status %#x", r.status)
	}
	if dialect := le16(r.body[4:6]); dialect != 0x0302 {
		t.Fatalf("negotiated dialect %#x", dialect)
	}

	// SESSION_SETUP: NTLMSSP NEGOTIATE → challenge.
	blob := append([]byte{}, ntlmSig...)
	blob = append(blob, 1, 0, 0, 0)
	f = reqHdr(CmdSessionSetup, 1, 0, 0)
	f.U16(25)
	f.U8(0)
	f.U8(1)
	f.U32(0)
	f.U32(0)
	f.U16(88) // security buffer offset
	f.U16(uint16(len(blob)))
	f.U64(0)
	f.Bytes8(blob)
	r = roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusMoreProcessingRequire {
		t.Fatalf("session setup 1 status %#x", r.status)
	}
	sess := r.sessionID
	if sess == 0 {
		t.Fatal("interim session id must be assigned")
	}

	// SESSION_SETUP: NTLMSSP AUTHENTICATE (no proof) → guest session.
	blob = append([]byte{}, ntlmSig...)
	blob = append(blob, 3, 0, 0, 0)
	f = reqHdr(CmdSessionSetup, 2, 0, sess)
	f.U16(25)
	f.U8(0)
	f.U8(1)
	f.U32(0)
	f.U32(0)
	f.U16(88)
	f.U16(uint16(len(blob)))
	f.U64(0)
	f.Bytes8(blob)
	r = roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("session setup 3 status %#x", r.status)
	}

	// TREE_CONNECT \\srv\t.
	path := UTF16LE(`\\srv\t`)
	f = reqHdr(CmdTreeConnect, 3, 0, sess)
	f.U16(9)
	f.U16(0)
	f.U16(72)
	f.U16(uint16(len(path)))
	f.Bytes8(path)
	r = roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("tree connect status %#x", r.status)
	}
	return sess, r.treeID
}

func createFile(t *testing.T, srv *Srv, pc *ProtoConn, sess uint64, tree uint32, name string, disp, opts, desired uint32) (uint32, uint64) {
	t.Helper()
	n := UTF16LE(name)
	f := reqHdr(CmdCreate, 10, tree, sess)
	f.U16(57)
	f.U8(0)
	f.U8(0)
	f.U32(2) // ImpersonationLevel
	f.U64(0)
	f.U64(0)
	f.U32(desired)
	f.U32(0)
	f.U32(7) // ShareAccess
	f.U32(disp)
	f.U32(opts)
	f.U16(120) // NameOffset
	f.U16(uint16(len(n)))
	f.U32(0)
	f.U32(0)
	f.Bytes8(n)
	r := roundtrip(t, srv, pc, f.Bytes())
	var fid uint64
	if r.status == StatusSuccess {
		fid = le64(r.body[72:80])
	}
	return r.status, fid
}

func TestFullSessionCreateWriteReadDir(t *testing.T) {
	dir := t.TempDir()
	srv := testSrv(t, dir, nil)
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)

	// CREATE hello.txt (overwrite-if, generic all).
	st, fid := createFile(t, srv, pc, sess, tree, "hello.txt", fileOverwriteIf, 0x40, 0x1000_0000)
	if st != StatusSuccess {
		t.Fatalf("create status %#x", st)
	}

	// WRITE "rocket data".
	data := []byte("rocket data")
	f := reqHdr(CmdWrite, 11, tree, sess)
	f.U16(49)
	f.U16(112) // data offset
	f.U32(uint32(len(data)))
	f.U64(0)
	f.U64(fid)
	f.U64(fid)
	f.U32(0)
	f.U32(0)
	f.U16(0)
	f.U16(0)
	f.U32(0)
	f.Bytes8(data)
	r := roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("write status %#x", r.status)
	}
	if count := le32(r.body[4:8]); int(count) != len(data) {
		t.Fatalf("write count = %d", count)
	}

	// READ it back (small read → buffered path).
	f = reqHdr(CmdRead, 12, tree, sess)
	f.U16(49)
	f.U8(0)
	f.U8(0)
	f.U32(1024)
	f.U64(0)
	f.U64(fid)
	f.U64(fid)
	f.U32(0)
	f.U32(0)
	f.U32(0)
	f.U16(0)
	f.U16(0)
	f.U8(0)
	r = roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("read status %#x", r.status)
	}
	dlen := int(le32(r.body[4:8]))
	if !bytes.Equal(r.body[16:16+dlen], data) {
		t.Fatalf("read %q, want %q", r.body[16:16+dlen], data)
	}

	// CLOSE.
	f = reqHdr(CmdClose, 13, tree, sess)
	f.U16(24)
	f.U16(1) // post-query attributes
	f.U32(0)
	f.U64(fid)
	f.U64(fid)
	r = roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("close status %#x", r.status)
	}

	// Open the share root and enumerate: it must contain hello.txt.
	st, dfid := createFile(t, srv, pc, sess, tree, "", fileOpen, 0x1, 0x8000_0000)
	if st != StatusSuccess {
		t.Fatalf("open root status %#x", st)
	}
	pat := UTF16LE("*")
	f = reqHdr(CmdQueryDirectory, 14, tree, sess)
	f.U16(33)
	f.U8(fileIDBothDirectoryInformation)
	f.U8(0)
	f.U32(0)
	f.U64(dfid)
	f.U64(dfid)
	f.U16(96) // FileNameOffset
	f.U16(uint16(len(pat)))
	f.U32(65536)
	f.Bytes8(pat)
	r = roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("query directory status %#x", r.status)
	}
	if !bytes.Contains(r.body, UTF16LE("hello.txt")) {
		t.Fatal("directory listing must contain hello.txt")
	}

	// Traversal must be rejected.
	st, _ = createFile(t, srv, pc, sess, tree, `..\evil`, fileOpen, 0x40, 0x8000_0000)
	if st != StatusObjectNameInvalid {
		t.Fatalf("traversal status %#x, want OBJECT_NAME_INVALID", st)
	}

	// A large standalone READ must produce a zero-copy plan.
	st, fid2 := createFile(t, srv, pc, sess, tree, "hello.txt", fileOpen, 0x40, 0x8000_0000)
	if st != StatusSuccess {
		t.Fatalf("reopen status %#x", st)
	}
	f = reqHdr(CmdRead, 15, tree, sess)
	f.U16(49)
	f.U8(0)
	f.U8(0)
	f.U32(64 * 1024)
	f.U64(0)
	f.U64(fid2)
	f.U64(fid2)
	f.U32(0)
	f.U32(0)
	f.U32(0)
	f.U16(0)
	f.U16(0)
	f.U8(0)
	tx := NewWriter(0)
	act, plan := ProcessFrame(srv, pc, f.Bytes(), tx)
	if act != actionZcRead {
		t.Fatalf("expected a zero-copy plan for a 64K read")
	}
	if plan.Length != 64*1024 || plan.Offset != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	// Transport-side header builder sanity.
	hdr := NewWriter(0)
	BuildReadRespPrefix(plan, 11, hdr)
	if hdr.Len() != 4+64+16 {
		t.Fatalf("read header length = %d", hdr.Len())
	}
	nbt := int(hdr.Bytes()[1])<<16 | int(hdr.Bytes()[2])<<8 | int(hdr.Bytes()[3])
	if nbt != 80+11 {
		t.Fatalf("read header NBT length = %d, want %d", nbt, 80+11)
	}
}

// TestNTLMv2AuthAndSigning drives a full authenticated session: NTLMv2
// challenge/response against a real user database, a signed TREE_CONNECT whose
// response must carry a valid signature, and rejection of a wrong password.
func TestNTLMv2AuthAndSigning(t *testing.T) {
	dir := t.TempDir()
	srv := testSrv(t, dir, []UserCfg{{Name: "glenn", Password: "s3cret"}})
	if srv.allowGuest {
		t.Fatal("users defined → guest off by default")
	}
	pc := NewProtoConn(srv, 0, 0, 1)

	// NEGOTIATE 3.0.2.
	f := reqHdr(CmdNegotiate, 0, 0, 0)
	f.U16(36)
	f.U16(1)
	f.U16(1)
	f.U16(0)
	f.U32(0)
	f.Zeros(16 + 8)
	f.U16(0x0302)
	if r := roundtrip(t, srv, pc, f.Bytes()); r.status != StatusSuccess {
		t.Fatalf("negotiate status %#x", r.status)
	}

	// Type 1 → challenge.
	blob := append([]byte{}, ntlmSig...)
	blob = append(blob, 1, 0, 0, 0)
	f = reqHdr(CmdSessionSetup, 1, 0, 0)
	f.U16(25)
	f.U8(0)
	f.U8(1)
	f.U32(0)
	f.U32(0)
	f.U16(88)
	f.U16(uint16(len(blob)))
	f.U64(0)
	f.Bytes8(blob)
	r := roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusMoreProcessingRequire {
		t.Fatalf("type 1 status %#x", r.status)
	}
	sess := r.sessionID
	chal := extractChallenge(t, r.body)

	// A wrong password must be rejected.
	t3 := clientType3("glenn", "WG", "wrong", chal)
	f = reqHdr(CmdSessionSetup, 2, 0, sess)
	f.U16(25)
	f.U8(0)
	f.U8(2) // the client requires signing
	f.U32(0)
	f.U32(0)
	f.U16(88)
	f.U16(uint16(len(t3)))
	f.U64(0)
	f.Bytes8(t3)
	if r := roundtrip(t, srv, pc, f.Bytes()); r.status != StatusLogonFailure {
		t.Fatalf("wrong password status %#x, want LOGON_FAILURE", r.status)
	}

	// Redo the handshake with the right password.
	blob = append([]byte{}, ntlmSig...)
	blob = append(blob, 1, 0, 0, 0)
	f = reqHdr(CmdSessionSetup, 3, 0, 0)
	f.U16(25)
	f.U8(0)
	f.U8(1)
	f.U32(0)
	f.U32(0)
	f.U16(88)
	f.U16(uint16(len(blob)))
	f.U64(0)
	f.Bytes8(blob)
	r = roundtrip(t, srv, pc, f.Bytes())
	sess = r.sessionID
	chal = extractChallenge(t, r.body)
	t3 = clientType3("glenn", "WG", "s3cret", chal)
	f = reqHdr(CmdSessionSetup, 4, 0, sess)
	f.U16(25)
	f.U8(0)
	f.U8(2)
	f.U32(0)
	f.U32(0)
	f.U16(88)
	f.U16(uint16(len(t3)))
	f.U64(0)
	f.Bytes8(t3)
	r = roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("authenticated session setup status %#x", r.status)
	}
	if r.flags&FlagSigned == 0 {
		t.Fatal("the final SESSION_SETUP response must be signed")
	}

	// The channel must hold signing state, and the shared session must not be a
	// guest.
	ch := pc.Channel(sess)
	if ch == nil || ch.Sign == nil || !ch.SigningRequired {
		t.Fatalf("channel state = %+v", ch)
	}
	if s, ok := srv.sessions.Get(sess); !ok {
		t.Fatal("session must exist")
	} else {
		s.Lock()
		guest := s.Guest
		s.Unlock()
		if guest {
			t.Fatal("an authenticated session must not be a guest")
		}
	}

	// An unsigned TREE_CONNECT on a signing-required session must be rejected.
	path16 := UTF16LE(`\\srv\t`)
	f = reqHdr(CmdTreeConnect, 5, 0, sess)
	f.U16(9)
	f.U16(0)
	f.U16(72)
	f.U16(uint16(len(path16)))
	f.Bytes8(path16)
	if r := roundtrip(t, srv, pc, f.Bytes()); r.status != StatusAccessDenied {
		t.Fatalf("unsigned tree connect status %#x, want ACCESS_DENIED", r.status)
	}

	// A properly signed TREE_CONNECT must succeed and the response must verify
	// under the same key.
	sc := *ch.Sign
	f = reqHdr(CmdTreeConnect, 6, 0, sess)
	f.U16(9)
	f.U16(0)
	f.U16(72)
	f.U16(uint16(len(path16)))
	f.Bytes8(path16)
	req := f.Bytes()
	put32(req[16:20], le32(req[16:20])|FlagSigned)
	sig := smb2Signature(sc.Alg, &sc.Key, req[:48], make([]byte, 16), req[64:])
	copy(req[48:64], sig[:])

	tx := processOnce(t, srv, pc, req)
	out := tx.Bytes()
	if st := le32(out[12:16]); st != StatusSuccess {
		t.Fatalf("signed tree connect status %#x", st)
	}
	if le32(out[20:24])&FlagSigned == 0 {
		t.Fatal("the response must be signed")
	}
	if !verifySignature(out[4:], &sc) {
		t.Fatal("the response signature must verify")
	}
}

// extractChallenge pulls the 8-byte server challenge out of a CHALLENGE token
// inside an SESSION_SETUP response body.
func extractChallenge(t *testing.T, body []byte) [8]byte {
	t.Helper()
	idx := bytes.LastIndex(body, ntlmSig)
	if idx < 0 {
		t.Fatal("no NTLMSSP token in the response")
	}
	tok := body[idx:]
	if len(tok) < 32 {
		t.Fatalf("challenge token is %d bytes", len(tok))
	}
	var chal [8]byte
	copy(chal[:], tok[24:32])
	return chal
}

// clientType3 builds a genuine NTLMv2 AUTHENTICATE_MESSAGE like a client would.
func clientType3(user, domain, password string, chal [8]byte) []byte {
	nt := ntHash(password)
	id := append(UTF16LE(toUpperASCII(user)), UTF16LE(domain)...)
	v2 := hmacMD5(nt[:], id)
	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = append(temp, make([]byte, 8)...)
	temp = append(temp, bytes.Repeat([]byte{0x42}, 8)...)
	temp = append(temp, make([]byte, 8)...)
	buf := append([]byte{}, chal[:]...)
	buf = append(buf, temp...)
	proof := hmacMD5(v2[:], buf)
	ntResp := append([]byte{}, proof[:]...)
	ntResp = append(ntResp, temp...)
	user16 := UTF16LE(user)
	dom16 := UTF16LE(domain)

	w := NewWriter(0)
	w.Bytes8(ntlmSig)
	w.U32(3)
	off := 64
	for _, l := range []int{0, len(ntResp), len(dom16), len(user16), 0, 0} {
		w.U16(uint16(l))
		w.U16(uint16(l))
		w.U32(uint32(off))
		off += l
	}
	w.U32(0) // flags: no KEY_EXCH → session key = session base key
	w.Bytes8(ntResp)
	w.Bytes8(dom16)
	w.Bytes8(user16)
	return w.Bytes()
}

// TestSMB311PreauthSigning drives a real SMB 3.1.1 handshake and independently
// recomputes the preauth integrity chain and signing key from the exact
// transmitted bytes, then verifies the final SESSION_SETUP response signature.
// This catches preauth/key-derivation divergence that real clients reject.
func TestSMB311PreauthSigning(t *testing.T) {
	dir := t.TempDir()
	srv := testSrv(t, dir, []UserCfg{{Name: "u", Password: "pw"}})
	pc := NewProtoConn(srv, 0, 0, 1)

	// --- NEGOTIATE with a 3.1.1 preauth-integrity context (SHA-512) ---
	neg := reqHdr(CmdNegotiate, 0, 0, 0)
	negBody := neg.Len()
	neg.U16(36)
	neg.U16(1) // dialect count
	neg.U16(1) // signing enabled
	neg.U16(0)
	neg.U32(0)
	neg.Zeros(16) // client guid
	ncoffPos := neg.Len()
	neg.U32(0) // negotiate context offset, patched below
	neg.U16(1) // context count
	neg.U16(0)
	neg.U16(0x0311) // dialect
	for (neg.Len()-negBody)%8 != 0 {
		neg.U16(0)
	}
	ctxOff := neg.Len()
	neg.U16(1)  // PREAUTH_INTEGRITY_CAPABILITIES
	neg.U16(38) // data length
	neg.U32(0)
	neg.U16(1)  // one hash algorithm
	neg.U16(32) // salt length
	neg.U16(1)  // SHA-512
	neg.Zeros(32)
	negBytes := neg.Bytes()
	put32(negBytes[ncoffPos:ncoffPos+4], uint32(ctxOff))

	tx := NewWriter(0)
	if act, _ := ProcessFrame(srv, pc, negBytes, tx); act != actionRespond {
		t.Fatal("negotiate must respond")
	}
	negResp := append([]byte{}, tx.Bytes()[4:]...) // strip NBT
	if dialect := le16(negResp[68:70]); dialect != 0x0311 {
		t.Fatalf("dialect = %#x", dialect)
	}

	var zero [64]byte
	h1 := sha512Parts(zero[:], negBytes)
	preauth := sha512Parts(h1[:], negResp)

	// --- SESSION_SETUP type 1 ---
	blob := append([]byte{}, ntlmSig...)
	blob = append(blob, 1, 0, 0, 0)
	ss1 := reqHdr(CmdSessionSetup, 1, 0, 0)
	ss1.U16(25)
	ss1.U8(0)
	ss1.U8(1)
	ss1.U32(0)
	ss1.U32(0)
	ss1.U16(88)
	ss1.U16(uint16(len(blob)))
	ss1.U64(0)
	ss1.Bytes8(blob)
	ss1Bytes := ss1.Bytes()

	tx = NewWriter(0)
	ProcessFrame(srv, pc, ss1Bytes, tx)
	ss1Resp := append([]byte{}, tx.Bytes()[4:]...)
	sess := le64(ss1Resp[40:48])
	preauth = sha512Parts(preauth[:], ss1Bytes)
	preauth = sha512Parts(preauth[:], ss1Resp)
	chal := extractChallenge(t, ss1Resp)

	// --- SESSION_SETUP type 3 (NTLMv2) ---
	nt := ntHash("pw")
	id := append(UTF16LE("U"), UTF16LE("")...)
	v2 := hmacMD5(nt[:], id)
	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = append(temp, make([]byte, 8)...)
	temp = append(temp, bytes.Repeat([]byte{0x33}, 8)...)
	temp = append(temp, make([]byte, 8)...)
	pb := append([]byte{}, chal[:]...)
	pb = append(pb, temp...)
	proof := hmacMD5(v2[:], pb)
	ntResp := append([]byte{}, proof[:]...)
	ntResp = append(ntResp, temp...)
	sessionBase := hmacMD5(v2[:], proof[:])

	user16 := UTF16LE("u")
	t3 := NewWriter(0)
	t3.Bytes8(ntlmSig)
	t3.U32(3)
	off := 64
	for _, l := range []int{0, len(ntResp), 0, len(user16), 0, 0} {
		t3.U16(uint16(l))
		t3.U16(uint16(l))
		t3.U32(uint32(off))
		off += l
	}
	t3.U32(0) // flags: no KEY_EXCH → session key = session base key
	t3.Bytes8(ntResp)
	t3.Bytes8(user16)

	ss3 := reqHdr(CmdSessionSetup, 2, 0, sess)
	ss3.U16(25)
	ss3.U8(0)
	ss3.U8(1)
	ss3.U32(0)
	ss3.U32(0)
	ss3.U16(88)
	ss3.U16(uint16(len(t3.Bytes())))
	ss3.U64(0)
	ss3.Bytes8(t3.Bytes())
	ss3Bytes := ss3.Bytes()

	// The preauth hash for the signing key includes ss_req3 but NOT ss_resp3.
	preauth = sha512Parts(preauth[:], ss3Bytes)
	expectKey := kdf128(&sessionBase, []byte("SMBSigningKey\x00"), preauth[:])
	expectSC := SignCtx{Alg: SignAesCmac, Key: expectKey}

	tx = NewWriter(0)
	ProcessFrame(srv, pc, ss3Bytes, tx)
	out := tx.Bytes()
	if st := le32(out[12:16]); st != StatusSuccess {
		t.Fatalf("auth status %#x", st)
	}

	// The server's stored signing key must match the independently derived one.
	serverSC := pc.Channel(sess).Sign
	if serverSC == nil || serverSC.Key != expectSC.Key {
		t.Fatalf("3.1.1 signing key mismatch: %x vs %x", serverSC, expectSC.Key)
	}
	if le32(out[20:24])&FlagSigned == 0 {
		t.Fatal("the final SESSION_SETUP response must be signed")
	}
	if !verifySignature(out[4:], &expectSC) {
		t.Fatal("the final SESSION_SETUP response must verify under the spec-derived key")
	}
}

func TestTransformRoundtripAndTamper(t *testing.T) {
	for _, cipherID := range []uint16{CipherAES128GCM, CipherAES256GCM, CipherAES128CCM, CipherAES256CCM} {
		// The same key for c2s/s2c so wrap (s2c) round-trips through
		// decryptTransform (c2s) in one process.
		enc := &EncCtx{Cipher: cipherID, C2S: [32]byte{3}, S2C: [32]byte{3}}
		plain := []byte("\xfeSMBplaintext-inner-smb2-message-bytes-0123456789")
		tx := NewWriter(0)
		wrapTransformAppend(plain, enc, 0xABCD, tx)
		frame := tx.Bytes()[4:] // strip the NBT prefix
		if !isTransform(frame) {
			t.Fatal("wrapped frame must be a transform")
		}
		if got := le64(frame[44:52]); got != 0xABCD {
			t.Fatalf("session id = %#x", got)
		}
		if enc.NonceCtr != 1 {
			t.Fatalf("the nonce counter must advance (%#x)", cipherID)
		}
		dec, ok := decryptTransform(frame, enc)
		if !ok {
			t.Fatalf("decrypt must succeed (%#x)", cipherID)
		}
		if !bytes.Equal(dec, plain) {
			t.Fatalf("decrypt recovered %q (%#x)", dec, cipherID)
		}
		bad := append([]byte{}, frame...)
		bad[len(bad)-1] ^= 1
		if _, ok := decryptTransform(bad, enc); ok {
			t.Fatalf("tampering must be detected (%#x)", cipherID)
		}
	}
}

func TestProcessFrameAppendsForBatching(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	pc := NewProtoConn(srv, 0, 0, 1)

	// Two ECHO frames processed into the same tx buffer must yield two
	// complete, independently-framed responses.
	echo := reqHdr(CmdEcho, 7, 0, 0)
	echo.U16(4)
	echo.U16(0)
	tx := NewWriter(0)
	for range 2 {
		if act, _ := ProcessFrame(srv, pc, echo.Bytes(), tx); act != actionRespond {
			t.Fatal("echo must respond")
		}
	}
	b := tx.Bytes()
	off := 0
	for range 2 {
		nbt := int(b[off+1])<<16 | int(b[off+2])<<8 | int(b[off+3])
		if st := le32(b[off+4+8 : off+4+12]); st != StatusSuccess {
			t.Fatalf("echo status %#x", st)
		}
		off += 4 + nbt
	}
	if off != len(b) {
		t.Fatalf("expected exactly two framed responses, consumed %d of %d", off, len(b))
	}
}

func TestSMB1WildcardNegotiate(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	pc := NewProtoConn(srv, 0, 0, 1)
	// A legacy SMB1 NEGOTIATE: 0xFF 'S' 'M' 'B'.
	frame := append([]byte{0xFF, 'S', 'M', 'B'}, make([]byte, 32)...)
	tx := NewWriter(0)
	if act, _ := ProcessFrame(srv, pc, frame, tx); act != actionRespond {
		t.Fatal("SMB1 negotiate must respond")
	}
	b := tx.Bytes()
	if st := le32(b[12:16]); st != StatusSuccess {
		t.Fatalf("status %#x", st)
	}
	if dialect := le16(b[4+64+4 : 4+64+6]); dialect != 0x02FF {
		t.Fatalf("wildcard dialect = %#x, want 0x02FF", dialect)
	}
}

func TestEncryptedFrameWithoutKeyDisconnects(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	pc := NewProtoConn(srv, 0, 0, 1)
	// A transform frame for a session with no decryption key must close the
	// connection rather than leave the client hanging.
	frame := make([]byte, transformHdrLen+8)
	copy(frame[:4], transformProto)
	tx := NewWriter(0)
	if act, _ := ProcessFrame(srv, pc, frame, tx); act != actionClose {
		t.Fatal("an undecryptable transform frame must disconnect")
	}
}

func TestCreditAccountingClamps(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	pc := NewProtoConn(srv, 0, 0, 1)
	echo := reqHdr(CmdEcho, 1, 0, 0)
	echo.U16(4)
	echo.U16(0)
	// Ask for far more credits than the window allows.
	put16(echo.Bytes()[14:16], 0xFFFF)
	tx := NewWriter(0)
	ProcessFrame(srv, pc, echo.Bytes(), tx)
	granted := le16(tx.Bytes()[14:16])
	if granted > uint16(creditWindow) {
		t.Fatalf("granted %d credits, window is %d", granted, creditWindow)
	}
	if pc.CreditsOut > creditWindow {
		t.Fatalf("outstanding credits %d exceed the window", pc.CreditsOut)
	}
}

func TestOpenShareRootAndEchoRoundtrip(t *testing.T) {
	// A minimal smoke test that exercises ECHO before any session exists.
	dir := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := testSrv(t, dir, nil)
	pc := NewProtoConn(srv, 0, 0, 1)
	echo := reqHdr(CmdEcho, 1, 0, 0)
	echo.U16(4)
	echo.U16(0)
	r := roundtrip(t, srv, pc, echo.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("echo status %#x", r.status)
	}
	if le16(r.body[0:2]) != 4 {
		t.Fatalf("echo body = % x", r.body)
	}
}
