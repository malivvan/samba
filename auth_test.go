package samba

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// NTLM token builders for the session-setup branches.

// ntlmType1 builds a NEGOTIATE_MESSAGE (type 1) with the given flags.
func ntlmType1(flags uint32) []byte {
	w := NewWriter(0)
	w.Bytes8(ntlmSig)
	w.U32(1)
	w.U32(flags)
	w.Zeros(8)  // domain security buffer
	w.Zeros(8)  // workstation security buffer
	w.Zeros(16) // version + reserved tail
	return w.Bytes()
}

// spnegoWrapInit wraps a mechanism token in a SPNEGO NegTokenInit.
func spnegoWrapInit(token []byte) []byte {
	mech := der(0xA0, der(0x30, derOID(oidNTLMSSP)))
	tok := der(0xA2, der(0x04, token))
	init := append(mech, tok...)
	neg := der(0xA0, der(0x30, init))
	body := derOID(oidSPNEGO)
	body = append(body, neg...)
	return der(0x60, body)
}

// spnegoWrapResp wraps a mechanism token the way a later SPNEGO leg does.
func spnegoWrapResp(token []byte) []byte {
	return negResp(acceptIncomplete, mechNtlmssp, token)
}

// challengeFrom pulls the 8-byte challenge out of an NTLMSSP token.
func challengeFrom(t *testing.T, body []byte) [8]byte {
	t.Helper()
	return extractChallenge(t, body)
}

// userSession establishes a full authenticated (NTLMv2) session and returns it.
func userSession(t *testing.T, srv *Srv, pc *ProtoConn) uint64 {
	t.Helper()
	neg := reqHdr(CmdNegotiate, 1, 0, 0)
	neg.U16(36)
	neg.U16(1)
	neg.U16(1)
	neg.U16(0)
	neg.U32(0)
	neg.Zeros(16 + 8)
	neg.U16(0x0302)
	if r := roundtrip(t, srv, pc, neg.Bytes()); r.status != StatusSuccess {
		t.Fatalf("negotiate status %#x", r.status)
	}
	r := roundtrip(t, srv, pc, sessionSetupFrame(2, 0, ntlmType1(0x0000_0001), 0, 1))
	if r.status != StatusMoreProcessingRequire {
		t.Fatalf("type 1 status %#x", r.status)
	}
	sid := r.sessionID
	chal := challengeFrom(t, r.body)
	t3 := clientType3("alice", "WG", "s3cret", chal)
	r = roundtrip(t, srv, pc, sessionSetupFrame(3, sid, t3, 0, 2))
	if r.status != StatusSuccess {
		t.Fatalf("authenticated setup status %#x", r.status)
	}
	return sid
}

func ntlmSrv(t *testing.T) *Srv {
	t.Helper()
	return testSrv(t, t.TempDir(), []UserCfg{{Name: "alice", Password: "s3cret"}})
}

func TestSessionSetupSpnegoWrapping(t *testing.T) {
	srv := ntlmSrv(t)
	pc := NewProtoConn(srv, 0, 0, 1)
	neg := reqHdr(CmdNegotiate, 1, 0, 0)
	neg.U16(36)
	neg.U16(1)
	neg.U16(1)
	neg.U16(0)
	neg.U32(0)
	neg.Zeros(16 + 8)
	neg.U16(0x0302)
	roundtrip(t, srv, pc, neg.Bytes())

	// A SPNEGO-wrapped type 1 gets a SPNEGO-wrapped challenge back.
	r := roundtrip(t, srv, pc, sessionSetupFrame(2, 0, spnegoWrapInit(ntlmType1(0x0000_0001)), 0, 1))
	if r.status != StatusMoreProcessingRequire {
		t.Fatalf("wrapped type 1 status %#x", r.status)
	}
	if inc := classifyBlob(r.body[8:]); inc.Mech != mechNtlmssp || !inc.SPNEGO {
		t.Fatalf("the challenge must be SPNEGO-wrapped: %+v", inc)
	}
	// And a SPNEGO-wrapped type 3 completes with a SPNEGO accept-completed.
	chal := challengeFrom(t, r.body)
	t3 := clientType3("alice", "WG", "s3cret", chal)
	blob := spnegoWrapResp(t3)
	r = roundtrip(t, srv, pc, sessionSetupFrame(3, r.sessionID, blob, 0, 2))
	if r.status != StatusSuccess {
		t.Fatalf("wrapped type 3 status %#x", r.status)
	}
	if !isSPNEGO(r.body[8:]) {
		t.Fatal("the final response must be SPNEGO-wrapped")
	}
}

func TestSessionSetupReauthAcknowledges(t *testing.T) {
	srv := ntlmSrv(t)
	pc := NewProtoConn(srv, 0, 0, 1)
	sid := userSession(t, srv, pc)
	// A second AUTHENTICATE on an established channel with no pending challenge
	// is acknowledged rather than rejected.
	t3 := clientType3("alice", "WG", "s3cret", [8]byte{1})
	r := roundtrip(t, srv, pc, sessionSetupFrame(4, sid, t3, 0, 1))
	if r.status != StatusSuccess {
		t.Fatalf("re-auth status %#x", r.status)
	}
	if flags := le16(r.body[2:4]); flags&sessionFlagIsGuest != 0 {
		t.Fatal("an authenticated channel must not report the guest flag")
	}
}

func TestSessionSetupPolicyAndGuestDenials(t *testing.T) {
	t.Run("ntlm token with kerberos-only policy", func(t *testing.T) {
		srv := ntlmSrv(t)
		srv.cfg.Auth = AuthKerberos
		pc := NewProtoConn(srv, 0, 0, 1)
		r := roundtrip(t, srv, pc, sessionSetupFrame(1, 0, ntlmType1(0x0000_0001), 0, 1))
		if r.status != StatusNotSupported {
			t.Fatalf("status %#x, want NOT_SUPPORTED", r.status)
		}
	})
	t.Run("anonymous with encryption required", func(t *testing.T) {
		srv := testSrv(t, t.TempDir(), nil)
		srv.cfg.Encrypt = true
		srv.cfg.AllowGuest = new(true)
		srv.allowGuest = true
		pc := NewProtoConn(srv, 0, 0, 1)
		r := roundtrip(t, srv, pc, sessionSetupEmpty(1))
		if r.status != StatusAccessDenied {
			t.Fatalf("status %#x, want ACCESS_DENIED", r.status)
		}
	})
	t.Run("guest authenticate with encryption required", func(t *testing.T) {
		srv := testSrv(t, t.TempDir(), nil)
		srv.allowGuest = true
		pc := NewProtoConn(srv, 0, 0, 1)
		// A type 1 establishes the challenge; then flip the policy to require
		// encryption before the type 3 arrives, so the guest verdict path is
		// taken with encryption on.
		r := roundtrip(t, srv, pc, sessionSetupFrame(1, 0, ntlmType1(0x0000_0001), 0, 1))
		if r.status != StatusMoreProcessingRequire {
			t.Fatalf("type 1 status %#x", r.status)
		}
		srv.cfg.Encrypt = true
		t3 := clientType3("nobody", "WG", "wrong", challengeFrom(t, r.body))
		r = roundtrip(t, srv, pc, sessionSetupFrame(2, r.sessionID, t3, 0, 1))
		if r.status != StatusAccessDenied {
			t.Fatalf("status %#x, want ACCESS_DENIED", r.status)
		}
	})
	t.Run("no guest allowed", func(t *testing.T) {
		srv := testSrv(t, t.TempDir(), nil)
		srv.allowGuest = false
		pc := NewProtoConn(srv, 0, 0, 1)
		r := roundtrip(t, srv, pc, sessionSetupEmpty(1))
		if r.status != StatusLogonFailure {
			t.Fatalf("status %#x, want LOGON_FAILURE", r.status)
		}
	})
	t.Run("unknown user with guest allowed", func(t *testing.T) {
		srv := testSrv(t, t.TempDir(), nil)
		srv.allowGuest = true
		pc := NewProtoConn(srv, 0, 0, 1)
		r := roundtrip(t, srv, pc, sessionSetupFrame(1, 0, ntlmType1(0x0000_0001), 0, 1))
		t3 := clientType3("stranger", "WG", "pw", challengeFrom(t, r.body))
		r = roundtrip(t, srv, pc, sessionSetupFrame(2, r.sessionID, t3, 0, 1))
		if r.status != StatusSuccess {
			t.Fatalf("status %#x, want SUCCESS (guest)", r.status)
		}
		if flags := le16(r.body[2:4]); flags&sessionFlagIsGuest == 0 {
			t.Fatal("the guest flag must be set")
		}
	})
}

func TestMultichannelBinding(t *testing.T) {
	srv := ntlmSrv(t)
	first := NewProtoConn(srv, 0, 0, 1)
	sid := userSession(t, srv, first)

	// A second connection binds to the same session by proving the identity
	// again.
	second := NewProtoConn(srv, 0, 1, 1)
	neg := reqHdr(CmdNegotiate, 1, 0, 0)
	neg.U16(36)
	neg.U16(1)
	neg.U16(1)
	neg.U16(0)
	neg.U32(0)
	neg.Zeros(16 + 8)
	neg.U16(0x0302)
	roundtrip(t, srv, second, neg.Bytes())

	r := roundtrip(t, srv, second, sessionSetupFrame(2, sid, ntlmType1(0x0001), sessionFlagBinding, 1))
	if r.status != StatusMoreProcessingRequire {
		t.Fatalf("bind type 1 status %#x", r.status)
	}
	if r.sessionID != sid {
		t.Fatalf("the bind must reuse the session id: %#x != %#x", r.sessionID, sid)
	}
	chal := challengeFrom(t, r.body)

	// The wrong password is refused and the channel is dropped.
	bad := clientType3("alice", "WG", "wrong", chal)
	if r := roundtrip(t, srv, second, sessionSetupFrame(3, sid, bad, sessionFlagBinding, 1)); r.status != StatusAccessDenied {
		t.Fatalf("bind with the wrong password status %#x, want ACCESS_DENIED", r.status)
	}
	if second.Channel(sid) != nil {
		t.Fatal("a refused bind must drop the channel")
	}

	// The right one succeeds and the session now counts two channels.
	r = roundtrip(t, srv, second, sessionSetupFrame(2, sid, ntlmType1(0x0001), sessionFlagBinding, 1))
	chal = challengeFrom(t, r.body)
	good := clientType3("alice", "WG", "s3cret", chal)
	r = roundtrip(t, srv, second, sessionSetupFrame(4, sid, good, sessionFlagBinding, 1))
	if r.status != StatusSuccess {
		t.Fatalf("bind status %#x", r.status)
	}
	if ch := second.Channel(sid); ch == nil || !ch.Established || ch.Sign == nil {
		t.Fatalf("the bound channel must be established and signing: %+v", ch)
	}
	sess, ok := srv.sessions.Get(sid)
	if !ok {
		t.Fatal("the session must exist")
	}
	sess.Lock()
	channels := sess.Channels
	sess.Unlock()
	if channels != 2 {
		t.Fatalf("session channels = %d, want 2", channels)
	}

	// A bind naming a session that does not exist is refused.
	if r := roundtrip(t, srv, second, sessionSetupFrame(6, 0xDEAD, ntlmType1(0x0001), sessionFlagBinding, 1)); r.status != StatusUserSessionDeleted {
		t.Fatalf("unknown session bind status %#x", r.status)
	}
	// As is a bind with no session id at all.
	if r := roundtrip(t, srv, second, sessionSetupFrame(7, 0, ntlmType1(0x0001), sessionFlagBinding, 1)); r.status != StatusUserSessionDeleted {
		t.Fatalf("missing session bind status %#x", r.status)
	}
}

func TestMultichannelBindingToGuestSession(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	srv.allowGuest = true
	first := NewProtoConn(srv, 0, 0, 1)
	// An anonymous session.
	r := roundtrip(t, srv, first, sessionSetupEmpty(1))
	if r.status != StatusSuccess {
		t.Fatalf("guest session status %#x", r.status)
	}
	sid := r.sessionID

	// Guest sessions carry no key, so a bind is signing-free: whatever the
	// client presents is accepted.
	second := NewProtoConn(srv, 0, 1, 1)
	roundtrip(t, srv, second, sessionSetupFrame(2, sid, ntlmType1(0x0001), sessionFlagBinding, 1))
	body := reqHdr(CmdSessionSetup, 3, 0, sid)
	_ = body
	chal := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	t3 := clientType3("anyone", "WG", "anything", chal)
	r = roundtrip(t, srv, second, sessionSetupFrame(3, sid, t3, sessionFlagBinding, 1))
	if r.status != StatusSuccess {
		t.Fatalf("guest bind status %#x", r.status)
	}
	if flags := le16(r.body[2:4]); flags&sessionFlagIsGuest == 0 {
		t.Fatal("a bound guest channel must report the guest flag")
	}
	if ch := second.Channel(sid); ch.Sign != nil {
		t.Fatal("a guest channel must not hold signing material")
	}
}

func TestSessionSetupMalformedBodies(t *testing.T) {
	srv := ntlmSrv(t)
	pc := NewProtoConn(srv, 0, 0, 1)
	// A security buffer that points past the end of the frame.
	w := reqHdr(CmdSessionSetup, 1, 0, 0)
	w.U16(25)
	w.U8(0)
	w.U8(1)
	w.U32(0)
	w.U32(0)
	w.U16(60000) // offset beyond the frame
	w.U16(100)
	w.U64(0)
	if r := roundtrip(t, srv, pc, w.Bytes()); r.status != StatusInvalidParameter {
		t.Fatalf("out-of-range security buffer status %#x", r.status)
	}
	// A body too short for the fixed part.
	w = reqHdr(CmdSessionSetup, 2, 0, 0)
	w.U16(25)
	if r := roundtrip(t, srv, pc, w.Bytes()); r.status != StatusInvalidParameter {
		t.Fatalf("short body status %#x", r.status)
	}
}

func TestNegotiateVariants(t *testing.T) {
	t.Run("no common dialect", func(t *testing.T) {
		srv := testSrv(t, t.TempDir(), nil)
		pc := NewProtoConn(srv, 0, 0, 1)
		w := reqHdr(CmdNegotiate, 1, 0, 0)
		w.U16(36)
		w.U16(1)
		w.U16(1)
		w.U16(0)
		w.U32(0)
		w.Zeros(16 + 8)
		w.U16(0x0100) // an ancient dialect nobody supports
		if r := roundtrip(t, srv, pc, w.Bytes()); r.status != StatusNotSupported {
			t.Fatalf("status %#x, want NOT_SUPPORTED", r.status)
		}
	})
	t.Run("require signing is advertised", func(t *testing.T) {
		srv := testSrv(t, t.TempDir(), nil)
		srv.cfg.RequireSigning = true
		pc := NewProtoConn(srv, 0, 0, 1)
		r := roundtrip(t, srv, pc, negotiate302(t, 1))
		if got := le16(r.body[2:4]); got&securityModeSigningRequired == 0 {
			t.Fatalf("security mode = %#x, want SIGNING_REQUIRED", got)
		}
	})
	t.Run("311 without preauth is refused", func(t *testing.T) {
		srv := testSrv(t, t.TempDir(), nil)
		pc := NewProtoConn(srv, 0, 0, 1)
		// Offer 3.1.1 with an encryption context but no preauth integrity one.
		w := reqHdr(CmdNegotiate, 1, 0, 0)
		body := w.Len()
		w.U16(36)
		w.U16(1)
		w.U16(1)
		w.U16(0)
		w.U32(0)
		w.Zeros(16)
		offPos := w.Len()
		w.U32(0)
		w.U16(1)
		w.U16(0)
		w.U16(0x0311)
		for (w.Len()-body)%8 != 0 {
			w.U16(0)
		}
		ctxOff := w.Len()
		w.U16(2) // SMB2_ENCRYPTION_CAPABILITIES
		w.U16(4)
		w.U32(0)
		w.U16(1)
		w.U16(CipherAES128GCM)
		b := w.Bytes()
		put32(b[offPos:offPos+4], uint32(ctxOff))
		if r := roundtrip(t, srv, pc, b); r.status != StatusInvalidParameter {
			t.Fatalf("status %#x, want INVALID_PARAMETER", r.status)
		}
	})
	t.Run("cipher preference", func(t *testing.T) {
		// The client's order is honored by default...
		srv := testSrv(t, t.TempDir(), nil)
		pc := NewProtoConn(srv, 0, 0, 1)
		cipher := negotiateCipher(t, srv, pc, []uint16{CipherAES128GCM, CipherAES256GCM})
		if cipher != CipherAES128GCM {
			t.Fatalf("cipher = %#x, want the client's first choice", cipher)
		}
		// ...and AES-256 wins when the server prefers it.
		srv2 := testSrv(t, t.TempDir(), nil)
		srv2.cfg.PreferAES256 = true
		pc2 := NewProtoConn(srv2, 0, 0, 1)
		cipher = negotiateCipher(t, srv2, pc2, []uint16{CipherAES128GCM, CipherAES256GCM})
		if cipher != CipherAES256GCM {
			t.Fatalf("cipher = %#x, want AES-256-GCM", cipher)
		}
		// Unsupported ciphers are ignored; a list of only unsupported ones
		// negotiates no cipher but still succeeds.
		srv3 := testSrv(t, t.TempDir(), nil)
		pc3 := NewProtoConn(srv3, 0, 0, 1)
		if cipher = negotiateCipher(t, srv3, pc3, []uint16{0x0099}); cipher != 0 {
			t.Fatalf("cipher = %#x, want none", cipher)
		}
		// A list with only CCM still negotiates it.
		srv4 := testSrv(t, t.TempDir(), nil)
		pc4 := NewProtoConn(srv4, 0, 0, 1)
		if cipher = negotiateCipher(t, srv4, pc4, []uint16{CipherAES256CCM}); cipher != CipherAES256CCM {
			t.Fatalf("cipher = %#x, want AES-256-CCM", cipher)
		}
	})
}

// negotiate302 builds a plain NEGOTIATE offering SMB 3.0.2.
func negotiate302(t *testing.T, msgID uint64) []byte {
	t.Helper()
	w := reqHdr(CmdNegotiate, msgID, 0, 0)
	w.U16(36)
	w.U16(1)
	w.U16(1)
	w.U16(0)
	w.U32(0)
	w.Zeros(16 + 8)
	w.U16(0x0302)
	return w.Bytes()
}

// negotiateCipher negotiates SMB 3.1.1 offering the given ciphers and returns
// the cipher the server selected. It always offers the mandatory preauth
// integrity context.
func negotiateCipher(t *testing.T, srv *Srv, pc *ProtoConn, ciphers []uint16) uint16 {
	t.Helper()
	w := reqHdr(CmdNegotiate, 1, 0, 0)
	body := w.Len()
	w.U16(36)
	w.U16(1) // one dialect
	w.U16(1) // signing enabled
	w.U16(0)
	w.U32(0)
	w.Zeros(16)
	offPos := w.Len()
	w.U32(0) // negotiate context offset, patched below
	w.U16(2) // two contexts: preauth + encryption
	w.U16(0)
	w.U16(0x0311)
	for (w.Len()-body)%8 != 0 {
		w.U16(0)
	}
	ctxOff := w.Len()
	// PREAUTH_INTEGRITY_CAPABILITIES
	w.U16(1)
	w.U16(38)
	w.U32(0)
	w.U16(1)  // one hash
	w.U16(32) // salt length
	w.U16(1)  // SHA-512
	w.Zeros(32)
	w.Pad8(0)
	// ENCRYPTION_CAPABILITIES
	w.U16(2)
	w.U16(uint16(2 + 2*len(ciphers)))
	w.U32(0)
	w.U16(uint16(len(ciphers)))
	for _, c := range ciphers {
		w.U16(c)
	}
	b := w.Bytes()
	put32(b[offPos:offPos+4], uint32(ctxOff))
	r := roundtrip(t, srv, pc, b)
	if r.status != StatusSuccess {
		t.Fatalf("negotiate status %#x", r.status)
	}
	return pc.Cipher
}

func TestSessionSetupWithUnknownMechanism(t *testing.T) {
	srv := ntlmSrv(t)
	srv.cfg.Auth = AuthNTLM
	pc := NewProtoConn(srv, 0, 0, 1)
	// A Kerberos token when only NTLM is allowed is refused loudly.
	krb := buildFakeKrbBlob()
	if r := roundtrip(t, srv, pc, sessionSetupFrame(1, 0, krb, 0, 1)); r.status != StatusNotSupported {
		t.Fatalf("status %#x, want NOT_SUPPORTED", r.status)
	}
}

func TestCloseHandleReleasesLeaseAndNotify(t *testing.T) {
	dir := t.TempDir()
	if err := writeFileData(dir, "leased.txt", "x"); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Oplocks = true
	cfg.Shares = []ShareCfg{{Name: "t", Path: dir}}
	srv := testSrvFromConfig(t, cfg)
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)

	// Open with a read-caching lease request.
	var key [16]byte
	key[0] = 0xAB
	data := NewWriter(0)
	data.Bytes8(key[:])
	data.U32(LeaseReadCaching)
	data.U32(0)
	data.U64(0)
	n := UTF16LE("leased.txt")
	w := reqHdr(CmdCreate, 20, tree, sess)
	w.U16(57)
	w.U8(0)
	w.U8(OplockLease)
	w.U32(2)
	w.U64(0)
	w.U64(0)
	w.U32(0x1000_0000)
	w.U32(0)
	w.U32(7)
	w.U32(fileOpenIf)
	w.U32(0)
	w.U16(120)
	w.U16(uint16(len(n)))
	ctx := rqlsCtx(data.Bytes())
	w.U32(64 + 56 + uint32(len(n)))
	w.U32(uint32(len(ctx)))
	w.Bytes8(n)
	w.Bytes8(ctx)
	r := roundtrip(t, srv, pc, w.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("create status %#x", r.status)
	}
	if oplock := r.body[2]; oplock != OplockLease {
		t.Fatalf("oplock level = %#x, want a lease", oplock)
	}
	fid := le64(r.body[72:80])

	// Nothing is left in the lease table once the handle closes.
	cl := reqHdr(CmdClose, 21, tree, sess)
	cl.U16(24)
	cl.U16(1)
	cl.U32(0)
	cl.U64(fid)
	cl.U64(fid)
	if r := roundtrip(t, srv, pc, cl.Bytes()); r.status != StatusSuccess {
		t.Fatalf("close status %#x", r.status)
	}
	srv.leases.mu.Lock()
	grants := len(srv.leases.m)
	srv.leases.mu.Unlock()
	if grants != 0 {
		t.Fatalf("the lease was not released on close: %d entries", grants)
	}
}

func TestCloseHandleCompletesPendingNotify(t *testing.T) {
	f := newFixture(t)
	dfid := f.open("", fileOpen, 0x1, 0x8000_0000)
	// Pend a notification on the directory handle.
	if r := f.queryDir(dfid, fileIDBothDirectoryInformation, qdRestartScans, "*", 4096); r.status != StatusSuccess {
		t.Fatalf("listing status %#x", r.status)
	}
	w := reqHdr(CmdChangeNotify, f.nextID(), f.tree, f.sess)
	w.U16(32)
	w.U16(0)
	w.U32(4096)
	w.U64(dfid)
	w.U64(dfid)
	w.U32(0x1F)
	if r := f.rt(w.Bytes()); r.status != StatusPending {
		t.Fatalf("change notify status %#x", r.status)
	}
	if len(f.pc.NotifyActive) != 1 {
		t.Fatalf("pending ops = %+v", f.pc.NotifyActive)
	}
	// Closing the handle must complete the pending notification.
	if st := f.closeFID(dfid); st != StatusSuccess {
		t.Fatalf("close status %#x", st)
	}
	if len(f.pc.NotifyActive) != 0 {
		t.Fatalf("the close must clear the pending op: %+v", f.pc.NotifyActive)
	}
	if len(f.pc.NotifyDone) != 1 || f.pc.NotifyDone[0].Status != StatusNotifyCleanup {
		t.Fatalf("the completion must be queued: %+v", f.pc.NotifyDone)
	}
}

func TestCreateWithV2LeaseContext(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Oplocks = true
	cfg.Shares = []ShareCfg{{Name: "t", Path: dir}}
	srv := testSrvFromConfig(t, cfg)
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)

	var key, parent [16]byte
	key[0], parent[0], parent[1] = 0x11, 0x22, 0x33
	data := NewWriter(0)
	data.Bytes8(key[:])
	data.U32(LeaseReadCaching | LeaseHandleCaching)
	data.U32(0)
	data.U64(0)
	data.Bytes8(parent[:])
	data.U16(7) // epoch
	data.U16(0)
	if data.Len() != 52 {
		t.Fatalf("v2 lease data is %d bytes", data.Len())
	}
	n := UTF16LE("v2.txt")
	w := reqHdr(CmdCreate, 20, tree, sess)
	w.U16(57)
	w.U8(0)
	w.U8(OplockLease)
	w.U32(2)
	w.U64(0)
	w.U64(0)
	w.U32(0x1000_0000)
	w.U32(0)
	w.U32(7)
	w.U32(fileOpenIf)
	w.U32(0)
	w.U16(120)
	w.U16(uint16(len(n)))
	ctx := rqlsCtx(data.Bytes())
	w.U32(64 + 56 + uint32(len(n)))
	w.U32(uint32(len(ctx)))
	w.Bytes8(n)
	w.Bytes8(ctx)
	r := roundtrip(t, srv, pc, w.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("create status %#x", r.status)
	}
	// The echoed lease context must carry the key, the granted state, and (for a
	// v2 request) the parent key and epoch. The CREATE response fixed part is 88
	// bytes, then the 24-byte context header with the data 8-aligned at offset
	// 112 from the start of the body.
	ctxBody := r.body[88:]
	if got := le32(ctxBody[0:4]); got != 0 {
		t.Fatalf("the echoed context must be the last one (Next = %d)", got)
	}
	if !bytes.Equal(ctxBody[16:20], CtxNameRQLS) {
		t.Fatalf("context name = %q", ctxBody[16:20])
	}
	lease := ctxBody[24:]
	if !bytes.Equal(lease[0:16], key[:]) {
		t.Fatalf("lease key = %x", lease[0:16])
	}
	if got := le32(lease[16:20]); got != LeaseReadCaching|LeaseHandleCaching {
		t.Fatalf("granted state = %#x", got)
	}
	if !bytes.Equal(lease[32:48], parent[:]) {
		t.Fatalf("parent key = %x", lease[32:48])
	}
	if got := le16(lease[48:50]); got != 7 {
		t.Fatalf("epoch = %d", got)
	}
}

// writeFileData writes a small file into dir.
func writeFileData(dir, name, data string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644)
}
