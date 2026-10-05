package samba

import "testing"

// Dialect negotiation: the floor (`min_dialect`, and the floor `encrypt`
// implies) and what happens to a client that cannot meet it.
//
// These are the security-relevant half of the dialect table in introspect.go.
// The rule they pin is that a client below the floor is *refused*, never
// downgraded: `encrypt = true` is only a guarantee if a client cannot simply
// offer a weaker dialect to escape it.

// offerDialects negotiates exactly the given dialects with the given client
// capabilities. It reports the response status, the chosen revision and the
// server's capability set.
func offerDialects(t *testing.T, srv *Srv, pc *ProtoConn, clientCaps uint32, dialects ...uint16) (status uint32, chosen uint16, serverCaps uint32) {
	t.Helper()
	f := reqHdr(CmdNegotiate, 1, 0, 0)
	f.U16(36)
	f.U16(uint16(len(dialects)))
	f.U16(1) // signing enabled
	f.U16(0)
	f.U32(clientCaps)
	f.Zeros(16 + 8) // client guid + start time
	for _, d := range dialects {
		f.U16(d)
	}
	r := roundtrip(t, srv, pc, f.Bytes())
	if r.status != StatusSuccess {
		return r.status, 0, 0
	}
	return r.status, le16(r.body[4:6]), le32(r.body[24:28])
}

// offer311 negotiates 3.1.1, whose request must carry the SHA-512 preauth
// context; the encryption capabilities context is included only when withCipher
// is set.
func offer311(t *testing.T, srv *Srv, pc *ProtoConn, withCipher bool) uint32 {
	t.Helper()
	neg := reqHdr(CmdNegotiate, 1, 0, 0)
	neg.U16(36)
	neg.U16(1) // one dialect
	neg.U16(1) // signing enabled
	neg.U16(0)
	neg.U32(0)
	neg.Zeros(16)
	ctxOffPos := neg.Len()
	neg.U32(0) // negotiate context offset, patched below
	count := uint16(1)
	if withCipher {
		count = 2
	}
	neg.U16(count)
	neg.U16(0)
	neg.U16(0x0311)
	neg.Pad8(0)
	ctxOff := neg.Len()
	// PREAUTH_INTEGRITY_CAPABILITIES: SHA-512.
	neg.U16(1)
	neg.U16(38)
	neg.U32(0)
	neg.U16(1)
	neg.U16(32)
	neg.U16(1)
	neg.Zeros(32)
	if withCipher {
		neg.Pad8(0)
		// ENCRYPTION_CAPABILITIES: one cipher.
		neg.U16(2)
		neg.U16(4)
		neg.U32(0)
		neg.U16(1)
		neg.U16(CipherAES128GCM)
	}
	body := neg.Bytes()
	put32(body[ctxOffPos:ctxOffPos+4], uint32(ctxOff))
	return roundtrip(t, srv, pc, body).status
}

// ntlmLogin runs the two NTLM legs on an already-negotiated connection with
// signing optional, and reports the SESSION_SETUP status, the session id and the
// response's SessionFlags.
func ntlmLogin(t *testing.T, srv *Srv, pc *ProtoConn) (status uint32, sid uint64, flags uint16) {
	t.Helper()
	// Signing enabled but not required, so a rejection we see later is about
	// encryption rather than an unsigned request.
	const secmode = uint8(securityModeSigningEnabled)
	r := roundtrip(t, srv, pc, sessionSetupFrame(2, 0, ntlmType1(0x0000_0001), 0, secmode))
	if r.status != StatusMoreProcessingRequire {
		t.Fatalf("NTLM NEGOTIATE status %#x, want MORE_PROCESSING_REQUIRED", r.status)
	}
	sid = r.sessionID
	chal := challengeFrom(t, r.body)
	t3 := clientType3("alice", "WG", "s3cret", chal)
	r = roundtrip(t, srv, pc, sessionSetupFrame(3, sid, t3, 0, secmode))
	if r.status != StatusSuccess {
		return r.status, sid, 0
	}
	return r.status, sid, le16(r.body[2:4])
}

func TestMinDialectRefusesOlderClients(t *testing.T) {
	cases := []struct {
		name       string
		minDialect string
		offered    []uint16
		wantStatus uint32
		wantChosen uint16
	}{
		{"default accepts 2.x", "", []uint16{0x0210, 0x0202}, StatusSuccess, 0x0210},
		{"floor refuses a client below it", "3.0", []uint16{0x0210}, StatusNotSupported, 0},
		{"floor still takes a newer dialect", "3.0", []uint16{0x0210, 0x0302}, StatusSuccess, 0x0302},
		{"floor refuses 3.0 when it wants 3.1.1", "3.1.1", []uint16{0x0302, 0x0300}, StatusNotSupported, 0},
		{"2.0.2 floor is the default behaviour", "2.0.2", []uint16{0x0202}, StatusSuccess, 0x0202},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := testSrv(t, t.TempDir(), nil)
			srv.cfg.MinDialect = c.minDialect
			pc := NewProtoConn(srv, 0, 0, 1)
			status, chosen, _ := offerDialects(t, srv, pc, 0, c.offered...)
			if status != c.wantStatus {
				t.Fatalf("status %#x, want %#x", status, c.wantStatus)
			}
			if status == StatusSuccess && chosen != c.wantChosen {
				t.Fatalf("chose %#x, want %#x", chosen, c.wantChosen)
			}
		})
	}
}

// TestMinDialectFloorIsNotADowngrade is the property that makes the floor worth
// having: a client that offers both a dialect above and one below must be given
// the higher one, never the lower.
func TestMinDialectFloorIsNotADowngrade(t *testing.T) {
	srv := testSrv(t, t.TempDir(), nil)
	srv.cfg.MinDialect = "3.0"
	pc := NewProtoConn(srv, 0, 0, 1)
	// Offered worst-first, so taking the client's order would pick 2.1.
	status, chosen, _ := offerDialects(t, srv, pc, 0, 0x0202, 0x0210, 0x0300, 0x0302)
	if status != StatusSuccess {
		t.Fatalf("status %#x", status)
	}
	if chosen != 0x0302 {
		t.Fatalf("chose %#x, want the newest at or above the floor (0x0302)", chosen)
	}
}

// TestEncryptRequiresADialectThatCanEncrypt covers the bug this whole check
// exists for: `encrypt = true` used to let a 2.x *or 3.0/3.0.2* client negotiate,
// authenticate and then exchange cleartext, because a cipher was only ever
// chosen for 3.1.1.
func TestEncryptRequiresADialectThatCanEncrypt(t *testing.T) {
	t.Run("2.x is refused outright", func(t *testing.T) {
		for _, old := range []uint16{0x0202, 0x0210} {
			srv := testSrv(t, t.TempDir(), []UserCfg{{Name: "alice", Password: "s3cret"}})
			srv.cfg.Encrypt = true
			pc := NewProtoConn(srv, 0, 0, 1)
			if status, _, _ := offerDialects(t, srv, pc, 0, old); status != StatusNotSupported {
				t.Errorf("dialect %#x with encrypt = true: status %#x, want NOT_SUPPORTED", old, status)
			}
		}
	})

	t.Run("3.x is encrypted, not merely accepted", func(t *testing.T) {
		for _, d := range []uint16{0x0300, 0x0302} {
			srv := testSrv(t, t.TempDir(), []UserCfg{{Name: "alice", Password: "s3cret"}})
			srv.cfg.Encrypt = true
			pc := NewProtoConn(srv, 0, 0, 1)

			status, chosen, _ := offerDialects(t, srv, pc, 0, d)
			if status != StatusSuccess || chosen != d {
				t.Fatalf("dialect %#x: status %#x, chose %#x", d, status, chosen)
			}
			status, sid, flags := ntlmLogin(t, srv, pc)
			if status != StatusSuccess {
				t.Fatalf("dialect %#x: login status %#x", d, status)
			}
			if flags&sessionFlagEncryptData == 0 {
				t.Errorf("dialect %#x: SessionFlags %#x has no ENCRYPT_DATA, so the client was never told to seal", d, flags)
			}

			// The point of the flag: a plaintext request on that session must be
			// refused, or `encrypt = true` is decoration.
			echo := reqHdr(CmdEcho, 9, 0, sid)
			echo.U16(4)
			echo.U16(0)
			if r := roundtrip(t, srv, pc, echo.Bytes()); r.status != StatusAccessDenied {
				t.Errorf("dialect %#x: plaintext ECHO status %#x, want ACCESS_DENIED", d, r.status)
			}
		}
	})
}

// TestEncryptBackstopRefusesSessionWithoutCipher covers the guard that does not
// depend on the floor at all: a 3.1.1 client can offer preauth integrity and no
// encryption capability, which leaves the server with no cipher. With
// `encrypt = true` the session is refused rather than served in the clear.
func TestEncryptBackstopRefusesSessionWithoutCipher(t *testing.T) {
	srv := testSrv(t, t.TempDir(), []UserCfg{{Name: "alice", Password: "s3cret"}})
	srv.cfg.Encrypt = true
	pc := NewProtoConn(srv, 0, 0, 1)

	if status := offer311(t, srv, pc, false); status != StatusSuccess {
		t.Fatalf("negotiate without an encryption context: status %#x", status)
	}
	if status, _, _ := ntlmLogin(t, srv, pc); status != StatusNotSupported {
		t.Fatalf("session setup status %#x, want NOT_SUPPORTED: a session that cannot be encrypted must not be established", status)
	}
}

// TestEncryptCapabilityEchoedForSmb30 checks the pre-3.1.1 way of agreeing on
// encryption, which a client-requested (`seal`) mount needs.
func TestEncryptCapabilityEchoedForSmb30(t *testing.T) {
	for _, d := range []uint16{0x0300, 0x0302} {
		srv := testSrv(t, t.TempDir(), nil)
		pc := NewProtoConn(srv, 0, 0, 1)
		if _, _, caps := offerDialects(t, srv, pc, capEncryption, d); caps&capEncryption == 0 {
			t.Errorf("dialect %#x: server did not echo SMB2_GLOBAL_CAP_ENCRYPTION (%#x)", d, caps)
		}

		pc = NewProtoConn(srv, 0, 0, 1)
		if _, _, caps := offerDialects(t, srv, pc, 0, d); caps&capEncryption != 0 {
			t.Errorf("dialect %#x: server advertised encryption the client did not ask for (%#x)", d, caps)
		}
	}

	// Below 3.0 there is nothing to advertise.
	srv := testSrv(t, t.TempDir(), nil)
	pc := NewProtoConn(srv, 0, 0, 1)
	if _, _, caps := offerDialects(t, srv, pc, capEncryption, 0x0210); caps&capEncryption != 0 {
		t.Errorf("dialect 2.1 advertised encryption: %#x", caps)
	}
}
