package samba

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestStatusForKrbFailure(t *testing.T) {
	cases := []struct {
		reason string
		want   uint32
	}{
		{"clock skew too great", StatusTimeDifferenceAtDC},
		{"Clock Skew Too Great while validating", StatusTimeDifferenceAtDC},
		{"time skew between client and server", StatusTimeDifferenceAtDC},
		{"KDC has no support for encryption type", StatusLogonFailure},
		{"", StatusLogonFailure},
		{"integrity check failed", StatusLogonFailure},
	}
	for _, c := range cases {
		if got := statusForKrbFailure(c.reason); got != c.want {
			t.Errorf("statusForKrbFailure(%q) = %#x, want %#x", c.reason, got, c.want)
		}
	}
}

func TestKrbStepKindString(t *testing.T) {
	for kind, want := range map[krbStepKind]string{
		krbContinue: "continue",
		krbDone:     "done",
		krbFailed:   "failed",
	} {
		if got := kind.String(); got != want {
			t.Errorf("kind %d = %q, want %q", kind, got, want)
		}
	}
}

func TestUnwrapGSSAPREQFailures(t *testing.T) {
	if _, ok := unwrapGSSAPREQ(nil); ok {
		t.Fatal("an empty token must not unwrap")
	}
	if _, ok := unwrapGSSAPREQ([]byte{0x04, 0x01, 0x00}); ok {
		t.Fatal("a non-GSS token must not unwrap")
	}
	// A GSS wrapper with no inner token.
	if _, ok := unwrapGSSAPREQ(der(0x60, derOID(oidKrb5))); ok {
		t.Fatal("a wrapper with no AP-REQ must not unwrap")
	}
	// A wrapper whose body is only the token id.
	if _, ok := unwrapGSSAPREQ(der(0x60, []byte{0x01, 0x00})); ok {
		t.Fatal("a wrapper with only a token id must not unwrap")
	}
}

// writeTestKeytab creates a keytab holding the service key this test signs its
// tickets with, exactly as a KDC would have provisioned the server.
func writeTestKeytab(t *testing.T, path, spn, realm, password string) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(spn, realm, password, time.Now().UTC().Add(-time.Hour), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatalf("keytab entry: %v", err)
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatalf("keytab marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return kt
}

// buildAPREQ produces a genuine AP-REQ for spn, encrypted with the service key
// in kt, and returns its GSS initial-context wrapper.
func buildAPREQ(t *testing.T, kt *keytab.Keytab, spn, realm, client string) []byte {
	t.Helper()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, client)
	sname, _ := types.ParseSPNString(spn)
	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(
		cname, realm, sname, realm,
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), time.Time{},
	)
	if err != nil {
		t.Fatalf("ticket: %v", err)
	}
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	if err := auth.GenerateSeqNumberAndSubKey(etypeID.AES256_CTS_HMAC_SHA1_96, 32); err != nil {
		t.Fatalf("subkey: %v", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		t.Fatalf("ap-req: %v", err)
	}
	raw, err := apReq.Marshal()
	if err != nil {
		t.Fatalf("ap-req marshal: %v", err)
	}
	// Wrap it the way a GSS client does: application-0, mech OID, token id, AP-REQ.
	body := derOID(oidKrb5)
	body = append(body, 0x01, 0x00)
	body = append(body, raw...)
	return der(0x60, body)
}

// sessionSetupFrame builds a SESSION_SETUP request carrying a security blob.
func sessionSetupFrame(msgID, sess uint64, blob []byte, flags, secmode uint8) []byte {
	f := reqHdr(CmdSessionSetup, msgID, 0, sess)
	f.U16(25)
	f.U8(flags)
	f.U8(secmode)
	f.U32(0)
	f.U32(0)
	f.U16(88)
	f.U16(uint16(len(blob)))
	f.U64(0)
	f.Bytes8(blob)
	return f.Bytes()
}

// TestKerberosLoginEndToEnd drives a complete Kerberos SESSION_SETUP with a
// ticket signed by a keytab the server trusts, and checks that the session key
// is the Kerberos sub-session key from the AP-REQ authenticator.
func TestKerberosLoginEndToEnd(t *testing.T) {
	const (
		realm = "EXAMPLE.COM"
		spn   = "cifs/testsrv.example.com"
	)
	dir := t.TempDir()
	ktPath := filepath.Join(dir, "test.keytab")
	kt := writeTestKeytab(t, ktPath, spn, realm, "service-password")

	srv := testSrv(t, dir, nil)
	srv.cfg.ServerName = "TESTSRV"
	srv.cfg.Auth = AuthKerberos
	srv.cfg.Kerberos = &KerberosCfg{Keytab: ktPath, SPN: spn}
	srv.cfg.Encrypt = false

	pc := NewProtoConn(srv, 0, 0, 1)

	// NEGOTIATE first, as a real client would.
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

	// A SPNEGO-wrapped Kerberos AP-REQ, as cifs.ko sends.
	apReq := buildAPREQ(t, kt, spn, realm, "alice")
	init := der(0xA0, der(0x30,
		append(
			der(0xA0, der(0x30, derOID(oidKrb5))),
			der(0xA2, der(0x04, apReq))...)))
	body := derOID(oidSPNEGO)
	body = append(body, init...)
	blob := der(0x60, body)

	frame := sessionSetupFrame(2, 0, blob, 0, 1)
	r := roundtrip(t, srv, pc, frame)
	if r.status != StatusSuccess {
		t.Fatalf("kerberos session setup status %#x", r.status)
	}
	if r.sessionID == 0 {
		t.Fatal("a session id must be assigned")
	}
	// The session must be recorded as an authenticated, non-guest Kerberos
	// session under the client principal.
	sess, ok := srv.sessions.Get(r.sessionID)
	if !ok {
		t.Fatal("the session must exist")
	}
	sess.Lock()
	user := sess.User
	guest := sess.Guest
	established := sess.Established
	sess.Unlock()
	if !established || guest {
		t.Fatalf("session established=%t guest=%t", established, guest)
	}
	if user != "alice@"+realm {
		t.Fatalf("session user = %q, want alice@%s", user, realm)
	}
	// The channel must hold signing material derived from the Kerberos session
	// key, and the response must be signed.
	ch := pc.Channel(r.sessionID)
	if ch == nil || ch.Sign == nil {
		t.Fatalf("channel state = %+v", ch)
	}
	if r.flags&FlagSigned == 0 {
		t.Fatal("the SESSION_SETUP response must be signed")
	}
	// The response is SPNEGO-wrapped with the Kerberos mechanism.
	if inc := classifyBlob(r.body[8:]); inc.Mech != mechKrb5 {
		t.Fatalf("response mechanism = %v, want Kerberos", inc.Mech)
	}
}

// TestKerberosRejectsForeignKeytab checks that a ticket signed with a key the
// server does not hold is refused: the acceptor must actually verify, not just
// parse.
func TestKerberosRejectsForeignKeytab(t *testing.T) {
	const (
		realm = "EXAMPLE.COM"
		spn   = "cifs/testsrv.example.com"
	)
	dir := t.TempDir()
	ktPath := filepath.Join(dir, "server.keytab")
	writeTestKeytab(t, ktPath, spn, realm, "service-password")

	// A keytab for the same principal but a different key.
	foreignPath := filepath.Join(dir, "foreign.keytab")
	foreign := writeTestKeytab(t, foreignPath, spn, realm, "a-different-password")

	srv := testSrv(t, dir, nil)
	srv.cfg.Auth = AuthKerberos
	srv.cfg.Kerberos = &KerberosCfg{Keytab: ktPath, SPN: spn}
	pc := NewProtoConn(srv, 0, 0, 1)

	blob := buildAPREQ(t, foreign, spn, realm, "alice")
	r := roundtrip(t, srv, pc, sessionSetupFrame(1, 0, blob, 0, 1))
	if r.status != StatusLogonFailure {
		t.Fatalf("a foreign keytab must be refused, got %#x", r.status)
	}
}

// TestKerberosSessionSetupFailures covers the acceptor's failure and policy
// paths, none of which need a real KDC.
func TestKerberosSessionSetupFailures(t *testing.T) {
	dir := t.TempDir()
	newSrv := func(tune func(*Srv)) (*Srv, *ProtoConn) {
		srv := testSrv(t, dir, nil)
		srv.cfg.Auth = AuthKerberos
		tune(srv)
		return srv, NewProtoConn(srv, 0, 0, 1)
	}

	t.Run("no keytab configured", func(t *testing.T) {
		srv, pc := newSrv(func(s *Srv) {
			s.cfg.Kerberos = &KerberosCfg{Keytab: filepath.Join(dir, "missing.keytab")}
		})
		blob := buildFakeKrbBlob()
		if r := roundtrip(t, srv, pc, sessionSetupFrame(1, 0, blob, 0, 1)); r.status != StatusLogonFailure {
			t.Fatalf("status = %#x, want LOGON_FAILURE", r.status)
		}
	})

	t.Run("kerberos disabled", func(t *testing.T) {
		disabled := false
		srv, pc := newSrv(func(s *Srv) { s.cfg.Kerberos = &KerberosCfg{Enabled: &disabled} })
		blob := buildFakeKrbBlob()
		if r := roundtrip(t, srv, pc, sessionSetupFrame(1, 0, blob, 0, 1)); r.status != StatusNotSupported {
			t.Fatalf("status = %#x, want NOT_SUPPORTED", r.status)
		}
	})

	t.Run("malformed ap-req", func(t *testing.T) {
		ktPath := filepath.Join(dir, "kt")
		writeTestKeytab(t, ktPath, "cifs/test", "EXAMPLE.COM", "pw")
		srv, pc := newSrv(func(s *Srv) { s.cfg.Kerberos = &KerberosCfg{Keytab: ktPath, SPN: "cifs/test"} })
		// A well-formed GSS wrapper around garbage: the acceptor must fail
		// cleanly rather than panic.
		body := derOID(oidKrb5)
		body = append(body, 0x01, 0x00)
		body = append(body, der(0x6E, []byte("not really an ap-req"))...)
		blob := der(0x60, body)
		r := roundtrip(t, srv, pc, sessionSetupFrame(1, 0, blob, 0, 1))
		if r.status != StatusLogonFailure {
			t.Fatalf("status = %#x, want LOGON_FAILURE", r.status)
		}
	})

	t.Run("bad setup body", func(t *testing.T) {
		disabled := false
		srv, pc := newSrv(func(s *Srv) { s.cfg.Kerberos = &KerberosCfg{Enabled: &disabled} })
		f := reqHdr(CmdSessionSetup, 1, 0, 0)
		f.U16(9) // wrong StructureSize
		f.Zeros(24)
		if r := roundtrip(t, srv, pc, f.Bytes()); r.status != StatusInvalidParameter {
			t.Fatalf("status = %#x, want INVALID_PARAMETER", r.status)
		}
	})
}

// buildFakeKrbBlob is a syntactically valid SPNEGO Kerberos token that is not a
// real AP-REQ, for the paths that fail before validation.
func buildFakeKrbBlob() []byte {
	body := derOID(oidKrb5)
	body = append(body, 0x01, 0x00)
	body = append(body, der(0x6E, []byte("token"))...)
	return der(0x60, body)
}

// TestKerberosAcceptorRejectsGarbage checks the acceptor directly, without the
// SMB layer, so its failure classification is covered too.
func TestKerberosAcceptorRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	ktPath := filepath.Join(dir, "kt")
	writeTestKeytab(t, ktPath, "cifs/test", "EXAMPLE.COM", "pw")
	acc, err := NewKerberosAcceptor("cifs/test", ktPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range [][]byte{
		nil,
		[]byte("garbage"),
		der(0x60, []byte{0x01, 0x00}),
	} {
		step := acc.Begin().Step(tok)
		if step.kind != krbFailed {
			t.Fatalf("step(% x) = %v, want failed", tok, step.kind)
		}
		if step.err == "" {
			t.Fatal("a failure must carry a reason")
		}
	}
	// A keytab that cannot be read is an error, not a panic.
	if _, err := NewKerberosAcceptor("cifs/test", filepath.Join(dir, "nope")); err == nil {
		t.Fatal("a missing keytab must be an error")
	}
	// $KRB5_KTNAME is honored when no path is configured.
	t.Setenv("KRB5_KTNAME", ktPath)
	acc2, err := NewKerberosAcceptor("cifs/test", "")
	if err != nil {
		t.Fatalf("KRB5_KTNAME should be used: %v", err)
	}
	if acc2 == nil || acc2.settings == nil {
		t.Fatal("acceptor not built")
	}
	if !bytes.Contains([]byte(acc2.spn), []byte("cifs/test")) {
		t.Fatalf("spn = %q", acc2.spn)
	}
}
