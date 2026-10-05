package samba

import (
	"fmt"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
)

// Kerberos acceptor: SPNEGO/GSS-facing glue over a pure-Go Kerberos service
// implementation.
//
// The original server delegated GSS-API acceptance to the system Kerberos
// library. This port keeps the same posture — keytab keyed by SPN, AP-REQ
// validation, clock-skew check, replay cache, and the Kerberos sub-session key
// used as the SMB session key — but implements it in pure Go through the
// gokrb5 service package, so the whole server stays CGO-free and statically
// linkable.
//
// SMB clients complete Kerberos in a single leg: the SESSION_SETUP blob carries
// a GSS initial-context token wrapping an AP-REQ, and the server answers with
// success (an AP-REP is not required, since SMB does not request mutual
// authentication). A multi-leg exchange is therefore rejected with a log line
// rather than half-supported.

// krbStepKind is the outcome of feeding one client token to the acceptor.
type krbStepKind int

const (
	// krbContinue means more legs are needed; `out` carries the reply token.
	krbContinue krbStepKind = iota
	// krbDone means the context is established.
	krbDone
	// krbFailed means authentication failed; `err` is a log-worthy reason.
	krbFailed
)

func (k krbStepKind) String() string {
	switch k {
	case krbContinue:
		return "continue"
	case krbDone:
		return "done"
	default:
		return "failed"
	}
}

// krbEstablished is a completed Kerberos authentication.
type krbEstablished struct {
	// Client is the authenticated principal, e.g. `alice@EXAMPLE.COM`.
	Client string
	// SessionKey is the Kerberos sub-session key. It is fed to the existing
	// SP800-108 KDF for signing/encryption keys, exactly like the NTLM key.
	SessionKey []byte
	// Out is the final output token (AP-REP) to return, if any.
	Out []byte
}

// krbStep is the result of one acceptor leg.
type krbStep struct {
	kind krbStepKind
	out  []byte
	est  *krbEstablished
	err  string
}

// KerberosAcceptor holds the service credential acquired from the keytab. It is
// safe for concurrent use, so each connection may hold one.
type KerberosAcceptor struct {
	spn      string
	settings *service.Settings
}

// DefaultKeytabPath is the system keytab used when no keytab is configured and
// $KRB5_KTNAME is unset.
const DefaultKeytabPath = "/etc/krb5.keytab"

// loadKeytab resolves and parses a keytab: the configured path, else
// $KRB5_KTNAME, else the system keytab.
func loadKeytab(path string) (*keytab.Keytab, error) {
	if path == "" {
		path = os.Getenv("KRB5_KTNAME")
	}
	if path == "" {
		path = DefaultKeytabPath
	}
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, fmt.Errorf("cannot load keytab %s: %w", path, err)
	}
	return kt, nil
}

// NewKerberosAcceptor acquires the acceptor credential for spn (e.g.
// `cifs/host.example.com`) from keytabPath (or the default keytab /
// $KRB5_KTNAME when empty).
func NewKerberosAcceptor(spn, keytabPath string) (*KerberosAcceptor, error) {
	kt, err := loadKeytab(keytabPath)
	if err != nil {
		return nil, err
	}
	return &KerberosAcceptor{
		spn:      spn,
		settings: service.NewSettings(kt, service.SName(spn)),
	}, nil
}

// Begin starts a new per-session acceptor context.
func (a *KerberosAcceptor) Begin() *kerberosCtx { return &kerberosCtx{acc: a} }

// kerberosCtx is an in-progress acceptor context for one SMB session/channel.
type kerberosCtx struct {
	acc *KerberosAcceptor
}

// Step feeds one client token (the GSS AP-REQ, unwrapped from SPNEGO by
// classifyBlob). On completion it extracts the Kerberos sub-session key.
func (c *kerberosCtx) Step(token []byte) krbStep {
	apReqDER, ok := unwrapGSSAPREQ(token)
	if !ok {
		return krbStep{kind: krbFailed, err: "malformed GSS AP-REQ token"}
	}
	var apReq messages.APReq
	if err := apReq.Unmarshal(apReqDER); err != nil {
		return krbStep{kind: krbFailed, err: fmt.Sprintf("cannot parse AP-REQ: %v", err)}
	}
	// VerifyAPREQ decrypts the ticket with the keytab, checks the authenticator
	// (clock skew, client-name match) and consults the replay cache.
	ok, _, err := service.VerifyAPREQ(&apReq, c.acc.settings)
	if err != nil {
		return krbStep{kind: krbFailed, err: err.Error()}
	}
	if !ok {
		return krbStep{kind: krbFailed, err: "AP-REQ rejected"}
	}

	// The SMB session key is the Kerberos sub-session key from the AP-REQ
	// authenticator (the same value GSS_C_INQ_SSPI_SESSION_KEY reports). A
	// client that omits a subkey falls back to the ticket session key.
	sessionKey := apReq.Authenticator.SubKey.KeyValue
	if len(sessionKey) == 0 {
		sessionKey = apReq.Ticket.DecryptedEncPart.Key.KeyValue
	}
	client := apReq.Authenticator.CName.PrincipalNameString()
	if realm := apReq.Authenticator.CRealm; realm != "" {
		client += "@" + realm
	}
	return krbStep{
		kind: krbDone,
		est:  &krbEstablished{Client: client, SessionKey: sessionKey},
	}
}

// unwrapGSSAPREQ strips the GSS-API initial-context wrapper (RFC 2743):
// [APPLICATION 0] { MechType OID, TOK_ID, AP-REQ }. A bare AP-REQ is accepted
// as-is.
func unwrapGSSAPREQ(token []byte) ([]byte, bool) {
	if len(token) == 0 {
		return nil, false
	}
	// A bare AP-REQ starts with the application tag for AP-REQ (0x6E).
	if token[0] == 0x6E {
		return token, true
	}
	wrapper, ok := parseTLV(token)
	if !ok || wrapper.tag != 0x60 {
		return nil, false
	}
	rest := wrapper.val
	if oid, ok := parseTLV(rest); ok && oid.tag == 0x06 {
		rest = rest[oid.len:]
	}
	// TOK_ID: a 2-byte token identifier, 0x01 0x00 for the initial AP-REQ.
	if len(rest) >= 2 && rest[0] == 0x01 && rest[1] == 0x00 {
		rest = rest[2:]
	}
	if len(rest) == 0 {
		return nil, false
	}
	return rest, true
}

// statusForKrbFailure maps a failed Kerberos authentication to the most
// informative SMB status. Clock skew is the single most common Kerberos
// misconfiguration, so it is surfaced distinctly; everything else is a logon
// failure.
func statusForKrbFailure(reason string) uint32 {
	r := strings.ToLower(reason)
	if strings.Contains(r, "clock skew") || (strings.Contains(r, "time") && strings.Contains(r, "skew")) {
		return StatusTimeDifferenceAtDC
	}
	return StatusLogonFailure
}

// kerberosSessionSetup handles a Kerberos SESSION_SETUP: it unwraps the GSS
// AP-REQ from SPNEGO, runs it through the connection's acceptor, and on success
// establishes the session using the Kerberos sub-session key for SMB
// signing/encryption.
func kerberosSessionSetup(srv *Srv, pc *ProtoConn, h *ReqHdr, msg []byte, chain *Chain, tx *Writer) {
	_, clientSecmode, blob, ok := parseSessionSetupReq(msg)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	incoming := classifyBlob(blob)
	wrapped := incoming.SPNEGO
	signingRequired := srv.cfg.RequireSigning || uint16(clientSecmode)&securityModeSigningRequired != 0
	dialect := pc.Dialect
	cipher := pc.Cipher

	// Resolve the (shared) acceptor credential once per connection.
	if pc.krbAcceptor == nil {
		if kcfg := srv.cfg.Kerberos; kcfg != nil && kcfg.Enabled != nil && !*kcfg.Enabled {
			LogWarn("kerberos: token received but [kerberos].enabled = false")
			errResp(tx, h, StatusNotSupported, chain)
			return
		}
		acc, err := srv.kerberosAcceptor()
		if err != nil {
			LogWarn("kerberos: acceptor init failed (%v)", err)
			errResp(tx, h, StatusLogonFailure, chain)
			return
		}
		pc.krbAcceptor = acc
	}

	step := pc.krbAcceptor.Begin().Step(incoming.Token)
	if step.kind != krbDone {
		if step.kind == krbContinue {
			LogWarn("kerberos: multi-leg exchange is not supported")
		} else {
			LogWarn("kerberos: authentication failed (%s)", step.err)
		}
		errResp(tx, h, statusForKrbFailure(step.err), chain)
		return
	}
	est := step.est

	// SMB session key: the first 16 bytes of the Kerberos sub-session key.
	var key [16]byte
	n := min(len(est.SessionKey), 16)
	copy(key[:], est.SessionKey[:n])

	// Fresh session; chain the 3.1.1 preauth over this single setup message.
	if len(pc.Channels) >= maxSessionsPerConn {
		LogWarn("refusing a session: %d already set up on this connection", len(pc.Channels))
		errResp(tx, h, StatusInsufficientResources, chain)
		return
	}
	sid, sref, created := srv.sessions.Create()
	if !created {
		LogWarn("refusing a session: the server is at its session limit (%d)", maxSessionsTotal)
		errResp(tx, h, StatusInsufficientResources, chain)
		return
	}
	chain.SessionID = sid
	var chPreauth [64]byte
	if dialect == 0x0311 {
		chPreauth = sha512Parts(pc.PreauthNeg[:], msg)
	}

	sref.Lock()
	sref.SessionKey = key
	sref.Established = true
	sref.Guest = false
	sref.SigningRequired = signingRequired
	sref.User = est.Client
	sref.Channels = 1
	sref.Unlock()

	sc := deriveSignCtx(dialect, &key, &chPreauth)
	ch := &ChannelState{
		Established:     true,
		SigningRequired: signingRequired,
		Sign:            &sc,
		Preauth:         chPreauth,
	}
	var ssFlags uint16
	if cipher != 0 && dialect == 0x0311 {
		c2s, s2c := smb311EncryptionKeys(cipher, &key, &chPreauth)
		ch.Enc = &EncCtx{Cipher: cipher, C2S: c2s, S2C: s2c}
		if srv.cfg.Encrypt {
			ch.Encrypt = true
			ssFlags |= sessionFlagEncryptData
		}
	}
	pc.Channels[sid] = ch

	signState := "optional"
	if signingRequired {
		signState = "required"
	}
	encState := "off"
	if ch.Enc != nil {
		encState = "ready"
	}
	LogInfo("session %x: kerberos principal %q authenticated (signing %s, encryption %s)", sid, est.Client, signState, encState)

	// Wrap the AP-REP (if any) in a SPNEGO accept-completed when the request was
	// SPNEGO-wrapped; otherwise return the raw GSS output token.
	done := est.Out
	if wrapped {
		done = negResp(acceptCompleted, mechKrb5, est.Out)
	}
	ssResp(tx, h, StatusSuccess, chain.Related, sid, ssFlags, done)
}
