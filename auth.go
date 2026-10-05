package samba

// Session establishment.
//
// Authentication itself is mechanism-specific — the NTLMv2 handshake lives in
// ntlm.go and its SESSION_SETUP handler in handlers.go — but *establishing the
// session* is not. Once a mechanism has decided that the peer is a user with a
// session key, or a guest, everything that follows is identical: the session
// bounds, installing the key, deriving the signing and encryption contexts for
// the negotiated dialect, the audit line, and the response.
//
// That shared tail lives here rather than in each mechanism, so the two cannot
// drift apart, and so a future mechanism has one place to plug into (see the
// authentication note in AGENTS.md). It is also the only code that turns an
// identity into a usable session, which is what keeps three properties true no
// matter what a mechanism does: a guest is never handed a key, the session
// bounds always apply, and SESSION_SETUP is answered exactly once.

// sessionAuth is the outcome of a mechanism-specific authentication: an identity
// with its session key, or a guest session. Anything else is a refusal, which
// the mechanism reports through rejectSessionSetup.
type sessionAuth struct {
	// User is the authenticated identity. Empty for a guest session.
	User string
	// Key is the SMB session key the mechanism derived from the negotiated
	// credential. Ignored for a guest session.
	Key [16]byte
	// Guest marks a guest/anonymous session. A guest has no key, so it can
	// neither sign nor encrypt, and it is refused when the server requires
	// encryption.
	Guest bool
	// Token is the final output token to return to the client, when the
	// mechanism has one: NTLM passes the SPNEGO accept-completed token or
	// nothing, and a mechanism with a real final token (a GSS AP-REP, say)
	// puts it here.
	Token []byte
}

// sessionSetupCtx is one SESSION_SETUP request: the decoded security blob plus
// the connection and chain it arrived on. The request is decoded once, here, and
// both the mechanism and the establishment code below work from it instead of
// re-deriving the same fields.
type sessionSetupCtx struct {
	srv   *Srv
	pc    *ProtoConn
	h     *ReqHdr
	chain *Chain
	tx    *Writer

	// blob is the client's security buffer.
	blob []byte
	// spnego records that the blob was SPNEGO-wrapped, so the response has to
	// be wrapped to match.
	spnego bool
	// binding marks the multichannel session-binding handshake, which attaches
	// this connection to an existing session instead of creating one.
	binding bool
	// signReqd is whether signing is required on this session, from the server
	// policy or the client's own security mode.
	signReqd bool
}

// newSessionSetup decodes a SESSION_SETUP request into a context. It answers
// STATUS_INVALID_PARAMETER and reports false when the request is malformed, so
// the caller can return immediately.
func newSessionSetup(srv *Srv, pc *ProtoConn, h *ReqHdr, msg []byte, chain *Chain, tx *Writer) (sessionSetupCtx, bool) {
	s := sessionSetupCtx{srv: srv, pc: pc, h: h, chain: chain, tx: tx}
	ssFlags, clientSecmode, blob, ok := parseSessionSetupReq(msg)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return s, false
	}
	s.blob = blob
	s.spnego = isSPNEGO(blob)
	s.binding = ssFlags&sessionFlagBinding != 0
	s.signReqd = srv.cfg.RequireSigning || uint16(clientSecmode)&securityModeSigningRequired != 0
	return s, true
}

// createSession allocates a session for a fresh (non-binding) setup, enforcing
// the per-connection and server-wide bounds. A client can ask for sessions far
// faster than for anything else, and each one costs a handle table and a tree
// map, so both counts are capped. It answers STATUS_INSUFFICIENT_RESOURCES and
// reports false when the limit is reached.
func (s *sessionSetupCtx) createSession() (uint64, bool) {
	if len(s.pc.Channels) >= maxSessionsPerConn {
		LogWarn("refusing a session: %d already set up on this connection", len(s.pc.Channels))
		errResp(s.tx, s.h, StatusInsufficientResources, s.chain)
		return 0, false
	}
	sid, _, created := s.srv.sessions.Create()
	if !created {
		LogWarn("refusing a session: the server is at its session limit (%d)", maxSessionsTotal)
		errResp(s.tx, s.h, StatusInsufficientResources, s.chain)
		return 0, false
	}
	return sid, true
}

// rejectSessionSetup drops a half-built session and answers with status. Every
// authentication failure goes through here, so a refused attempt cannot leave a
// session slot or a channel entry behind.
func (s *sessionSetupCtx) rejectSessionSetup(status uint32) {
	sid := s.chain.SessionID
	delete(s.pc.Channels, sid)
	s.srv.sessions.Remove(sid)
	errResp(s.tx, s.h, status, s.chain)
}

// establish completes an authenticated SESSION_SETUP: it installs the session
// key into the shared session record and into this channel's state, derives the
// signing context and — when a cipher was negotiated — the encryption context
// for the negotiated dialect, logs what was established, and writes the
// SESSION_SETUP response.
//
// The session must already exist and be one of this connection's channels.
func (s *sessionSetupCtx) establish(authed sessionAuth) {
	sid := s.chain.SessionID
	sref, ok := s.srv.sessions.Get(sid)
	if !ok {
		errResp(s.tx, s.h, StatusUserSessionDeleted, s.chain)
		return
	}
	ch := s.pc.Channel(sid)
	if ch == nil {
		errResp(s.tx, s.h, StatusUserSessionDeleted, s.chain)
		return
	}

	if authed.Guest {
		// A guest session carries no key, so it can neither sign nor encrypt.
		// Rather than let the client seal traffic the server cannot decrypt,
		// refuse it outright when encryption is required.
		if s.srv.cfg.Encrypt {
			LogWarn("session %x: guest denied — encryption is required but guest sessions cannot be encrypted", sid)
			s.rejectSessionSetup(StatusAccessDenied)
			return
		}
		sref.Lock()
		sref.Established = true
		sref.Guest = true
		sref.Channels = 1
		sref.Unlock()
		ch.Established = true
		ssResp(s.tx, s.h, StatusSuccess, s.chain.Related, sid, sessionFlagIsGuest, authed.Token)
		return
	}

	dialect := s.pc.Dialect
	cipher := s.pc.Cipher
	chPreauth := ch.Preauth

	sref.Lock()
	sref.SessionKey = authed.Key
	sref.Established = true
	sref.Guest = false
	sref.SigningRequired = s.signReqd
	sref.User = authed.User
	sref.Channels = 1
	sref.Unlock()

	ch.Established = true
	ch.SigningRequired = s.signReqd
	sc := deriveSignCtx(dialect, &authed.Key, &chPreauth)
	ch.Sign = &sc

	// SMB3 encryption: derive the keys when a cipher was negotiated. If the
	// server requires encryption, set ENCRYPT_DATA so the client seals all
	// subsequent traffic; otherwise stay ready to honor client-initiated
	// encryption (e.g. cifs `seal`).
	var flags uint16
	if cipher != 0 && dialect == 0x0311 {
		c2s, s2c := smb311EncryptionKeys(cipher, &authed.Key, &chPreauth)
		ch.Enc = &EncCtx{Cipher: cipher, C2S: c2s, S2C: s2c}
		if s.srv.cfg.Encrypt {
			ch.Encrypt = true
			flags |= sessionFlagEncryptData
		}
	}
	logSessionEstablished(sid, authed.User, s.signReqd, ch.Enc != nil)
	ssResp(s.tx, s.h, StatusSuccess, s.chain.Related, sid, flags, authed.Token)
}

// logSessionEstablished reports one successful session setup, in the same shape
// whichever mechanism produced it.
func logSessionEstablished(sid uint64, user string, signReqd, encReady bool) {
	signState := "optional"
	if signReqd {
		signState = "required"
	}
	encState := "off"
	if encReady {
		encState = "ready"
	}
	LogInfo("session %x: user %q authenticated (signing %s, encryption %s)", sid, user, signState, encState)
}
