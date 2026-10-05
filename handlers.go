package samba

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// SMB2 command handlers.

// DesiredAccess bits.
const (
	fileWriteData    uint32 = 0x0000_0002
	fileAppendData   uint32 = 0x0000_0004
	maximumAllowed   uint32 = 0x0200_0000
	genericAll       uint32 = 0x1000_0000
	genericWrite     uint32 = 0x4000_0000
	writeBits               = fileWriteData | fileAppendData | genericWrite | genericAll
	maximalAccessAll uint32 = 0x001F_01FF
)

// CreateDisposition values.
const (
	fileSupersede   uint32 = 0
	fileOpen        uint32 = 1
	fileCreate      uint32 = 2
	fileOpenIf      uint32 = 3
	fileOverwrite   uint32 = 4
	fileOverwriteIf uint32 = 5
)

// CreateOptions bits.
const (
	fileDirectoryFile    uint32 = 0x0001
	fileNonDirectoryFile uint32 = 0x0040
	fileDeleteOnClose    uint32 = 0x1000
)

// ShareType / CreateAction.
const (
	createActionOpened      uint32 = 1
	createActionCreated     uint32 = 2
	createActionOverwritten uint32 = 3
)

// FSCTL codes.
const (
	fsctlValidateNegotiateInfo     uint32 = 0x0014_0204
	fsctlQueryNetworkInterfaceInfo uint32 = 0x0014_01FC
)

// Supported dialects, in server preference order.
var supportedDialects = []uint16{0x0311, 0x0302, 0x0300, 0x0210, 0x0202}

// Capability and security-mode bits.
const (
	capLeasing      uint32 = 0x2
	capLargeMTU     uint32 = 0x4
	capMultiChannel uint32 = 0x8

	securityModeSigningEnabled  uint16 = 0x1
	securityModeSigningRequired uint16 = 0x2

	sessionFlagIsGuest     uint16 = 0x1
	sessionFlagEncryptData uint16 = 0x4
	sessionFlagBinding     uint8  = 0x01
)

// creditWindow is the maximum number of credits a connection may hold.
const creditWindow int64 = 512

// connID locates a connection in the worker table (worker, slot, generation).
type connID struct {
	Wid int
	Idx int
	Gen uint16
}

// dispatch routes one SMB2 command to its handler. It returns a non-nil plan
// when the transport must serve the response zero-copy. sealed reports whether
// these messages arrived inside an SMB3 transform (so they are already
// integrity-protected and must not be rejected for being unencrypted).
func dispatch(srv *Srv, pc *ProtoConn, h *ReqHdr, msg []byte, chain *Chain, tx *Writer, sealed bool) *ZcReadPlan {
	body := msg[64:]

	// Resolve the effective session/tree for related compound operations.
	if h.Flags&FlagRelated != 0 {
		chain.Related = true
		if h.SessionID != 0 && h.SessionID != ^uint64(0) {
			chain.SessionID = h.SessionID
		}
		if h.TreeID != 0 && h.TreeID != ^uint32(0) {
			chain.TreeID = h.TreeID
		}
	} else {
		chain.Related = false
		chain.SessionID = h.SessionID
		chain.TreeID = h.TreeID
	}

	// Credit accounting: consume the charge, grant within the window.
	pc.CreditsOut = max(pc.CreditsOut-int64(max(h.CreditCharge, 1)), 0)
	avail := max(creditWindow-pc.CreditsOut, 1)
	grant := uint16(clamp(int64(h.Credits), 1, avail))
	pc.CreditsOut += int64(grant)
	hdr := *h
	hdr.Credits = grant
	h = &hdr

	// A session that must encrypt rejects any request that did not arrive
	// sealed. The server told the client to seal (SESSION_FLAG_ENCRYPT_DATA, or
	// the client turned sealing on itself), so honoring a plaintext request
	// would let an attacker strip encryption from the session — which is
	// precisely what SMB3 encryption exists to prevent.
	if ch := pc.Channel(chain.SessionID); ch != nil && ch.Encrypt && !sealed &&
		h.Command != CmdNegotiate && h.Command != CmdSessionSetup && h.Command != CmdCancel {
		LogWarn("session %x: unencrypted %s on an encryption-required session", chain.SessionID, cmdName(h.Command))
		errResp(tx, h, StatusAccessDenied, chain)
		return nil
	}

	// Verify signatures on signed requests, and reject unsigned requests on
	// signing-required channels. Signing state is connection-local. This is
	// skipped for encrypted sessions: an SMB3-encrypted message is not
	// separately signed (the AEAD tag provides integrity, verified at decrypt).
	if ch := pc.Channel(chain.SessionID); ch != nil && !ch.Encrypt && ch.Sign != nil {
		if h.Flags&FlagSigned != 0 {
			if !verifySignature(msg, ch.Sign) {
				errResp(tx, h, StatusAccessDenied, chain)
				return nil
			}
		} else if ch.SigningRequired &&
			h.Command != CmdNegotiate && h.Command != CmdSessionSetup && h.Command != CmdCancel {
			errResp(tx, h, StatusAccessDenied, chain)
			return nil
		}
	}

	switch h.Command {
	case CmdNegotiate:
		negotiate(srv, pc, h, msg, chain, tx)
	case CmdEcho:
		simpleResp(tx, h, chain)
	case CmdCancel:
		cancel(pc, h)
	case CmdSessionSetup:
		sessionSetup(srv, pc, h, msg, chain, tx)
	case CmdLogoff:
		logoff(srv, pc, h, chain, tx)
	default:
		// An established session is required. The channel proves this
		// connection is bound; the shared session holds trees and handles.
		ch := pc.Channel(chain.SessionID)
		if ch == nil || !ch.Established {
			errResp(tx, h, StatusUserSessionDeleted, chain)
			return nil
		}
		sess, ok := srv.sessions.Get(chain.SessionID)
		if !ok {
			errResp(tx, h, StatusUserSessionDeleted, chain)
			return nil
		}

		if h.Command == CmdTreeConnect {
			sess.Lock()
			treeConnect(srv, sess, h, msg, chain, tx)
			sess.Unlock()
			return nil
		}

		sess.Lock()
		tree, ok := sess.Trees[chain.TreeID]
		if !ok {
			sess.Unlock()
			errResp(tx, h, StatusNetworkNameDeleted, chain)
			return nil
		}
		if h.Command == CmdTreeDisconnect {
			delete(sess.Trees, chain.TreeID)
			sess.Unlock()
			simpleResp(tx, h, chain)
			return nil
		}
		if tree.IPC {
			sess.Unlock()
			if h.Command == CmdIoctl {
				ioctl(srv, pc, h, msg, chain, tx)
			} else {
				errResp(tx, h, StatusAccessDenied, chain)
			}
			return nil
		}
		share := &srv.cfg.Shares[tree.ShareIdx]
		cid := connID{pc.Wid, pc.ConnIdx, pc.ConnGen}
		// Only grant oplocks on non-encrypted sessions: a break notification on
		// an encrypted session would need to be sealed too.
		allowOplock := pc.Channel(h.SessionID) == nil || !pc.Channel(h.SessionID).Encrypt

		switch h.Command {
		case CmdRead:
			// Read re-locks the session itself so concurrent reads across
			// channels do not serialize on the session lock.
			sess.Unlock()
			return read(pc, sess, h, body, chain, tx)
		case CmdIoctl:
			sess.Unlock()
			ioctl(srv, pc, h, msg, chain, tx)
			return nil
		case CmdCreate:
			create(srv, sess, h, msg, chain, tx, share, tree.ShareIdx, cid, allowOplock)
		case CmdClose:
			closeHandle(srv, pc, sess, h, body, chain, tx)
		case CmdFlush:
			flush(sess, h, body, chain, tx)
		case CmdWrite:
			write(srv, sess, h, msg, chain, tx, share, tree.ShareIdx)
		case CmdQueryDirectory:
			queryDirectory(sess, h, msg, chain, tx)
		case CmdQueryInfo:
			queryInfo(srv, sess, h, body, chain, tx)
		case CmdSetInfo:
			setInfo(sess, h, msg, chain, tx, share)
		case CmdLock:
			lockRange(sess, h, body, chain, tx)
		case CmdChangeNotify:
			changeNotify(pc, sess, h, body, chain, tx)
		default:
			errResp(tx, h, StatusNotSupported, chain)
		}
		sess.Unlock()
	}
	return nil
}

// logoff drops this connection's channel and tears down the shared session when
// its last channel goes away.
func logoff(srv *Srv, pc *ProtoConn, h *ReqHdr, chain *Chain, tx *Writer) {
	if _, ok := pc.Channels[chain.SessionID]; !ok {
		errResp(tx, h, StatusUserSessionDeleted, chain)
		return
	}
	delete(pc.Channels, chain.SessionID)
	if sess, ok := srv.sessions.Get(chain.SessionID); ok {
		sess.Lock()
		if sess.Channels > 0 {
			sess.Channels--
		}
		drop := sess.Channels == 0
		sess.Unlock()
		if drop {
			if s, ok := srv.sessions.Remove(chain.SessionID); ok {
				s.Lock()
				s.Handles.CloseAll()
				s.Unlock()
			}
		}
	}
	simpleResp(tx, h, chain)
}

// cancel pends no response of its own: a matching pended operation completes
// with STATUS_CANCELLED through the notify queues.
func cancel(pc *ProtoConn, h *ReqHdr) {
	if h.AsyncID == nil {
		return // synchronous cancel of a completed operation: nothing pended
	}
	aid := *h.AsyncID
	for i, e := range pc.NotifyActive {
		if e[1] == aid {
			pc.NotifyActive = append(pc.NotifyActive[:i], pc.NotifyActive[i+1:]...)
			pc.NotifyDone = append(pc.NotifyDone, NotifyDone{AsyncID: aid, Status: StatusCancelled})
			return
		}
	}
}

func simpleResp(tx *Writer, h *ReqHdr, chain *Chain) {
	beginResp(tx, h, StatusSuccess, chain.Related, chain.TreeID, chain.SessionID)
	tx.U16(4)
	tx.U16(0)
}

// parseFID reads a 16-byte FileId. All-ones means "use the previous handle in
// the compound chain".
func parseFID(r *Reader, chain *Chain) (uint64, bool) {
	persistent, ok := r.U64()
	if !ok {
		return 0, false
	}
	volatile, ok := r.U64()
	if !ok {
		return 0, false
	}
	if persistent == ^uint64(0) && volatile == ^uint64(0) {
		if chain.LastFID == nil {
			return 0, false
		}
		return *chain.LastFID, true
	}
	return volatile, true
}

func putFID(tx *Writer, fid uint64) {
	tx.U64(fid)
	tx.U64(fid)
}

// ---------------------------------------------------------------- NEGOTIATE

func negotiate(srv *Srv, pc *ProtoConn, h *ReqHdr, msg []byte, chain *Chain, tx *Writer) {
	body := msg[64:]
	dialects, ctxOff, ctxCount, ok := parseNegotiateReq(body)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	chosen := uint16(0)
	for _, d := range supportedDialects {
		if containsU16(dialects, d) {
			chosen = d
			break
		}
	}
	if chosen == 0 {
		errResp(tx, h, StatusNotSupported, chain)
		return
	}

	// For 3.1.1, require the preauth integrity context (SHA-512) and pick a
	// cipher from the client's encryption capabilities.
	cipher := uint16(0)
	if chosen == 0x0311 {
		havePreauth := false
		off := ctxOff
		for range min(ctxCount, 16) {
			t, dataLen, ok := parseNegotiateContext(msg, off)
			if !ok {
				break
			}
			switch t {
			case 1:
				havePreauth = preauthCtxSupportsSHA512(msg, off, dataLen)
			case 2:
				cipher = chooseCipher(srv, msg, off, dataLen)
			}
			off += uint32(8 + dataLen)
			off = (off + 7) &^ 7
		}
		if !havePreauth {
			errResp(tx, h, StatusInvalidParameter, chain)
			return
		}
	}

	pc.Dialect = chosen
	pc.Cipher = cipher
	if cipher != 0 {
		LogDebug("negotiated dialect %#x cipher %#x", chosen, cipher)
	}
	start := beginResp(tx, h, StatusSuccess, false, 0, 0)
	negotiateBody(srv, pc, chosen, cipher, start, tx)
}

func parseNegotiateReq(body []byte) (dialects []uint16, ctxOff uint32, ctxCount uint16, ok bool) {
	r := NewReader(body)
	if v, ok := r.U16(); !ok || v != 36 {
		return nil, 0, 0, false
	}
	count, ok := r.U16()
	if !ok {
		return nil, 0, 0, false
	}
	if !r.Skip(2 + 2 + 4 + 16) { // security mode, reserved, capabilities, guid
		return nil, 0, 0, false
	}
	ctxOff, ok = r.U32()
	if !ok {
		return nil, 0, 0, false
	}
	ctxCount, ok = r.U16()
	if !ok {
		return nil, 0, 0, false
	}
	if !r.Skip(2) {
		return nil, 0, 0, false
	}
	n := min(int(count), 16)
	for range n {
		d, ok := r.U16()
		if !ok {
			return nil, 0, 0, false
		}
		dialects = append(dialects, d)
	}
	return dialects, ctxOff, ctxCount, true
}

// parseNegotiateContext reads one SMB2_NEGOTIATE_CONTEXT header.
func parseNegotiateContext(msg []byte, off uint32) (typ uint16, dataLen int, ok bool) {
	sl, ok := sliceAt(msg, int(off), len(msg)-int(off))
	if !ok {
		return 0, 0, false
	}
	r := NewReader(sl)
	t, ok := r.U16()
	if !ok {
		return 0, 0, false
	}
	l, ok := r.U16()
	if !ok {
		return 0, 0, false
	}
	if !r.Skip(4) {
		return 0, 0, false
	}
	return t, int(l), true
}

// preauthCtxSupportsSHA512 reports whether a PREAUTH_INTEGRITY_CAPABILITIES
// context offers SHA-512 (hash algorithm id 1).
func preauthCtxSupportsSHA512(msg []byte, off uint32, dataLen int) bool {
	data, ok := sliceAt(msg, int(off)+8, dataLen)
	if !ok {
		return false
	}
	r := NewReader(data)
	n, ok := r.U16()
	if !ok {
		return false
	}
	if _, ok := r.U16(); !ok { // salt length
		return false
	}
	for range min(int(n), 8) {
		algo, ok := r.U16()
		if !ok {
			return false
		}
		if algo == 1 {
			return true
		}
	}
	return false
}

// chooseCipher picks the negotiated AES cipher from the client's
// SMB2_ENCRYPTION_CAPABILITIES list.
func chooseCipher(srv *Srv, msg []byte, off uint32, dataLen int) uint16 {
	data, ok := sliceAt(msg, int(off)+8, dataLen)
	if !ok {
		return 0
	}
	r := NewReader(data)
	n, ok := r.U16()
	if !ok {
		return 0
	}
	var offered []uint16
	for range min(int(n), 8) {
		c, ok := r.U16()
		if !ok {
			break
		}
		if cipherSupported(c) {
			offered = append(offered, c)
		}
	}
	if srv.cfg.PreferAES256 {
		// Server preference: strongest GCM, then CCM.
		for _, want := range []uint16{CipherAES256GCM, CipherAES256CCM, CipherAES128GCM, CipherAES128CCM} {
			if containsU16(offered, want) {
				return want
			}
		}
		return 0
	}
	if len(offered) == 0 {
		return 0
	}
	return offered[0] // honor the client's preference order
}

// negotiateRespSMB1Wildcard answers a legacy SMB1 NEGOTIATE with the SMB2
// wildcard dialect, so an SMB2-capable client upgrades.
func negotiateRespSMB1Wildcard(srv *Srv, pc *ProtoConn, tx *Writer) {
	h := &ReqHdr{Credits: 1, Command: CmdNegotiate}
	start := beginResp(tx, h, StatusSuccess, false, 0, 0)
	negotiateBody(srv, pc, 0x02FF, 0, start, tx)
}

func negotiateBody(srv *Srv, pc *ProtoConn, dialect, cipher uint16, respStart int, tx *Writer) {
	secmode := securityModeSigningEnabled
	if srv.cfg.RequireSigning {
		secmode |= securityModeSigningRequired
	}
	// The SPNEGO NegTokenInit2 hint advertises the mechanisms this server is
	// willing to accept, Kerberos first so a Kerberos-capable client prefers it.
	var mechs []Mech
	if srv.cfg.Auth.AllowsKerberos() {
		mechs = append(mechs, mechKrb5)
	}
	if srv.cfg.Auth.AllowsNTLM() {
		mechs = append(mechs, mechNtlmssp)
	}
	hint := negInitHint(mechs)

	body := respStart + 64
	tx.U16(65)
	tx.U16(secmode)
	tx.U16(dialect)
	tx.U16(0) // NegotiateContextCount, patched below for 3.1.1
	tx.Bytes8(srv.guid[:])
	// MULTI_CHANNEL is an SMB 3.x capability: it lets a client open several
	// connections to one share and stripe I/O across them.
	caps := capLargeMTU
	if dialect >= 0x0300 && srv.cfg.Multichannel {
		caps |= capMultiChannel
	}
	// Advertise leasing (SMB 2.1+) so clients request leases (RqLs) instead of
	// legacy oplocks; the caching/break path is lease-based.
	if dialect >= 0x0210 && srv.cfg.Oplocks {
		caps |= capLeasing
	}
	tx.U32(caps)
	tx.U32(MaxTransact)
	tx.U32(pc.MaxRead)
	tx.U32(MaxWrite)
	tx.U64(filetimeNow())
	tx.U64(srv.startFT)
	tx.U16(128) // SecurityBufferOffset (header 64 + fixed body 64)
	tx.U16(uint16(len(hint)))
	tx.U32(0) // NegotiateContextOffset, patched below
	tx.Bytes8(hint)

	if dialect == 0x0311 {
		tx.Pad8(respStart)
		ctxOff := tx.Len() - respStart
		count := uint16(1)
		// PREAUTH_INTEGRITY_CAPABILITIES: SHA-512 + 32-byte salt.
		var salt [32]byte
		randBytes(salt[:])
		tx.U16(1)
		tx.U16(38)
		tx.U32(0)
		tx.U16(1)
		tx.U16(32)
		tx.U16(1) // SHA-512
		tx.Bytes8(salt[:])
		if cipher != 0 {
			tx.Pad8(respStart)
			// SMB2_ENCRYPTION_CAPABILITIES: the selected cipher.
			count++
			tx.U16(2)
			tx.U16(4)
			tx.U32(0)
			tx.U16(1) // CipherCount
			tx.U16(cipher)
		}
		tx.Patch32(body+60, uint32(ctxOff))
		tx.Patch16(body+6, count)
	}
}

// ------------------------------------------------------------ SESSION_SETUP

func ssResp(tx *Writer, h *ReqHdr, st uint32, related bool, sid uint64, flags uint16, blob []byte) {
	beginResp(tx, h, st, related, 0, sid)
	tx.U16(9)
	tx.U16(flags)
	tx.U16(72) // SecurityBufferOffset
	tx.U16(uint16(len(blob)))
	tx.Bytes8(blob)
}

// sessionSetup classifies the SPNEGO/raw security blob and routes it to the
// mechanism that owns it, subject to the `auth` policy. Kerberos is preferred
// when both are offered. A token for a mechanism that is disabled by policy is
// rejected with STATUS_NOT_SUPPORTED (fail loudly).
func sessionSetup(srv *Srv, pc *ProtoConn, h *ReqHdr, msg []byte, chain *Chain, tx *Writer) {
	blob, ok := sessionSetupBlob(msg)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	mech := classifyBlob(blob).Mech
	allowKrb := srv.cfg.Auth.AllowsKerberos()
	allowNTLM := srv.cfg.Auth.AllowsNTLM()

	switch {
	case mech == mechKrb5 && allowKrb:
		kerberosSessionSetup(srv, pc, h, msg, chain, tx)
	case (mech == mechNtlmssp || mech == mechUnknown) && allowNTLM:
		ntlmSessionSetup(srv, pc, h, msg, chain, tx)
	default:
		LogInfo("session_setup: no enabled auth mechanism for the offered token (auth=%s)", srv.cfg.Auth)
		errResp(tx, h, StatusNotSupported, chain)
	}
}

// sessionSetupBlob extracts the SESSION_SETUP security buffer.
func sessionSetupBlob(msg []byte) ([]byte, bool) {
	r := NewReader(msg[64:])
	if v, ok := r.U16(); !ok || v != 25 {
		return nil, false
	}
	if !r.Skip(1 + 1 + 4 + 4) { // flags, security mode, capabilities, channel
		return nil, false
	}
	off, ok := r.U16()
	if !ok {
		return nil, false
	}
	length, ok := r.U16()
	if !ok {
		return nil, false
	}
	if length == 0 {
		return []byte{}, true
	}
	return sliceAt(msg, int(off), int(length))
}

func ntlmSessionSetup(srv *Srv, pc *ProtoConn, h *ReqHdr, msg []byte, chain *Chain, tx *Writer) {
	ssFlags, clientSecmode, blob, ok := parseSessionSetupReq(msg)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	spnego := isSPNEGO(blob)
	binding := ssFlags&sessionFlagBinding != 0
	signingRequired := srv.cfg.RequireSigning || uint16(clientSecmode)&securityModeSigningRequired != 0

	switch classifyToken(blob) {
	case TokenNegotiate:
		// Interim: assign/locate the session id, stash a challenge in this
		// connection's channel state, and respond with the NTLM CHALLENGE.
		var sid uint64
		if binding {
			// Bind to an existing session — it must already exist.
			if h.SessionID == 0 {
				errResp(tx, h, StatusUserSessionDeleted, chain)
				return
			}
			if _, ok := srv.sessions.Get(h.SessionID); !ok {
				errResp(tx, h, StatusUserSessionDeleted, chain)
				return
			}
			sid = h.SessionID
		} else {
			sid, _ = srv.sessions.Create()
		}
		chain.SessionID = sid
		ch := &ChannelState{
			Pending: &PendingAuth{SPNEGO: spnego, Binding: binding},
			Preauth: pc.PreauthNeg,
		}
		randBytes(ch.Pending.Challenge[:])
		if pc.Dialect == 0x0311 {
			ch.Preauth = sha512Parts(ch.Preauth[:], msg)
		}
		pc.Channels[sid] = ch

		token := ntlmChallenge(srv.cfg.ServerName, ch.Pending.Challenge, ntlmNegotiateFlags(blob))
		if spnego {
			token = spnegoWrapChallenge(token)
		}
		ssResp(tx, h, StatusMoreProcessingRequire, chain.Related, sid, 0, token)

	case TokenAuthenticate:
		sid := h.SessionID
		chain.SessionID = sid
		ch := pc.Channel(sid)
		if ch == nil {
			errResp(tx, h, StatusUserSessionDeleted, chain)
			return
		}
		if pc.Dialect == 0x0311 {
			ch.Preauth = sha512Parts(ch.Preauth[:], msg)
		}
		pending := ch.Pending
		if pending == nil {
			// Re-authentication on an already-established channel: acknowledge.
			var flags uint16
			if ch.Sign == nil {
				flags = sessionFlagIsGuest
			}
			ssResp(tx, h, StatusSuccess, chain.Related, sid, flags, nil)
			return
		}
		ch.Pending = nil
		chPreauth := ch.Preauth
		wrapped := pending.SPNEGO || spnego
		var done []byte
		if wrapped {
			done = spnegoAcceptCompleted()
		}
		dialect := pc.Dialect
		cipher := pc.Cipher

		sref, ok := srv.sessions.Get(sid)
		if !ok {
			errResp(tx, h, StatusUserSessionDeleted, chain)
			return
		}
		auth, _ := parseAuthenticate(blob)

		if pending.Binding {
			// Channel binding: prove the same identity, then derive this
			// channel's signing key from the session's original key.
			sref.Lock()
			ok := false
			switch {
			case !sref.Established:
				ok = false
			case sref.Guest:
				// Guest sessions carry no key; binding is signing-free
				// regardless of what the client presents.
				ok = true
			case auth != nil && !auth.IsAnonymous():
				if nt, found := srv.users[strings.ToLower(auth.User)]; found &&
					strings.EqualFold(auth.User, sref.User) {
					_, verified := verifyNTLMv2(&nt, auth, &pending.Challenge)
					ok = verified
				}
			}
			if !ok {
				bindUser := ""
				anon := true
				if auth != nil {
					bindUser = auth.User
					anon = auth.IsAnonymous()
				}
				LogWarn("session %x: channel bind rejected (established=%t guest=%t sess_user=%q bind_user=%q anon=%t)",
					sid, sref.Established, sref.Guest, sref.User, bindUser, anon)
				sref.Unlock()
				delete(pc.Channels, sid)
				errResp(tx, h, StatusAccessDenied, chain)
				return
			}
			key := sref.SessionKey
			guest := sref.Guest
			sref.Channels++
			sref.Unlock()

			chm := pc.Channel(sid)
			chm.Established = true
			chm.SigningRequired = signingRequired && !guest
			if guest {
				chm.Sign = nil
			} else {
				sc := deriveSignCtx(dialect, &key, &chPreauth)
				chm.Sign = &sc
			}
			// This channel's own encryption keys (per-connection preauth).
			var flags uint16
			if guest {
				flags = sessionFlagIsGuest
			}
			if !guest && cipher != 0 && dialect == 0x0311 {
				c2s, s2c := smb311EncryptionKeys(cipher, &key, &chPreauth)
				chm.Enc = &EncCtx{Cipher: cipher, C2S: c2s, S2C: s2c}
				if srv.cfg.Encrypt {
					chm.Encrypt = true
					flags |= sessionFlagEncryptData
				}
			}
			LogInfo("session %x: channel bound (now striping)", sid)
			ssResp(tx, h, StatusSuccess, chain.Related, sid, flags, done)
			return
		}

		// First authentication on a fresh session.
		type verdict int
		const (
			verdictUser verdict = iota
			verdictGuest
			verdictReject
		)
		v := verdictReject
		var userKey [16]byte
		var userName string
		switch {
		case auth != nil && !auth.IsAnonymous():
			if nt, found := srv.users[strings.ToLower(auth.User)]; found {
				if key, ok := verifyNTLMv2(&nt, auth, &pending.Challenge); ok {
					v, userKey, userName = verdictUser, key, auth.User
				}
			} else if srv.allowGuest {
				v = verdictGuest
			}
		case srv.allowGuest:
			v = verdictGuest
		}

		switch v {
		case verdictUser:
			sref.Lock()
			sref.SessionKey = userKey
			sref.Established = true
			sref.Guest = false
			sref.SigningRequired = signingRequired
			sref.User = userName
			sref.Channels = 1
			sref.Unlock()

			chm := pc.Channel(sid)
			chm.Established = true
			chm.SigningRequired = signingRequired
			sc := deriveSignCtx(dialect, &userKey, &chPreauth)
			chm.Sign = &sc
			// SMB3 encryption: derive keys when a cipher is negotiated. If the
			// server requires encryption, set ENCRYPT_DATA so the client seals
			// all subsequent traffic; otherwise stay ready to honor
			// client-initiated encryption (e.g. cifs `seal`).
			var ssFl = uint16(0)
			if cipher != 0 && dialect == 0x0311 {
				c2s, s2c := smb311EncryptionKeys(cipher, &userKey, &chPreauth)
				chm.Enc = &EncCtx{Cipher: cipher, C2S: c2s, S2C: s2c}
				if srv.cfg.Encrypt {
					chm.Encrypt = true
					ssFl |= sessionFlagEncryptData
				}
			}
			encState := "off"
			if chm.Enc != nil {
				encState = "ready"
			}
			signState := "optional"
			if signingRequired {
				signState = "required"
			}
			LogInfo("session %x: user %q authenticated (signing %s, encryption %s)", sid, userName, signState, encState)
			ssResp(tx, h, StatusSuccess, chain.Related, sid, ssFl, done)

		case verdictGuest:
			if srv.cfg.Encrypt {
				// Guest/anonymous sessions carry no key and cannot be
				// encrypted; refuse rather than let the client seal traffic the
				// server cannot decrypt.
				LogWarn("session %x: guest denied — encryption is required but guest sessions cannot be encrypted", sid)
				delete(pc.Channels, sid)
				srv.sessions.Remove(sid)
				errResp(tx, h, StatusAccessDenied, chain)
				return
			}
			sref.Lock()
			sref.Established = true
			sref.Guest = true
			sref.Channels = 1
			sref.Unlock()
			pc.Channel(sid).Established = true
			ssResp(tx, h, StatusSuccess, chain.Related, sid, sessionFlagIsGuest, done)

		default:
			user := ""
			if auth != nil {
				user = auth.User
			}
			LogWarn("session %x: logon failure for user %q", sid, user)
			delete(pc.Channels, sid)
			srv.sessions.Remove(sid)
			errResp(tx, h, StatusLogonFailure, chain)
		}

	default:
		// No NTLMSSP token at all (e.g. pure anonymous): guest if allowed.
		// Guest/anonymous sessions carry no key, so they cannot be encrypted —
		// if encryption is required, deny rather than let the client seal
		// traffic we cannot decrypt.
		switch {
		case srv.allowGuest && srv.cfg.Encrypt:
			LogWarn("anonymous session denied: encryption is required but guest sessions cannot be encrypted")
			errResp(tx, h, StatusAccessDenied, chain)
		case srv.allowGuest:
			sid, sref := srv.sessions.Create()
			sref.Lock()
			sref.Established = true
			sref.Guest = true
			sref.Channels = 1
			sref.Unlock()
			pc.Channels[sid] = &ChannelState{Established: true, Preauth: pc.PreauthNeg}
			chain.SessionID = sid
			ssResp(tx, h, StatusSuccess, chain.Related, sid, sessionFlagIsGuest, nil)
		default:
			errResp(tx, h, StatusLogonFailure, chain)
		}
	}
}

// parseSessionSetupReq re-reads the SESSION_SETUP header fields the mechanism
// handlers need: the flags byte, the client security mode, and the blob.
func parseSessionSetupReq(msg []byte) (ssFlags, secmode uint8, blob []byte, ok bool) {
	r := NewReader(msg[64:])
	if v, ok := r.U16(); !ok || v != 25 {
		return 0, 0, nil, false
	}
	ssFlags, ok = r.U8()
	if !ok {
		return 0, 0, nil, false
	}
	secmode, ok = r.U8()
	if !ok {
		return 0, 0, nil, false
	}
	if !r.Skip(4 + 4) { // capabilities, channel
		return 0, 0, nil, false
	}
	off, ok := r.U16()
	if !ok {
		return 0, 0, nil, false
	}
	length, ok := r.U16()
	if !ok {
		return 0, 0, nil, false
	}
	if _, ok := r.U64(); !ok { // previous session id
		return 0, 0, nil, false
	}
	if length == 0 {
		return ssFlags, secmode, []byte{}, true
	}
	blob, ok = sliceAt(msg, int(off), int(length))
	if !ok {
		return 0, 0, nil, false
	}
	return ssFlags, secmode, blob, true
}

// ------------------------------------------------------------- TREE_CONNECT

func treeConnect(srv *Srv, sess *Session, h *ReqHdr, msg []byte, chain *Chain, tx *Writer) {
	r := NewReader(msg[64:])
	if v, ok := r.U16(); !ok || v != 9 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if !r.Skip(2) {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	off, ok := r.U16()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	length, ok := r.U16()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	raw, ok := sliceAt(msg, int(off), int(length))
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	path := FromUTF16LE(raw)

	// "\\server\share" → "share"
	shareName := path[strings.LastIndex(path, `\`)+1:]
	ipc := strings.EqualFold(shareName, "IPC$")
	var shareIdx uint32
	if ipc {
		shareIdx = ^uint32(0)
	} else {
		found := false
		for i := range srv.cfg.Shares {
			if strings.EqualFold(srv.cfg.Shares[i].Name, shareName) {
				shareIdx = uint32(i)
				found = true
				break
			}
		}
		if !found {
			errResp(tx, h, StatusBadNetworkName, chain)
			return
		}
	}
	sess.NextTreeID++
	treeID := sess.NextTreeID
	sess.Trees[treeID] = Tree{ShareIdx: shareIdx, IPC: ipc}
	chain.TreeID = treeID

	beginResp(tx, h, StatusSuccess, chain.Related, treeID, chain.SessionID)
	tx.U16(16)
	if ipc {
		tx.U8(2) // ShareType: pipe
	} else {
		tx.U8(1) // ShareType: disk
	}
	tx.U8(0)
	tx.U32(0) // ShareFlags
	tx.U32(0) // Capabilities
	if ipc {
		tx.U32(0x001F_00A9)
	} else {
		tx.U32(maximalAccessAll)
	}
}

// ------------------------------------------------------------------- CREATE

// leaseReq is a parsed lease request from the RqLs create context (v1 = 32-byte
// data, v2 = 52-byte data, distinguished by the presence of the parent/epoch
// fields).
type leaseReq struct {
	Key    [16]byte
	State  uint32
	V2     bool
	Parent [16]byte
	Epoch  uint16
}

type createReq struct {
	Desired     uint32
	Disposition uint32
	Options     uint32
	Name        string
	// Oplock is the RequestedOplockLevel byte (OplockNone/LevelII/Exclusive/
	// Batch, or OplockLease when a lease is requested via the RqLs context).
	Oplock uint8
	// Lease is the parsed RqLs lease request, if present.
	Lease *leaseReq
}

func parseCreateReq(msg []byte) (*createReq, bool) {
	body, ok := sliceAt(msg, 64, len(msg)-64)
	if !ok {
		return nil, false
	}
	r := NewReader(body)
	if v, ok := r.U16(); !ok || v != 57 {
		return nil, false
	}
	if !r.Skip(1) { // SecurityFlags
		return nil, false
	}
	oplock, ok := r.U8() // RequestedOplockLevel
	if !ok {
		return nil, false
	}
	if !r.Skip(4 + 8 + 8) { // ImpersonationLevel, SmbCreateFlags, Reserved
		return nil, false
	}
	desired, ok := r.U32()
	if !ok {
		return nil, false
	}
	if _, ok := r.U32(); !ok { // FileAttributes
		return nil, false
	}
	if _, ok := r.U32(); !ok { // ShareAccess
		return nil, false
	}
	disposition, ok := r.U32()
	if !ok {
		return nil, false
	}
	options, ok := r.U32()
	if !ok {
		return nil, false
	}
	nameOff, ok := r.U16()
	if !ok {
		return nil, false
	}
	nameLen, ok := r.U16()
	if !ok {
		return nil, false
	}
	ccOff, ok := r.U32() // CreateContextsOffset (from header start)
	if !ok {
		return nil, false
	}
	ccLen, ok := r.U32() // CreateContextsLength
	if !ok {
		return nil, false
	}
	name := ""
	if nameLen != 0 {
		raw, ok := sliceAt(msg, int(nameOff), int(nameLen))
		if !ok {
			return nil, false
		}
		name = FromUTF16LE(raw)
	}
	var lease *leaseReq
	if ccLen > 0 {
		ctx, ok := sliceAt(msg, int(ccOff), int(ccLen))
		if !ok {
			return nil, false
		}
		lease, _ = parseLeaseCtx(ctx)
	}
	return &createReq{
		Desired:     desired,
		Disposition: disposition,
		Options:     options,
		Name:        name,
		Oplock:      oplock,
		Lease:       lease,
	}, true
}

// parseLeaseCtx walks the chained SMB2_CREATE_CONTEXT list and returns the
// parsed RqLs lease request if one is present.
func parseLeaseCtx(buf []byte) (*leaseReq, bool) {
	for {
		if len(buf) < 16 {
			return nil, false
		}
		next := int(le32(buf[0:4]))
		nameOff := int(le16(buf[4:6]))
		nameLen := int(le16(buf[6:8]))
		dataOff := int(le16(buf[10:12]))
		dataLen := int(le32(buf[12:16]))
		if nameLen == 4 {
			nm, ok1 := sliceAt(buf, nameOff, 4)
			data, ok2 := sliceAt(buf, dataOff, dataLen)
			if ok1 && ok2 && bytesEqual(nm, CtxNameRQLS) && len(data) >= 32 {
				var lr leaseReq
				copy(lr.Key[:], data[0:16])
				lr.State = le32(data[16:20])
				lr.V2 = len(data) >= 52
				if lr.V2 {
					copy(lr.Parent[:], data[32:48])
					lr.Epoch = le16(data[48:50])
				}
				return &lr, true
			}
		}
		if next == 0 || next >= len(buf) {
			return nil, false
		}
		buf = buf[next:]
	}
}

func create(
	srv *Srv,
	sess *Session,
	h *ReqHdr,
	msg []byte,
	chain *Chain,
	tx *Writer,
	share *ShareCfg,
	shareIdx uint32,
	cid connID,
	allowOplock bool,
) {
	req, ok := parseCreateReq(msg)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	path, rel, st := resolvePath(share.Path, req.Name)
	if st != StatusSuccess {
		errResp(tx, h, st, chain)
		return
	}

	wantsWrite := req.Desired&writeBits != 0
	creates := req.Disposition == fileSupersede || req.Disposition == fileCreate ||
		req.Disposition == fileOverwrite || req.Disposition == fileOverwriteIf
	deleteOnClose := req.Options&fileDeleteOnClose != 0
	if share.ReadOnly && (wantsWrite || creates || deleteOnClose) {
		errResp(tx, h, StatusAccessDenied, chain)
		return
	}

	existingMeta, existingErr := statMeta(path)
	exists := existingErr == nil
	existingDir := exists && existingMeta.IsDir

	if exists && req.Disposition == fileCreate {
		errResp(tx, h, StatusObjectNameCollision, chain)
		return
	}
	if !exists && (req.Disposition == fileOpen || req.Disposition == fileOverwrite) {
		errResp(tx, h, StatusObjectNameNotFound, chain)
		return
	}

	dirRequested := req.Options&fileDirectoryFile != 0
	treatAsDir := existingDir || (dirRequested && !exists)

	if existingDir && req.Options&fileNonDirectoryFile != 0 {
		errResp(tx, h, StatusFileIsADirectory, chain)
		return
	}
	if exists && !existingDir && dirRequested {
		errResp(tx, h, StatusNotADirectory, chain)
		return
	}

	action := createActionOpened
	var (
		f        *os.File
		isDir    bool
		writable bool
		err      error
	)
	if treatAsDir {
		if !exists {
			if err := os.Mkdir(path, 0o755); err != nil {
				errResp(tx, h, statusFromErr(err), chain)
				return
			}
			action = createActionCreated
		}
		f, err = openRaw(path, os.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			errResp(tx, h, statusFromErr(err), chain)
			return
		}
		isDir, writable = true, false
	} else {
		var flags int
		switch req.Disposition {
		case fileCreate:
			flags = os.O_CREATE | os.O_EXCL
		case fileOpenIf:
			flags = os.O_CREATE
		case fileOverwrite:
			flags = os.O_TRUNC
		case fileOverwriteIf, fileSupersede:
			flags = os.O_CREATE | os.O_TRUNC
		}
		tryRW := wantsWrite || (req.Desired&maximumAllowed != 0 && !share.ReadOnly) || creates
		if tryRW {
			flags |= os.O_RDWR
		} else {
			flags |= os.O_RDONLY
		}
		f, err = openRaw(path, flags, 0o644)
		switch {
		case err == nil:
			if !exists {
				action = createActionCreated
			} else if flags&os.O_TRUNC != 0 {
				action = createActionOverwritten
			}
			isDir, writable = false, tryRW
		case errnoOf(err) == unix.EACCES && tryRW && !wantsWrite:
			// MAXIMUM_ALLOWED fallback: retry read-only.
			f, err = openRaw(path, (flags&^os.O_RDWR)|os.O_RDONLY, 0)
			if err != nil {
				errResp(tx, h, statusFromErr(err), chain)
				return
			}
			isDir, writable = false, false
		default:
			errResp(tx, h, statusFromErr(err), chain)
			return
		}
	}

	meta, err := fstatMeta(f)
	if err != nil {
		f.Close()
		errResp(tx, h, statusFromErr(err), chain)
		return
	}
	// Prefetch hint for streamed file reads (helps cold-storage throughput).
	if !isDir {
		adviseSequential(f)
	}
	leaf := rel[strings.LastIndex(rel, `\`)+1:]
	attrs := finalizeAttrs(meta.Attrs, leaf)

	// Grant a read-caching lease when the client requests one (RqLs) on a file.
	// Read-caching is the safe subset: distinct lease keys coexist, there is no
	// dirty client data, and a conflicting write breaks it to none. The client's
	// lease key is recorded on the handle regardless, so a WRITE can exempt the
	// client's own lease.
	lr := req.Lease
	grantLease := srv.cfg.Oplocks && allowOplock && !isDir &&
		lr != nil && lr.State&LeaseReadCaching != 0
	// Grant read-caching, plus handle-caching if the client asked for it — that
	// lets the client keep its lease (and cache) across CLOSE, avoiding
	// re-opens. Never write-caching (dirty client data needs break-with-ack).
	grantedState := uint32(0)
	if grantLease {
		grantedState = LeaseReadCaching | (lr.State & LeaseHandleCaching)
	}
	of := &OpenFile{
		File:          f,
		Path:          path,
		Rel:           rel,
		Leaf:          leaf,
		ShareIdx:      shareIdx,
		IsDir:         isDir,
		Writable:      writable,
		DeleteOnClose: deleteOnClose,
		LeaseGranted:  grantedState,
	}
	if grantLease {
		of.HasLease = true
		of.LeaseIno = meta.Ino
		key := lr.Key
		of.LeaseKey = &key
	}
	fid := sess.Handles.Insert(of)
	chain.LastFID = &fid
	if grantLease {
		srv.leases.Grant(fileKey{ShareIdx: shareIdx, Ino: meta.Ino}, LeaseGrant{
			LeaseKey:  lr.Key,
			State:     grantedState,
			Epoch:     lr.Epoch,
			SessionID: chain.SessionID,
			Wid:       cid.Wid,
			ConnIdx:   cid.Idx,
			ConnGen:   cid.Gen,
		})
		LogDebug("lease: granted %#x (share %d, ino %d)", grantedState, shareIdx, meta.Ino)
	}

	beginResp(tx, h, StatusSuccess, chain.Related, chain.TreeID, chain.SessionID)
	tx.U16(89)
	if grantLease {
		tx.U8(OplockLease) // OplockLevel
	} else {
		tx.U8(OplockNone)
	}
	tx.U8(0)
	tx.U32(action)
	tx.U64(meta.Crtime)
	tx.U64(meta.Atime)
	tx.U64(meta.Mtime)
	tx.U64(meta.Ctime)
	tx.U64(meta.Alloc)
	tx.U64(meta.Size)
	tx.U32(attrs)
	tx.U32(0)
	putFID(tx, fid)
	if grantLease {
		// Echo an RqLs response context with the granted lease state. The context
		// list begins at a fixed offset from the SMB2 header (64-byte header +
		// 88-byte fixed CREATE response = 152), 8-byte aligned.
		dataLen := uint32(32)
		if lr.V2 {
			dataLen = 52
		}
		tx.U32(152)            // CreateContextsOffset (from the SMB2 header)
		tx.U32(24 + dataLen)   // CreateContextsLength (16 hdr + 4 name + 4 pad + data)
		tx.U32(0)              // Next
		tx.U16(16)             // NameOffset
		tx.U16(4)              // NameLength
		tx.U16(0)              // Reserved
		tx.U16(24)             // DataOffset
		tx.U32(dataLen)        // DataLength
		tx.Bytes8(CtxNameRQLS) // "RqLs" at offset 16
		tx.Zeros(4)            // pad → data 8-aligned at offset 24
		tx.Bytes8(lr.Key[:])
		tx.U32(grantedState) // LeaseState
		tx.U32(0)            // LeaseFlags
		tx.U64(0)            // LeaseDuration
		if lr.V2 {
			tx.Bytes8(lr.Parent[:]) // ParentLeaseKey
			tx.U16(lr.Epoch)        // Epoch
			tx.U16(0)               // Reserved
		}
	} else {
		tx.U32(0) // CreateContextsOffset
		tx.U32(0) // CreateContextsLength
	}
}

// -------------------------------------------------------------------- CLOSE

func closeHandle(srv *Srv, pc *ProtoConn, sess *Session, h *ReqHdr, body []byte, chain *Chain, tx *Writer) {
	r := NewReader(body)
	if v, ok := r.U16(); !ok || v != 24 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	flags, ok := r.U16()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if !r.Skip(4) {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	fid, ok := parseFID(r, chain)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	of, ok := sess.Handles.Remove(fid)
	if !ok {
		errResp(tx, h, StatusFileClosed, chain)
		return
	}
	defer of.close()

	// Release the lease this handle held — unless handle-caching was granted.
	// With H caching the lease (and the client's cache) persists past CLOSE; it
	// is broken on a later conflicting access or released on connection
	// teardown. Without H, drop it now.
	if of.HasLease && of.LeaseKey != nil {
		if of.LeaseGranted&LeaseHandleCaching == 0 {
			srv.leases.Release(fileKey{ShareIdx: of.ShareIdx, Ino: of.LeaseIno}, *of.LeaseKey)
		}
	}
	// Complete any CHANGE_NOTIFY pended on this handle.
	kept := pc.NotifyActive[:0]
	for _, e := range pc.NotifyActive {
		if e[0] == fid {
			pc.NotifyDone = append(pc.NotifyDone, NotifyDone{AsyncID: e[1], Status: StatusNotifyCleanup})
		} else {
			kept = append(kept, e)
		}
	}
	pc.NotifyActive = kept

	postAttrib := flags&0x1 != 0
	var meta *Meta
	if postAttrib {
		if m, err := fstatMeta(of.File); err == nil {
			meta = &m
		}
	}

	if of.DeleteOnClose {
		if err := os.Remove(of.Path); err != nil {
			errResp(tx, h, statusFromErr(err), chain)
			return
		}
	}

	beginResp(tx, h, StatusSuccess, chain.Related, chain.TreeID, chain.SessionID)
	tx.U16(60)
	if postAttrib {
		tx.U16(1)
	} else {
		tx.U16(0)
	}
	tx.U32(0)
	if meta != nil {
		tx.U64(meta.Crtime)
		tx.U64(meta.Atime)
		tx.U64(meta.Mtime)
		tx.U64(meta.Ctime)
		tx.U64(meta.Alloc)
		tx.U64(meta.Size)
		tx.U32(finalizeAttrs(meta.Attrs, of.Leaf))
	} else {
		tx.Zeros(52)
	}
}

func flush(sess *Session, h *ReqHdr, body []byte, chain *Chain, tx *Writer) {
	r := NewReader(body)
	if v, ok := r.U16(); !ok || v != 24 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if !r.Skip(6) { // reserved + FileId; parseFID re-reads from the same cursor
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	fid, ok := parseFID(r, chain)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	of, ok := sess.Handles.Get(fid)
	if !ok {
		errResp(tx, h, StatusFileClosed, chain)
		return
	}
	if err := of.File.Sync(); err != nil {
		errResp(tx, h, statusFromErr(err), chain)
		return
	}
	simpleResp(tx, h, chain)
}

// --------------------------------------------------------------------- READ

func read(pc *ProtoConn, sess *Session, h *ReqHdr, body []byte, chain *Chain, tx *Writer) *ZcReadPlan {
	r := NewReader(body)
	if v, ok := r.U16(); !ok || v != 49 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return nil
	}
	if !r.Skip(2) { // padding, flags
		errResp(tx, h, StatusInvalidParameter, chain)
		return nil
	}
	length, ok := r.U32()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return nil
	}
	offset, ok := r.U64()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return nil
	}
	fid, ok := parseFID(r, chain)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return nil
	}
	minCount, ok := r.U32()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return nil
	}
	maxRead := pc.MaxRead
	// A signed or encrypted response covers the payload, which rules out
	// splicing straight from the file; those channels take the buffered path.
	// This is per channel.
	mustSign := false
	if ch := pc.Channel(chain.SessionID); ch != nil {
		mustSign = ch.Encrypt || (ch.Sign != nil && (ch.SigningRequired || h.Flags&FlagSigned != 0))
	}

	// Hold the session lock only long enough to validate the handle. All file
	// I/O then runs without it, so reads on different channels of the same
	// session run in parallel instead of serializing.
	sess.Lock()
	of, ok := sess.Handles.Get(fid)
	if !ok {
		sess.Unlock()
		errResp(tx, h, StatusFileClosed, chain)
		return nil
	}
	if of.IsDir {
		sess.Unlock()
		errResp(tx, h, StatusInvalidDeviceRequest, chain)
		return nil
	}
	f := of.File
	sess.Unlock()

	length = min(length, maxRead)

	// Standalone large unsigned reads take the zero-copy path.
	if chain.Single && length >= ZcMinRead && !mustSign {
		// A full read (offset+length within the file) can never hit EOF, so the
		// transport can emit header and payload without first learning the
		// count.
		linked := false
		if m, err := fstatMeta(f); err == nil {
			end, overflow := addU64(offset, uint64(length))
			linked = !overflow && end <= m.Size
		}
		return &ZcReadPlan{
			File:         f,
			Offset:       offset,
			Length:       length,
			MinCount:     minCount,
			MsgID:        h.MsgID,
			CreditCharge: h.CreditCharge,
			Credits:      h.Credits,
			TreeID:       chain.TreeID,
			SessionID:    chain.SessionID,
			Linked:       linked,
		}
	}

	// Buffered path (small reads, compounds, signed, encrypted).
	buf := make([]byte, length)
	n, err := pread(f, buf, int64(offset))
	switch {
	case err != nil:
		errResp(tx, h, statusFromErr(err), chain)
	case n == 0 && length > 0:
		errResp(tx, h, StatusEndOfFile, chain)
	case uint32(n) < minCount:
		errResp(tx, h, StatusEndOfFile, chain)
	default:
		beginResp(tx, h, StatusSuccess, chain.Related, chain.TreeID, chain.SessionID)
		tx.U16(17)
		tx.U8(80)
		tx.U8(0)
		tx.U32(uint32(n))
		tx.U32(0)
		tx.U32(0)
		tx.Bytes8(buf[:n])
	}
	return nil
}

// -------------------------------------------------------------------- WRITE

func write(srv *Srv, sess *Session, h *ReqHdr, msg []byte, chain *Chain, tx *Writer, share *ShareCfg, shareIdx uint32) {
	r := NewReader(msg[64:])
	if v, ok := r.U16(); !ok || v != 49 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	dataOff, ok := r.U16()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	length, ok := r.U32()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	offset, ok := r.U64()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	fid, ok := parseFID(r, chain)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	data, ok := sliceAt(msg, int(dataOff), int(length))
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if share.ReadOnly {
		errResp(tx, h, StatusAccessDenied, chain)
		return
	}
	of, ok := sess.Handles.Get(fid)
	if !ok {
		errResp(tx, h, StatusFileClosed, chain)
		return
	}
	if !of.Writable {
		errResp(tx, h, StatusAccessDenied, chain)
		return
	}
	writerKey := of.LeaseKey
	var ino uint64
	hasIno := false
	if m, err := fstatMeta(of.File); err == nil {
		ino = m.Ino
		hasIno = true
	}
	if err := pwriteAll(of.File, data, int64(offset)); err != nil {
		errResp(tx, h, statusFromErr(err), chain)
		return
	}
	// Break read-caching leases held by *other* clients (different lease key)
	// after the data is written, so a broken holder's re-read sees the final
	// content rather than racing a mid-write partial. The write handle's own
	// lease key is exempt; read → none needs no acknowledgement.
	if hasIno {
		for _, b := range srv.leases.BreakConflicts(fileKey{ShareIdx: shareIdx, Ino: ino}, writerKey) {
			if b.Wid >= 0 && b.Wid < len(srv.mailboxes) {
				srv.mailboxes[b.Wid].Post(b)
			}
		}
	}
	beginResp(tx, h, StatusSuccess, chain.Related, chain.TreeID, chain.SessionID)
	tx.U16(17)
	tx.U16(0)
	tx.U32(uint32(len(data)))
	tx.U32(0) // Remaining
	tx.U16(0)
	tx.U16(0)
}

// ---------------------------------------------------------- QUERY_DIRECTORY

const (
	qdRestartScans uint8 = 0x01
	qdReturnSingle uint8 = 0x02
	qdReopen       uint8 = 0x10
)

func queryDirectory(sess *Session, h *ReqHdr, msg []byte, chain *Chain, tx *Writer) {
	r := NewReader(msg[64:])
	if v, ok := r.U16(); !ok || v != 33 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	class, ok := r.U8()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	flags, ok := r.U8()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if _, ok := r.U32(); !ok { // FileIndex
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	fid, ok := parseFID(r, chain)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	nameOff, ok := r.U16()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	nameLen, ok := r.U16()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	outLen, ok := r.U32()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	pattern := ""
	if nameLen != 0 {
		raw, ok := sliceAt(msg, int(nameOff), int(nameLen))
		if !ok {
			errResp(tx, h, StatusInvalidParameter, chain)
			return
		}
		pattern = FromUTF16LE(raw)
	}

	of, ok := sess.Handles.Get(fid)
	if !ok {
		errResp(tx, h, StatusFileClosed, chain)
		return
	}
	if !of.IsDir {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}

	restart := flags&(qdRestartScans|qdReopen) != 0
	needNew := of.Dir == nil || restart || of.Dir.Pattern != pattern
	if needNew {
		entries, err := dirSnapshot(of, pattern)
		if err != nil {
			errResp(tx, h, statusFromErr(err), chain)
			return
		}
		of.Dir = &DirState{Entries: entries, Pattern: pattern}
	}
	dstate := of.Dir
	if dstate.Pos >= len(dstate.Entries) {
		if len(dstate.Entries) == 0 {
			errResp(tx, h, StatusNoSuchFile, chain)
		} else {
			errResp(tx, h, StatusNoMoreFiles, chain)
		}
		return
	}

	limit := int(min(outLen, MaxTransact))
	data := NewWriter(min(limit, 64*1024))
	lastEntryStart := 0
	emitted := 0
	for dstate.Pos < len(dstate.Entries) {
		e := &dstate.Entries[dstate.Pos]
		entry := NewWriter(128 + len(e.Name)*2)
		if !putDirEntry(entry, class, e) {
			errResp(tx, h, StatusInvalidParameter, chain)
			return
		}
		// Align to 8 and stamp NextEntryOffset (rewritten to 0 on the last).
		for entry.Len()%8 != 0 {
			entry.U8(0)
		}
		entry.Patch32(0, uint32(entry.Len()))
		if data.Len()+entry.Len() > limit {
			break
		}
		lastEntryStart = data.Len()
		data.Bytes8(entry.Bytes())
		dstate.Pos++
		emitted++
		if flags&qdReturnSingle != 0 {
			break
		}
	}
	if emitted == 0 {
		// The first entry alone does not fit the client buffer.
		errResp(tx, h, StatusBufferTooSmall, chain)
		return
	}
	data.Patch32(lastEntryStart, 0)

	beginResp(tx, h, StatusSuccess, chain.Related, chain.TreeID, chain.SessionID)
	tx.U16(9)
	tx.U16(72)
	tx.U32(uint32(data.Len()))
	tx.Bytes8(data.Bytes())
}

// File information classes (query directory + query info).
const (
	fileDirectoryInformation       uint8 = 1
	fileFullDirectoryInformation   uint8 = 2
	fileBothDirectoryInformation   uint8 = 3
	fileNameInformation            uint8 = 12
	fileIDBothDirectoryInformation uint8 = 37
	fileIDFullDirectoryInformation uint8 = 38
)

func putDirEntry(b *Writer, class uint8, e *DirEnt) bool {
	name := UTF16LE(e.Name)
	m := &e.Meta
	b.U32(0) // NextEntryOffset, patched by the caller
	b.U32(0) // FileIndex
	if class == fileNameInformation {
		b.U32(uint32(len(name)))
		b.Bytes8(name)
		return true
	}
	b.U64(m.Crtime)
	b.U64(m.Atime)
	b.U64(m.Mtime)
	b.U64(m.Ctime)
	b.U64(m.Size)
	b.U64(m.Alloc)
	b.U32(m.Attrs)
	b.U32(uint32(len(name)))
	switch class {
	case fileDirectoryInformation:
	case fileFullDirectoryInformation:
		b.U32(0) // EaSize
	case fileBothDirectoryInformation:
		b.U32(0) // EaSize
		b.U8(0)  // ShortNameLength
		b.U8(0)
		b.Zeros(24) // ShortName
	case fileIDBothDirectoryInformation:
		b.U32(0)
		b.U8(0)
		b.U8(0)
		b.Zeros(24)
		b.U16(0) // Reserved2
		b.U64(m.Ino)
	case fileIDFullDirectoryInformation:
		b.U32(0) // EaSize
		b.U32(0) // Reserved
		b.U64(m.Ino)
	default:
		return false
	}
	b.Bytes8(name)
	return true
}

// --------------------------------------------------------------- QUERY_INFO

const (
	infoFile       uint8 = 1
	infoFilesystem uint8 = 2
	infoSecurity   uint8 = 3
)

func queryInfo(srv *Srv, sess *Session, h *ReqHdr, body []byte, chain *Chain, tx *Writer) {
	r := NewReader(body)
	if v, ok := r.U16(); !ok || v != 41 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	infoType, ok := r.U8()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	class, ok := r.U8()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	outLen, ok := r.U32()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if !r.Skip(2 + 2 + 4 + 4 + 4) { // in offset, reserved, in len, addl info, flags
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	fid, ok := parseFID(r, chain)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	of, ok := sess.Handles.Get(fid)
	if !ok {
		errResp(tx, h, StatusFileClosed, chain)
		return
	}

	data := NewWriter(256)
	var st uint32
	switch infoType {
	case infoFile:
		st = fileInfo(of, class, data)
	case infoFilesystem:
		st = fsInfo(srv, of, class, data)
	case infoSecurity:
		securityDescriptor(data)
		st = StatusSuccess
	default:
		st = StatusNotSupported
	}
	if st != StatusSuccess {
		LogDebug("QUERY_INFO unsupported: info_type=%d class=%d -> %#x", infoType, class, st)
		errResp(tx, h, st, chain)
		return
	}
	finalSt := uint32(StatusSuccess)
	if data.Len() > int(outLen) {
		data.Truncate(int(outLen))
		finalSt = StatusBufferOverflow
	}
	beginResp(tx, h, finalSt, chain.Related, chain.TreeID, chain.SessionID)
	tx.U16(9)
	tx.U16(72)
	tx.U32(uint32(data.Len()))
	tx.Bytes8(data.Bytes())
}

func putBasicInfo(b *Writer, m *Meta, attrs uint32) {
	b.U64(m.Crtime)
	b.U64(m.Atime)
	b.U64(m.Mtime)
	b.U64(m.Ctime)
	b.U32(attrs)
	b.U32(0)
}

func putStandardInfo(b *Writer, m *Meta, deletePending bool) {
	b.U64(m.Alloc)
	b.U64(m.Size)
	b.U32(m.Nlink)
	if deletePending {
		b.U8(1)
	} else {
		b.U8(0)
	}
	if m.IsDir {
		b.U8(1)
	} else {
		b.U8(0)
	}
	b.U16(0)
}

func fileInfo(of *OpenFile, class uint8, b *Writer) uint32 {
	m, err := fstatMeta(of.File)
	if err != nil {
		return statusFromErr(err)
	}
	attrs := finalizeAttrs(m.Attrs, of.Leaf)
	switch class {
	case 4: // FileBasicInformation
		putBasicInfo(b, &m, attrs)
	case 5: // FileStandardInformation
		putStandardInfo(b, &m, of.DeleteOnClose)
	case 6: // FileInternalInformation
		b.U64(m.Ino)
	case 7: // FileEaInformation
		b.U32(0)
	case 8: // FileAccessInformation
		b.U32(maximalAccessAll)
	case 9: // FileNameInformation
		name := UTF16LE(`\` + of.Rel)
		b.U32(uint32(len(name)))
		b.Bytes8(name)
	case 14: // FilePositionInformation
		b.U64(0)
	case 16: // FileModeInformation
		b.U32(0)
	case 17: // FileAlignmentInformation
		b.U32(0)
	case 18: // FileAllInformation
		putBasicInfo(b, &m, attrs)
		putStandardInfo(b, &m, of.DeleteOnClose)
		b.U64(m.Ino)
		b.U32(0) // Ea
		b.U32(maximalAccessAll)
		b.U64(0) // Position
		b.U32(0) // Mode
		b.U32(0) // Alignment
		name := UTF16LE(`\` + of.Rel)
		b.U32(uint32(len(name)))
		b.Bytes8(name)
	case 34: // FileNetworkOpenInformation
		b.U64(m.Crtime)
		b.U64(m.Atime)
		b.U64(m.Mtime)
		b.U64(m.Ctime)
		b.U64(m.Alloc)
		b.U64(m.Size)
		b.U32(attrs)
		b.U32(0)
	case 35: // FileAttributeTagInformation
		b.U32(attrs)
		b.U32(0)
	case 22: // FileStreamInformation
		// A regular file has one data stream (the default ::$DATA); a directory
		// has none. .NET's FileStream queries this on open, so returning
		// NOT_SUPPORTED breaks it.
		if !m.IsDir {
			name := UTF16LE("::$DATA")
			b.U32(0) // NextEntryOffset (single entry)
			b.U32(uint32(len(name)))
			b.U64(m.Size)  // StreamSize
			b.U64(m.Alloc) // StreamAllocationSize
			b.Bytes8(name)
		}
		// directory → zero entries (empty buffer, SUCCESS)
	default:
		return StatusNotSupported
	}
	return StatusSuccess
}

// securityDescriptor writes a minimal self-relative SECURITY_DESCRIPTOR:
// owner/group = BUILTIN\Administrators (S-1-5-32-544) and a DACL granting
// Everyone (S-1-1-0) full access. ACLs are not enforced, but Windows and .NET
// query the descriptor on open and choke on an error reply, so a permissive one
// is synthesized.
func securityDescriptor(b *Writer) {
	// SID S-1-5-32-544 (Administrators), 16 bytes.
	admins := [16]byte{
		1, 2, 0, 0, 0, 0, 0, 5, // revision 1, 2 subauthorities, identifier authority 5
		32, 0, 0, 0, // 0x20
		32, 2, 0, 0, // 0x220 = 544
	}
	// SID S-1-1-0 (Everyone), 12 bytes.
	everyone := [12]byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}

	// Layout: header(20) | DACL(28) | owner(16) | group(16) = 80 bytes.
	const (
		offDACL  = 20
		offOwner = 48
		offGroup = 64
	)
	// Header (self-relative).
	b.U8(1)       // Revision
	b.U8(0)       // Sbz1
	b.U16(0x8004) // Control: SE_DACL_PRESENT | SE_SELF_RELATIVE
	b.U32(offOwner)
	b.U32(offGroup)
	b.U32(0) // OffsetSacl
	b.U32(offDACL)
	// DACL: ACL header(8) + one ACCESS_ALLOWED_ACE(8 + 12-byte SID = 20) = 28.
	b.U8(2)   // AclRevision
	b.U8(0)   // Sbz1
	b.U16(28) // AclSize
	b.U16(1)  // AceCount
	b.U16(0)  // Sbz2
	// ACE
	b.U8(0)            // ACCESS_ALLOWED_ACE_TYPE
	b.U8(0)            // AceFlags
	b.U16(20)          // AceSize (8 + 12)
	b.U32(0x001F_01FF) // FILE_ALL_ACCESS
	b.Bytes8(everyone[:])
	// Owner + Group SIDs
	b.Bytes8(admins[:])
	b.Bytes8(admins[:])
}

func fsInfo(srv *Srv, of *OpenFile, class uint8, b *Writer) uint32 {
	switch class {
	case 1: // FileFsVolumeInformation
		label := UTF16LE(srv.cfg.Shares[of.ShareIdx].Name)
		b.U64(srv.startFT)
		b.U32(0x52_4B54) // serial "RKT"
		b.U32(uint32(len(label)))
		b.U8(0) // SupportsObjects
		b.U8(0)
		b.Bytes8(label)
	case 3: // FileFsSizeInformation
		total, avail, _, spu, bps, err := fsSizes(of.File)
		if err != nil {
			return statusFromErr(err)
		}
		b.U64(total)
		b.U64(avail)
		b.U32(spu)
		b.U32(bps)
	case 4: // FileFsDeviceInformation
		b.U32(7)    // FILE_DEVICE_DISK
		b.U32(0x20) // FILE_DEVICE_IS_MOUNTED
	case 5: // FileFsAttributeInformation
		name := UTF16LE("NTFS")
		b.U32(0x47) // case-sensitive | case-preserved | unicode | sparse
		b.U32(255)
		b.U32(uint32(len(name)))
		b.Bytes8(name)
	case 7: // FileFsFullSizeInformation
		total, avail, free, spu, bps, err := fsSizes(of.File)
		if err != nil {
			return statusFromErr(err)
		}
		b.U64(total)
		b.U64(avail)
		b.U64(free)
		b.U32(spu)
		b.U32(bps)
	default:
		return StatusNotSupported
	}
	return StatusSuccess
}

// ----------------------------------------------------------------- SET_INFO

func setInfo(sess *Session, h *ReqHdr, msg []byte, chain *Chain, tx *Writer, share *ShareCfg) {
	r := NewReader(msg[64:])
	if v, ok := r.U16(); !ok || v != 33 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	infoType, ok := r.U8()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	class, ok := r.U8()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	bufLen, ok := r.U32()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	bufOff, ok := r.U16()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if !r.Skip(2 + 4) { // reserved, additional information
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	fid, ok := parseFID(r, chain)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	data, ok := sliceAt(msg, int(bufOff), int(bufLen))
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if infoType != infoFile {
		errResp(tx, h, StatusNotSupported, chain)
		return
	}
	if share.ReadOnly {
		errResp(tx, h, StatusAccessDenied, chain)
		return
	}
	shareRoot := share.Path
	of, ok := sess.Handles.Get(fid)
	if !ok {
		errResp(tx, h, StatusFileClosed, chain)
		return
	}

	var st uint32
	switch class {
	case 4:
		st = setBasicInfo(of, data)
	case 13:
		st = setDisposition(of, data)
	case 10:
		st = setRename(of, data, shareRoot)
	case 19:
		st = StatusSuccess // FileAllocationInformation: best-effort no-op
	case 20: // FileEndOfFileInformation
		r := NewReader(data)
		if length, ok := r.U64(); ok {
			if err := of.File.Truncate(int64(length)); err != nil {
				st = statusFromErr(err)
			} else {
				st = StatusSuccess
			}
		} else {
			st = StatusInvalidParameter
		}
	default:
		st = StatusNotSupported
	}
	if st != StatusSuccess {
		errResp(tx, h, st, chain)
		return
	}
	beginResp(tx, h, StatusSuccess, chain.Related, chain.TreeID, chain.SessionID)
	tx.U16(2)
}

func setBasicInfo(of *OpenFile, data []byte) uint32 {
	r := NewReader(data)
	if _, ok := r.U64(); !ok { // creation time
		return StatusInvalidParameter
	}
	at, ok := r.U64()
	if !ok {
		return StatusInvalidParameter
	}
	mt, ok := r.U64()
	if !ok {
		return StatusInvalidParameter
	}
	if _, ok := r.U64(); !ok { // change time
		return StatusInvalidParameter
	}
	if _, ok := r.U32(); !ok { // attributes
		return StatusInvalidParameter
	}
	times := [2]unix.Timespec{filetimeToTimespec(at), filetimeToTimespec(mt)}
	if err := unix.UtimesNanoAt(int(of.File.Fd()), "", times[:], unix.AT_EMPTY_PATH); err != nil {
		// Attribute-only updates (archive bit and friends) succeed as a no-op.
		e := errnoOf(err)
		if e != unix.EACCES && e != unix.EPERM {
			return StatusFromErrno(e)
		}
	}
	return StatusSuccess
}

// filetimeToTimespec converts a Windows FILETIME to a timespec, using
// UTIME_OMIT for the 0 / all-ones sentinels that mean "leave unchanged".
func filetimeToTimespec(ft uint64) unix.Timespec {
	if ft == 0 || ft == ^uint64(0) {
		return unix.Timespec{Sec: 0, Nsec: unix.UTIME_OMIT}
	}
	unix100 := int64(ft) - epochDeltaSecs*10_000_000
	return unix.Timespec{Sec: unix100 / 10_000_000, Nsec: (unix100 % 10_000_000) * 100}
}

func setDisposition(of *OpenFile, data []byte) uint32 {
	if len(data) == 0 {
		return StatusInvalidParameter
	}
	flag := data[0]
	if flag != 0 && of.IsDir {
		// Windows semantics: refuse to mark a non-empty directory.
		ents, err := os.ReadDir(of.Path)
		if err != nil {
			return statusFromErr(err)
		}
		if len(ents) > 0 {
			return StatusDirectoryNotEmpty
		}
	}
	of.DeleteOnClose = flag != 0
	return StatusSuccess
}

func setRename(of *OpenFile, data []byte, shareRoot string) uint32 {
	r := NewReader(data)
	rawReplace, ok := r.U8()
	if !ok {
		return StatusInvalidParameter
	}
	replace := rawReplace != 0
	if !r.Skip(7 + 8) { // reserved, RootDirectory
		return StatusInvalidParameter
	}
	nameLen, ok := r.U32()
	if !ok {
		return StatusInvalidParameter
	}
	raw, ok := r.Take(int(nameLen))
	if !ok {
		return StatusInvalidParameter
	}
	name := FromUTF16LE(raw)

	newPath, newRel, st := resolvePath(shareRoot, name)
	if st != StatusSuccess {
		return st
	}
	if !replace {
		if _, err := os.Stat(newPath); err == nil {
			return StatusObjectNameCollision
		}
	}
	if err := os.Rename(of.Path, newPath); err != nil {
		return statusFromErr(err)
	}
	of.Leaf = newRel[strings.LastIndex(newRel, `\`)+1:]
	of.Path = newPath
	of.Rel = newRel
	return StatusSuccess
}

// --------------------------------------------------------------------- LOCK

const (
	lockFlagShared    uint32 = 0x1
	lockFlagExclusive uint32 = 0x2
	lockFlagUnlock    uint32 = 0x4
)

func lockRange(sess *Session, h *ReqHdr, body []byte, chain *Chain, tx *Writer) {
	r := NewReader(body)
	if v, ok := r.U16(); !ok || v != 48 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	count, ok := r.U16()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if !r.Skip(4) { // lock sequence
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	fid, ok := parseFID(r, chain)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if count == 0 || count > 64 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	type lockElem struct {
		off, length uint64
		flags       uint32
	}
	elems := make([]lockElem, 0, count)
	for range count {
		off, ok := r.U64()
		if !ok {
			errResp(tx, h, StatusInvalidParameter, chain)
			return
		}
		length, ok := r.U64()
		if !ok {
			errResp(tx, h, StatusInvalidParameter, chain)
			return
		}
		flags, ok := r.U32()
		if !ok {
			errResp(tx, h, StatusInvalidParameter, chain)
			return
		}
		if !r.Skip(4) {
			errResp(tx, h, StatusInvalidParameter, chain)
			return
		}
		elems = append(elems, lockElem{off, length, flags})
	}
	of, ok := sess.Handles.Get(fid)
	if !ok {
		errResp(tx, h, StatusFileClosed, chain)
		return
	}
	if of.IsDir {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}

	// Batch semantics: all-or-nothing. Locks taken earlier in this request are
	// unwound if a later element conflicts. Blocking waits degrade to immediate
	// failure (clients retry).
	type applied struct{ off, length uint64 }
	var done []applied
	fail := uint32(StatusSuccess)
	for _, e := range elems {
		var res error
		switch {
		case e.flags&lockFlagUnlock != 0:
			res = rangeLock(of.File, e.off, e.length, LockUnlock)
		case e.flags&lockFlagExclusive != 0:
			res = rangeLock(of.File, e.off, e.length, LockExclusive)
		case e.flags&lockFlagShared != 0:
			res = rangeLock(of.File, e.off, e.length, LockShared)
		default:
			fail = StatusInvalidParameter
		}
		if fail != StatusSuccess {
			break
		}
		if res == nil {
			if e.flags&lockFlagUnlock == 0 {
				done = append(done, applied{e.off, e.length})
			}
			continue
		}
		if e := errnoOf(res); e == unix.EAGAIN || e == unix.EACCES {
			fail = StatusLockNotGranted
		} else {
			fail = StatusFromErrno(e)
		}
		break
	}
	if fail != StatusSuccess {
		for i := len(done) - 1; i >= 0; i-- {
			_ = rangeLock(of.File, done[i].off, done[i].length, LockUnlock)
		}
		errResp(tx, h, fail, chain)
		return
	}
	beginResp(tx, h, StatusSuccess, chain.Related, chain.TreeID, chain.SessionID)
	tx.U16(4)
	tx.U16(0)
}

// ------------------------------------------------------------ CHANGE_NOTIFY

func changeNotify(pc *ProtoConn, sess *Session, h *ReqHdr, body []byte, chain *Chain, tx *Writer) {
	r := NewReader(body)
	if v, ok := r.U16(); !ok || v != 32 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	flags, ok := r.U16()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	outLen, ok := r.U32()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	fid, ok := parseFID(r, chain)
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	filter, ok := r.U32()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	wantSign := false
	if ch := pc.Channel(chain.SessionID); ch != nil {
		wantSign = ch.Sign != nil && (ch.SigningRequired || h.Flags&FlagSigned != 0)
	}
	of, ok := sess.Handles.Get(fid)
	if !ok {
		errResp(tx, h, StatusFileClosed, chain)
		return
	}
	if !of.IsDir {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	path := of.Path

	asyncID := pc.NextAsyncID
	pc.NextAsyncID++
	meta := AsyncMeta{
		MsgID:        h.MsgID,
		CreditCharge: h.CreditCharge,
		SessionID:    chain.SessionID,
		AsyncID:      asyncID,
		WantSign:     wantSign,
	}
	pc.NotifyNew = append(pc.NotifyNew, NotifyPend{
		AsyncID:   asyncID,
		FID:       fid,
		Path:      path,
		Recursive: flags&0x1 != 0,
		Filter:    filter,
		OutLen:    min(outLen, MaxTransact),
		Meta:      meta,
	})
	pc.NotifyActive = append(pc.NotifyActive, [2]uint64{fid, asyncID})

	// Interim response: STATUS_PENDING with the async id; the final completion
	// is sent out-of-band by the transport.
	beginRespAsync(tx, &meta, StatusPending, h.Credits, CmdChangeNotify)
	errBody(tx)
}

// -------------------------------------------------------------------- IOCTL

func ioctl(srv *Srv, pc *ProtoConn, h *ReqHdr, msg []byte, chain *Chain, tx *Writer) {
	r := NewReader(msg[64:])
	if v, ok := r.U16(); !ok || v != 57 {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	if !r.Skip(2) {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	ctl, ok := r.U32()
	if !ok {
		errResp(tx, h, StatusInvalidParameter, chain)
		return
	}
	var out []byte
	switch ctl {
	case fsctlValidateNegotiateInfo:
		// Echo the negotiated parameters so the client can verify them. The
		// security mode MUST match what NEGOTIATE advertised or the client
		// aborts with "security settings mismatch".
		secmode := securityModeSigningEnabled
		if srv.cfg.RequireSigning {
			secmode |= securityModeSigningRequired
		}
		o := NewWriter(24)
		o.U32(capLargeMTU)
		o.Bytes8(srv.guid[:])
		o.U16(secmode)
		o.U16(pc.Dialect)
		out = o.Bytes()
	case fsctlQueryNetworkInterfaceInfo:
		// Report our interfaces so the client knows how many channels to open.
		// Loopback is never advertised — a remote client would try to connect to
		// its OWN loopback; same-IP multichannel still works via the RSS flag.
		var ifaces []Iface
		for _, i := range srv.interfaces {
			if !i.Loopback {
				ifaces = append(ifaces, i)
			}
		}
		out = EncodeInterfaceInfo(ifaces)
	default:
		errResp(tx, h, StatusNotSupported, chain)
		return
	}

	beginResp(tx, h, StatusSuccess, chain.Related, chain.TreeID, chain.SessionID)
	tx.U16(49)
	tx.U16(0)
	tx.U32(ctl)
	tx.U64(^uint64(0)) // FileId
	tx.U64(^uint64(0))
	tx.U32(112) // InputOffset
	tx.U32(0)   // InputCount
	tx.U32(112) // OutputOffset
	tx.U32(uint32(len(out)))
	tx.U32(0) // Flags
	tx.U32(0)
	tx.Bytes8(out)
}

// clamp restricts v to [lo, hi].
func clamp(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// addU64 adds two unsigned values, reporting overflow.
func addU64(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
}

// containsU16 reports whether list contains v.
func containsU16(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
