package samba

import (
	"os"
	"strconv"
)

// SMB2 core: header codec, compound dispatch, connection protocol state.
//
// The connection loop feeds complete NetBIOS-framed messages to processFrame and
// sends back whatever lands in tx. A standalone READ becomes a ZcReadPlan that
// the transport serves zero-copy (header write + splice from the file to the
// socket); everything else is answered from the tx buffer.

// SMB2 command codes.
const (
	CmdNegotiate      uint16 = 0
	CmdSessionSetup   uint16 = 1
	CmdLogoff         uint16 = 2
	CmdTreeConnect    uint16 = 3
	CmdTreeDisconnect uint16 = 4
	CmdCreate         uint16 = 5
	CmdClose          uint16 = 6
	CmdFlush          uint16 = 7
	CmdRead           uint16 = 8
	CmdWrite          uint16 = 9
	CmdLock           uint16 = 10
	CmdIoctl          uint16 = 11
	CmdCancel         uint16 = 12
	CmdEcho           uint16 = 13
	CmdQueryDirectory uint16 = 14
	CmdChangeNotify   uint16 = 15
	CmdQueryInfo      uint16 = 16
	CmdSetInfo        uint16 = 17
	CmdOplockBreak    uint16 = 18
)

// SMB2 oplock levels (RequestedOplockLevel / granted OplockLevel byte).
const (
	OplockNone      uint8 = 0x00
	OplockLevelII   uint8 = 0x01
	OplockExclusive uint8 = 0x08
	OplockBatch     uint8 = 0x09
	// OplockLease is the RequestedOplockLevel sentinel meaning "a lease is
	// requested via the RqLs create context" rather than a legacy oplock.
	OplockLease uint8 = 0xFF
)

// SMB2 lease state caching bits (LeaseState in the RqLs create context).
const (
	LeaseReadCaching   uint32 = 0x01
	LeaseHandleCaching uint32 = 0x02
	LeaseWriteCaching  uint32 = 0x04
)

// CtxNameRQLS is the create-context name "RqLs" (lease request/response).
var CtxNameRQLS = []byte("RqLs")

// SMB2 header flags.
const (
	FlagResponse uint32 = 0x1
	FlagAsync    uint32 = 0x2
	FlagRelated  uint32 = 0x4
	FlagSigned   uint32 = 0x8
)

// Buffer-size and data-path limits.
const (
	MaxTransact uint32 = 4 << 20
	MaxWrite    uint32 = 4 << 20
	// MaxReadTarget is the advertised MaxReadSize target. It is deliberately
	// smaller than MaxWriteSize: a modest rsize keeps the client issuing many
	// parallel READs (readahead), which pipelines far better than a few huge
	// serialized ones — measured 5.8 GB/s at 1 MiB vs 0.67 GB/s at 4 MiB on
	// loopback in the original implementation.
	MaxReadTarget uint32 = 1 << 20
	// ZcMinRead is the size at or above which a standalone read is served by the
	// zero-copy path.
	ZcMinRead uint32 = 8 * 1024
)

const hdrLen = 64

// ReqHdr is a parsed SMB2 request header.
type ReqHdr struct {
	CreditCharge uint16
	Command      uint16
	Credits      uint16
	Flags        uint32
	Next         uint32
	MsgID        uint64
	TreeID       uint32
	SessionID    uint64
	// AsyncID is present when the ASYNC flag is set (e.g. CANCEL of a pended
	// operation).
	AsyncID *uint64
}

// ParseHdr parses an SMB2 request header.
func ParseHdr(b []byte) (ReqHdr, bool) {
	r := NewReader(b)
	magic, ok := r.Take(4)
	if !ok || magic[0] != 0xFE || magic[1] != 'S' || magic[2] != 'M' || magic[3] != 'B' {
		return ReqHdr{}, false
	}
	if v, ok := r.U16(); !ok || v != 64 {
		return ReqHdr{}, false
	}
	creditCharge, ok := r.U16()
	if !ok {
		return ReqHdr{}, false
	}
	if !r.Skip(4) { // status
		return ReqHdr{}, false
	}
	command, ok := r.U16()
	if !ok {
		return ReqHdr{}, false
	}
	credits, ok := r.U16()
	if !ok {
		return ReqHdr{}, false
	}
	flags, ok := r.U32()
	if !ok {
		return ReqHdr{}, false
	}
	next, ok := r.U32()
	if !ok {
		return ReqHdr{}, false
	}
	msgID, ok := r.U64()
	if !ok {
		return ReqHdr{}, false
	}
	h := ReqHdr{
		CreditCharge: creditCharge,
		Command:      command,
		Credits:      credits,
		Flags:        flags,
		Next:         next,
		MsgID:        msgID,
	}
	if flags&FlagAsync != 0 {
		asyncID, ok := r.U64()
		if !ok {
			return ReqHdr{}, false
		}
		h.AsyncID = &asyncID
		sid, ok := r.U64()
		if !ok {
			return ReqHdr{}, false
		}
		h.SessionID = sid
	} else {
		if !r.Skip(4) { // process id
			return ReqHdr{}, false
		}
		treeID, ok := r.U32()
		if !ok {
			return ReqHdr{}, false
		}
		h.TreeID = treeID
		sid, ok := r.U64()
		if !ok {
			return ReqHdr{}, false
		}
		h.SessionID = sid
	}
	if !r.Skip(16) { // signature
		return ReqHdr{}, false
	}
	return h, true
}

// Tree is a connected share on a session.
type Tree struct {
	ShareIdx uint32
	IPC      bool
}

// SignCtx is the per-channel SMB2/3 signing state.
type SignCtx struct {
	Alg SignAlg
	Key [16]byte
}

// EncCtx holds the SMB3 encryption keys for one channel. C2S decrypts inbound
// transform frames, S2C encrypts outbound, and NonceCtr is the per-connection
// nonce counter (never reused for a given key).
type EncCtx struct {
	Cipher uint16
	// C2S/S2C are cipher keys in 32-byte buffers; only the first
	// cipherKeyLen(cipher) bytes are used (16 for AES-128, 32 for AES-256).
	C2S      [32]byte
	S2C      [32]byte
	NonceCtr uint64
}

// PendingAuth is the auth state stashed between the NTLM challenge and the
// AUTHENTICATE.
type PendingAuth struct {
	Challenge [8]byte
	SPNEGO    bool
	// Binding is set when this is a multichannel session-binding handshake.
	Binding bool
}

// ChannelState is the per-connection, per-session channel state. One ProtoConn
// holds a ChannelState for every session it is a channel of. Signing and preauth
// are connection-local, so the sign/verify hot path takes no registry lock; the
// shared session state (trees, handles, key) lives in the registry.
type ChannelState struct {
	Established     bool
	SigningRequired bool
	Sign            *SignCtx
	Pending         *PendingAuth
	// Preauth is this connection's running preauth hash for this session's setup.
	Preauth [64]byte
	// Enc holds the SMB3 encryption keys, set once the session negotiates
	// encryption.
	Enc *EncCtx
	// Encrypt causes responses on this session to be sealed (client requested or
	// server requires). When set, signing is implied by the AEAD tag.
	Encrypt bool
}

// AsyncMeta carries the header fields needed to answer a pended operation
// out-of-band.
type AsyncMeta struct {
	MsgID        uint64
	CreditCharge uint16
	SessionID    uint64
	AsyncID      uint64
	WantSign     bool
}

// NotifyPend is a pended CHANGE_NOTIFY the connection's watcher must watch.
// recursive (WATCH_TREE) and filter are accepted but not narrowed: inotify is
// non-recursive and the server over-delivers rather than filtering — clients
// treat extra notifications as a hint to re-check.
type NotifyPend struct {
	AsyncID   uint64
	FID       uint64
	Path      string
	Recursive bool
	Filter    uint32
	OutLen    uint32
	Meta      AsyncMeta
}

// NotifyDone completes a pended CHANGE_NOTIFY early (cancel or handle close).
type NotifyDone struct {
	AsyncID uint64
	Status  uint32
}

// ProtoConn is the per-connection protocol state. Sessions and their handles
// live in the shared registry (so channels on other cores share them);
// Channels holds this connection's per-session signing and preauth state.
type ProtoConn struct {
	Dialect uint16
	// Cipher is the negotiated SMB3 cipher (0 = none).
	Cipher   uint16
	Channels map[uint64]*ChannelState
	MaxRead  uint32
	// PreauthNeg is the SMB 3.1.1 connection preauth hash (negotiate exchange).
	PreauthNeg [64]byte
	// CreditsOut is the credit window currently granted to the client.
	CreditsOut  int64
	NextAsyncID uint64
	// NotifyNew holds CHANGE_NOTIFY pends for the watcher to register.
	NotifyNew []NotifyPend
	// NotifyDone holds completions (cancel / handle close) for the watcher.
	NotifyDone []NotifyDone
	// NotifyActive tracks live pends: (fid, asyncID), so CLOSE/CANCEL find them.
	NotifyActive [][2]uint64
	// Wid/ConnIdx/ConnGen locate this connection so a lease break raised on
	// another worker can be routed back to it.
	Wid     int
	ConnIdx int
	ConnGen uint16
	// krbAcceptor is the lazily acquired Kerberos acceptor for this connection.
	krbAcceptor *KerberosAcceptor
}

// NewProtoConn returns protocol state for a freshly accepted connection.
func NewProtoConn(srv *Srv, wid, connIdx int, connGen uint16) *ProtoConn {
	return &ProtoConn{
		Channels:    make(map[uint64]*ChannelState),
		MaxRead:     srv.maxRead,
		NextAsyncID: 1,
		Wid:         wid,
		ConnIdx:     connIdx,
		ConnGen:     connGen,
	}
}

// Channel returns the channel state for a session id, or nil.
func (pc *ProtoConn) Channel(sid uint64) *ChannelState { return pc.Channels[sid] }

// ZcReadPlan is everything the transport needs to finish a zero-copy READ after
// the dispatcher has validated the request.
type ZcReadPlan struct {
	File     *os.File
	Offset   uint64
	Length   uint32
	MinCount uint32
	MsgID    uint64
	// CreditCharge and Credits are echoed into the response header.
	CreditCharge uint16
	Credits      uint16
	TreeID       uint32
	SessionID    uint64
	// Linked is true when offset+length ≤ file size (a full read, no EOF
	// possible), so the transport can emit header+payload without a
	// userspace round trip to learn the byte count.
	Linked bool
}

// frameAction tells the transport what to do with a processed frame.
type frameAction int

const (
	// actionRespond means the response is in tx.
	actionRespond frameAction = iota
	// actionZcRead means the transport must serve the returned plan zero-copy.
	actionZcRead
	// actionClose means tear down the connection. Used when an encrypted
	// (TRANSFORM) frame cannot be decrypted — per MS-SMB2 the server
	// disconnects rather than leaving the client waiting forever.
	actionClose
)

// Chain is the state threaded through a compound request.
type Chain struct {
	Related   bool
	SessionID uint64
	TreeID    uint32
	LastFID   *uint64
	Single    bool
}

// cmdName names an SMB2 command for logs.
func cmdName(cmd uint16) string {
	switch cmd {
	case CmdNegotiate:
		return "NEGOTIATE"
	case CmdSessionSetup:
		return "SESSION_SETUP"
	case CmdLogoff:
		return "LOGOFF"
	case CmdTreeConnect:
		return "TREE_CONNECT"
	case CmdTreeDisconnect:
		return "TREE_DISCONNECT"
	case CmdCreate:
		return "CREATE"
	case CmdClose:
		return "CLOSE"
	case CmdFlush:
		return "FLUSH"
	case CmdRead:
		return "READ"
	case CmdWrite:
		return "WRITE"
	case CmdLock:
		return "LOCK"
	case CmdIoctl:
		return "IOCTL"
	case CmdCancel:
		return "CANCEL"
	case CmdEcho:
		return "ECHO"
	case CmdQueryDirectory:
		return "QUERY_DIRECTORY"
	case CmdChangeNotify:
		return "CHANGE_NOTIFY"
	case CmdQueryInfo:
		return "QUERY_INFO"
	case CmdSetInfo:
		return "SET_INFO"
	default:
		return "command " + strconv.FormatUint(uint64(cmd), 10)
	}
}

// beginResp writes a response header and returns the offset of the header start
// in tx.
func beginResp(tx *Writer, h *ReqHdr, st uint32, related bool, treeID uint32, sessionID uint64) int {
	start := tx.Len()
	tx.Bytes8([]byte{0xFE, 'S', 'M', 'B'})
	tx.U16(64)
	tx.U16(h.CreditCharge)
	tx.U32(st)
	tx.U16(h.Command)
	tx.U16(h.Credits) // credits granted (accounted by the dispatcher)
	flags := FlagResponse
	if related {
		flags |= FlagRelated
	}
	tx.U32(flags)
	tx.U32(0) // NextCommand, patched by the chain loop
	tx.U64(h.MsgID)
	tx.U32(0) // process id
	tx.U32(treeID)
	tx.U64(sessionID)
	tx.Zeros(16) // signature
	return start
}

// beginRespAsync writes an async response header (interim STATUS_PENDING and
// final completions).
func beginRespAsync(tx *Writer, meta *AsyncMeta, st uint32, credits uint16, cmd uint16) int {
	start := tx.Len()
	tx.Bytes8([]byte{0xFE, 'S', 'M', 'B'})
	tx.U16(64)
	tx.U16(meta.CreditCharge)
	tx.U32(st)
	tx.U16(cmd)
	tx.U16(credits)
	tx.U32(FlagResponse | FlagAsync)
	tx.U32(0) // NextCommand
	tx.U64(meta.MsgID)
	tx.U64(meta.AsyncID)
	tx.U64(meta.SessionID)
	tx.Zeros(16)
	return start
}

// signInPlace signs the message at tx[start:end] in place (the signature field is
// zeroed by construction) and sets the SIGNED flag.
func signInPlace(tx *Writer, start, end int, sc *SignCtx) {
	b := tx.Bytes()
	const flagsOff = 16
	cur := le32(b[start+flagsOff : start+flagsOff+4])
	put32(b[start+flagsOff:], cur|FlagSigned)
	sig := smb2Signature(sc.Alg, &sc.Key, b[start:end])
	copy(b[start+48:start+64], sig[:])
}

// verifySignature verifies a signed request message (the signature field is
// substituted with zeros).
func verifySignature(msg []byte, sc *SignCtx) bool {
	if len(msg) < 64 {
		return false
	}
	var zeros [16]byte
	sig := smb2Signature(sc.Alg, &sc.Key, msg[:48], zeros[:], msg[64:])
	// A MAC comparison; compare without early exit anyway.
	return cmacEqual(sig[:], msg[48:64])
}

// deriveSignCtx derives the SMB2/3 signing context for dialect from a 16-byte
// session key and the channel's preauth hash.
func deriveSignCtx(dialect uint16, sessionKey *[16]byte, preauth *[64]byte) SignCtx {
	switch dialect {
	case 0x0202, 0x0210:
		return SignCtx{Alg: SignHmacSha256, Key: *sessionKey}
	case 0x0311:
		return SignCtx{Alg: SignAesCmac, Key: kdf128(sessionKey, []byte("SMBSigningKey\x00"), preauth[:])}
	default:
		return SignCtx{Alg: SignAesCmac, Key: kdf128(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))}
	}
}

// errBody writes the 9-byte SMB2 ERROR response body.
func errBody(tx *Writer) {
	tx.U16(9)
	tx.U8(0) // ErrorContextCount
	tx.U8(0)
	tx.U32(0) // ByteCount
	tx.U8(0)  // ErrorData placeholder
}

func errResp(tx *Writer, h *ReqHdr, st uint32, chain *Chain) {
	beginResp(tx, h, st, chain.Related, chain.TreeID, chain.SessionID)
	errBody(tx)
}

// BuildReadRespPrefix writes the NBT prefix, success header and READ response
// fixed part for n bytes of payload the transport will append from the file. It
// replaces the contents of tx.
func BuildReadRespPrefix(plan *ZcReadPlan, n uint32, tx *Writer) {
	tx.Truncate(0)
	h := readPlanHdr(plan)
	tx.Zeros(4)
	beginResp(tx, h, StatusSuccess, false, plan.TreeID, plan.SessionID)
	tx.U16(17) // StructureSize
	tx.U8(80)  // DataOffset
	tx.U8(0)
	tx.U32(n)
	tx.U32(0) // DataRemaining
	tx.U32(0)
	finishNBTAt(tx, 0, uint32(tx.Len()-4)+n)
}

// BuildReadErr writes a complete NBT-framed error response for a failed
// zero-copy read. It replaces the contents of tx.
func BuildReadErr(plan *ZcReadPlan, st uint32, tx *Writer) {
	tx.Truncate(0)
	h := readPlanHdr(plan)
	tx.Zeros(4)
	beginResp(tx, h, st, false, plan.TreeID, plan.SessionID)
	errBody(tx)
	finishNBTAt(tx, 0, uint32(tx.Len()-4))
}

func readPlanHdr(plan *ZcReadPlan) *ReqHdr {
	return &ReqHdr{
		CreditCharge: plan.CreditCharge,
		Command:      CmdRead,
		Credits:      plan.Credits,
		MsgID:        plan.MsgID,
		TreeID:       plan.TreeID,
		SessionID:    plan.SessionID,
	}
}

// DirEvent is one (action, name) pair in a CHANGE_NOTIFY completion.
type DirEvent struct {
	Action uint32
	Name   string
}

// BuildNotifyFinal builds a complete (NBT-framed, optionally signed) final
// response for a pended CHANGE_NOTIFY. An empty event list — or an encoding that
// exceeds the client's buffer — degrades to STATUS_NOTIFY_ENUM_DIR
// ("re-enumerate") for success completions.
func BuildNotifyFinal(pc *ProtoConn, meta *AsyncMeta, st uint32, events []DirEvent, outLen uint32) []byte {
	tx := NewWriter(256)
	tx.Zeros(4)
	data := NewWriter(256)
	if st == StatusSuccess && len(events) > 0 {
		entryStarts := make([]int, 0, len(events))
		for _, e := range events {
			// 4-align between entries.
			for data.Len()%4 != 0 {
				data.U8(0)
			}
			entryStarts = append(entryStarts, data.Len())
			n16 := UTF16LE(e.Name)
			data.U32(0) // NextEntryOffset, patched below
			data.U32(e.Action)
			data.U32(uint32(len(n16)))
			data.Bytes8(n16)
		}
		for i := 0; i+1 < len(entryStarts); i++ {
			data.Patch32(entryStarts[i], uint32(entryStarts[i+1]-entryStarts[i]))
		}
	}
	if st == StatusSuccess && len(events) > 0 && data.Len() <= int(outLen) {
		start := beginRespAsync(tx, meta, st, 0, CmdChangeNotify)
		tx.U16(9)
		tx.U16(72)
		tx.U32(uint32(data.Len()))
		tx.Bytes8(data.Bytes())
		finalizeAsync(pc, meta, tx, start)
	} else {
		finalSt := st
		if st == StatusSuccess {
			finalSt = StatusNotifyEnumDir
		}
		start := beginRespAsync(tx, meta, finalSt, 0, CmdChangeNotify)
		errBody(tx)
		finalizeAsync(pc, meta, tx, start)
	}
	return tx.Bytes()
}

func finalizeAsync(pc *ProtoConn, meta *AsyncMeta, tx *Writer, start int) {
	if meta.WantSign {
		if ch := pc.Channel(meta.SessionID); ch != nil && ch.Sign != nil {
			signInPlace(tx, start, tx.Len(), ch.Sign)
		}
	}
	finishNBTAt(tx, 0, uint32(tx.Len()-4))
}

func finishNBTAt(tx *Writer, base int, n uint32) {
	b := tx.Bytes()
	b[base] = 0
	b[base+1] = byte(n >> 16)
	b[base+2] = byte(n >> 8)
	b[base+3] = byte(n)
}

// BuildLeaseBreak builds a complete NBT-framed SMB2 Lease Break notification
// (server→client, MS-SMB2 2.2.23.2): a synchronous response with
// MessageId = -1, keyed by the client's 16-byte LeaseKey, telling it to drop
// from curState to newState. Read-caching → none carries no dirty data, so
// Flags = 0 (no acknowledgement required). It is signed when the channel has a
// signing context.
func BuildLeaseBreak(leaseKey *[16]byte, curState, newState uint32, epoch uint16, sessionID uint64, sign *SignCtx) []byte {
	tx := NewWriter(4 + 64 + 44)
	tx.Zeros(4) // NBT length placeholder
	start := tx.Len()
	tx.Bytes8([]byte{0xFE, 'S', 'M', 'B'})
	tx.U16(64) // header StructureSize
	tx.U16(0)  // CreditCharge
	tx.U32(0)  // Status
	tx.U16(CmdOplockBreak)
	tx.U16(0) // CreditResponse
	tx.U32(FlagResponse)
	tx.U32(0)                     // NextCommand
	tx.U64(0xFFFF_FFFF_FFFF_FFFF) // MessageId (notification sentinel)
	tx.U32(0)                     // ProcessId
	tx.U32(0)                     // TreeId
	tx.U64(sessionID)
	tx.Zeros(16) // signature
	// Lease Break Notification body (StructureSize 44).
	tx.U16(44)
	tx.U16(epoch) // NewEpoch (v2 leases; 0 for v1)
	tx.U32(0)     // Flags: 0 = acknowledgement not required (read-cache drop)
	tx.Bytes8(leaseKey[:])
	tx.U32(curState) // CurrentLeaseState
	tx.U32(newState) // NewLeaseState
	tx.U32(0)        // BreakReason
	tx.U32(0)        // AccessMaskHint
	tx.U32(0)        // ShareMaskHint
	if sign != nil {
		signInPlace(tx, start, tx.Len(), sign)
	}
	finishNBTAt(tx, 0, uint32(tx.Len()-4))
	return tx.Bytes()
}

// ----------------------------------------------------- SMB3 TRANSFORM_HEADER

// transformProto is the SMB2_TRANSFORM_HEADER ProtocolId: 0xFD 'S' 'M' 'B'.
var transformProto = []byte{0xFD, 'S', 'M', 'B'}

const transformHdrLen = 52

// isTransform reports whether a (de-NBT'd) frame is an SMB3 encrypted transform
// message.
func isTransform(frame []byte) bool {
	return len(frame) >= 4 && bytesEqual(frame[:4], transformProto)
}

// decryptTransform decrypts a transform-wrapped frame into the inner plaintext
// SMB2 message(s). It reports failure on malformed input or AEAD authentication
// failure.
func decryptTransform(frame []byte, enc *EncCtx) ([]byte, bool) {
	if len(frame) < transformHdrLen || !bytesEqual(frame[:4], transformProto) {
		return nil, false
	}
	var tag [16]byte
	copy(tag[:], frame[4:20])
	origSize := int(le32(frame[36:40]))
	// AAD is the header from the Nonce field to the end (Signature excluded).
	aad := frame[20:transformHdrLen]
	ct := frame[transformHdrLen:]
	if len(ct) != origSize {
		return nil, false
	}
	klen := cipherKeyLen(enc.Cipher)
	nlen := cipherNonceLen(enc.Cipher)
	nonce := frame[20 : 20+nlen]
	buf := make([]byte, len(ct))
	copy(buf, ct)
	if !aeadOpen(enc.Cipher, enc.C2S[:klen], nonce, aad, buf, &tag) {
		return nil, false
	}
	return buf, true
}

// wrapTransformAppends wraps a plaintext SMB2 message/compound in a transform
// header, encrypting with the s2c key, and appends NBT prefix + transform header
// + ciphertext to tx.
func wrapTransformAppend(plain []byte, enc *EncCtx, sessionID uint64, tx *Writer) {
	base := tx.Len()
	tx.Zeros(4) // NBT placeholder
	hdr := tx.Len()
	tx.Bytes8(transformProto)
	sigOff := tx.Len()
	tx.Zeros(16) // Signature (AEAD tag) — filled after encryption
	enc.NonceCtr++
	var nonce16 [16]byte
	put64(nonce16[:8], enc.NonceCtr)
	tx.Bytes8(nonce16[:])      // Nonce (12 used for GCM, 11 for CCM)
	tx.U32(uint32(len(plain))) // OriginalMessageSize
	tx.U16(0)                  // Reserved
	tx.U16(1)                  // Flags: SMB2_ENCRYPTION (3.1.1)
	tx.U64(sessionID)
	aadStart := hdr + 20
	ctOff := tx.Len()
	tx.Bytes8(plain)
	klen := cipherKeyLen(enc.Cipher)
	nlen := cipherNonceLen(enc.Cipher)
	b := tx.Bytes()
	tag := aeadSeal(enc.Cipher, enc.S2C[:klen], nonce16[:nlen], b[aadStart:ctOff], b[ctOff:])
	copy(b[sigOff:sigOff+16], tag[:])
	finishNBTAt(tx, base, uint32(tx.Len()-base-4))
}

// ProcessFrame processes one NetBIOS-framed message (without the 4-byte NBT
// prefix). It transparently handles SMB3 encryption: a transform-wrapped frame
// is decrypted, the inner message processed, and the response re-encrypted. The
// response (with NBT prefix) is appended to tx.
func ProcessFrame(srv *Srv, pc *ProtoConn, frame []byte, tx *Writer) (frameAction, *ZcReadPlan) {
	if isTransform(frame) {
		// The session id lives at bytes 44..52 of the transform header.
		if len(frame) < transformHdrLen {
			return actionClose, nil // malformed transform → disconnect
		}
		sid := le64(frame[44:52])
		ch := pc.Channel(sid)
		if ch == nil || ch.Enc == nil {
			// No decryption key for this session (e.g. a guest/anonymous
			// session, which cannot be encrypted). The client sealed traffic we
			// cannot decrypt — disconnect instead of silently dropping, which
			// would hang the client forever.
			return actionClose, nil
		}
		enc := *ch.Enc
		plain, ok := decryptTransform(frame, &enc)
		if !ok {
			return actionClose, nil // authentication/decryption failure
		}
		// This session is actively encrypting — make reads take the buffered
		// path (responses are wrapped, so they cannot be spliced).
		ch.Encrypt = true
		inner := NewWriter(len(plain) + 64)
		// Encrypted sessions never splice (read() forces the buffered path), so
		// the inner processing cannot yield a zero-copy plan.
		processPlain(srv, pc, plain, inner, true)
		if inner.Len() <= 4 {
			return actionRespond, nil // no response (e.g. CANCEL)
		}
		// Re-encrypt the plaintext response (strip its NBT prefix first).
		encOut := *pc.Channel(sid).Enc
		wrapTransformAppend(inner.Bytes()[4:], &encOut, sid, tx)
		pc.Channel(sid).Enc = &encOut // persist the bumped nonce counter
		return actionRespond, nil
	}
	return processPlain(srv, pc, frame, tx, false)
}

// processPlain dispatches the message(s) in one frame. `encrypted` is true when
// these messages arrived inside a transform (so the response will be wrapped,
// not signed).
func processPlain(srv *Srv, pc *ProtoConn, frame []byte, tx *Writer, encrypted bool) (frameAction, *ZcReadPlan) {
	base := tx.Len()
	tx.Zeros(4) // NBT placeholder

	// Legacy SMB1 negotiate → wildcard SMB2 response (dialect 0x02FF).
	if len(frame) >= 4 && frame[0] == 0xFF && frame[1] == 'S' && frame[2] == 'M' && frame[3] == 'B' {
		negotiateRespSMB1Wildcard(srv, pc, tx)
		finishNBTAt(tx, base, uint32(tx.Len()-base-4))
		return actionRespond, nil
	}

	chain := &Chain{Single: true}
	var plan *ZcReadPlan
	prevStart := -1
	type respRec struct {
		cmd    uint16
		start  int
		reqOff int
		reqEnd int
		sessID uint64
	}
	var recs []respRec

	for off := 0; off < len(frame); {
		h, ok := ParseHdr(frame[off:])
		if !ok {
			break
		}
		msgEnd := len(frame)
		if h.Next > 0 {
			msgEnd = min(off+int(h.Next), len(frame))
		}
		if msgEnd < off+hdrLen {
			break
		}
		msg := frame[off:msgEnd]
		chain.Single = off == 0 && h.Next == 0

		// Align this response and patch the previous header's NextCommand.
		if prevStart >= 0 {
			tx.Pad8(base + 4)
			here := tx.Len()
			tx.Patch32(prevStart+20, uint32(here-prevStart))
		}
		respStart := tx.Len()
		if z := dispatch(srv, pc, &h, msg, chain, tx, encrypted); z != nil {
			plan = z
		}
		if tx.Len() > respStart {
			prevStart = respStart
			recs = append(recs, respRec{
				cmd:    h.Command,
				start:  respStart,
				reqOff: off,
				reqEnd: msgEnd,
				sessID: chain.SessionID,
			})
		}

		if h.Next == 0 {
			break
		}
		off += int(h.Next)
		if off+hdrLen > len(frame) {
			break
		}
	}

	if plan != nil {
		// A zero-copy plan writes nothing buffered; drop the placeholder.
		tx.Truncate(base)
		return actionZcRead, plan
	}

	// Post-pass 1: sign every response on an authenticated session. A session
	// only holds signing material once a non-guest user has authenticated, and
	// MS-SMB2 requires such sessions to sign all responses — including the final
	// SESSION_SETUP — regardless of whether the client set SIGNING_REQUIRED.
	// Responses to encrypted requests are wrapped (the AEAD tag is the
	// integrity), so they are not separately signed.
	if !encrypted {
		for i := range recs {
			end := tx.Len()
			if i+1 < len(recs) {
				end = recs[i+1].start
			}
			rec := &recs[i]
			ch := pc.Channel(rec.sessID)
			if ch == nil || ch.Sign == nil {
				continue
			}
			signInPlace(tx, rec.start, end, ch.Sign)
		}
	}

	// Post-pass 2 (SMB 3.1.1): preauth integrity hash chaining over the exact
	// transmitted bytes. The NEGOTIATE exchange updates the connection hash;
	// interim SESSION_SETUP responses update the pending session hash (requests
	// are hashed in the handler, where ordering against key derivation matters).
	if pc.Dialect == 0x0311 {
		b := tx.Bytes()
		for i := range recs {
			end := tx.Len()
			if i+1 < len(recs) {
				end = recs[i+1].start
			}
			rec := &recs[i]
			switch rec.cmd {
			case CmdNegotiate:
				var zero [64]byte
				h0 := sha512Parts(zero[:], frame[rec.reqOff:rec.reqEnd])
				pc.PreauthNeg = sha512Parts(h0[:], b[rec.start:end])
			case CmdSessionSetup:
				st := le32(b[rec.start+8 : rec.start+12])
				if st == StatusMoreProcessingRequire {
					if ch := pc.Channel(rec.sessID); ch != nil {
						ch.Preauth = sha512Parts(ch.Preauth[:], b[rec.start:end])
					}
				}
			}
		}
	}

	total := uint32(tx.Len() - base - 4)
	if total == 0 {
		tx.Truncate(base) // nothing to send for this frame
	} else {
		finishNBTAt(tx, base, total)
	}
	return actionRespond, nil
}
