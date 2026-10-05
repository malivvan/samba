package samba

import "fmt"

// Introspection: what this build implements, and the live state of a running
// server.
//
// The CLI reports all of it — `samba --check` prints the capabilities, the
// `--list-*` commands the negotiation facts, and the startup banner both — so
// the dialects, ciphers and features are described here once instead of being
// restated in the CLI, the man page and the docs and drifting apart. Every
// list here is checked against the code that acts on it by the tests in
// introspect_test.go.

// Dialect is one SMB dialect the server negotiates.
type Dialect struct {
	// Name is the marketing name, e.g. "SMB 3.1.1".
	Name string
	// Version is the spelling the configuration uses, e.g. "3.1.1". This is
	// what `min_dialect` takes, and what the CLI prints for it.
	Version string
	// Revision is the revision code as it appears on the wire.
	Revision uint16
	// Detail is what that dialect adds, in one line.
	Detail string
}

// dialects is the negotiation preference order, newest first. The revisions
// must match the list the NEGOTIATE handler searches (supportedDialects);
// TestDialectsMatchNegotiation pins the two together.
var dialects = []Dialect{
	{"SMB 3.1.1", "3.1.1", 0x0311, "pre-authentication integrity, negotiated ciphers, negotiate contexts"},
	{"SMB 3.0.2", "3.0.2", 0x0302, "RDMA transport revisions, AES-128-GCM"},
	{"SMB 3.0", "3.0", 0x0300, "encryption (AES-128-CCM), multichannel, secure negotiate"},
	{"SMB 2.1", "2.1", 0x0210, "leases, multi-credit, resilient handles; no encryption"},
	{"SMB 2.0.2", "2.0.2", 0x0202, "durable handles, handle-based operations; no encryption"},
}

// DialectByName resolves a configuration spelling ("2.0.2", "3.0", "3.1.1") to
// the dialect it names.
func DialectByName(version string) (Dialect, bool) {
	for _, d := range dialects {
		if d.Version == version {
			return d, true
		}
	}
	return Dialect{}, false
}

// DialectNames lists the configuration spellings, oldest first — the accepted
// values of `min_dialect`, in the order an error message should show them.
func DialectNames() []string {
	out := make([]string, 0, len(dialects))
	for i := len(dialects) - 1; i >= 0; i-- {
		out = append(out, dialects[i].Version)
	}
	return out
}

const (
	// DefaultMinDialect is the dialect floor when `min_dialect` is unset: every
	// dialect the server implements.
	DefaultMinDialect = "2.0.2"
	// EncryptionMinDialect is the oldest dialect that can encrypt at all, and so
	// the floor whenever `encrypt` is set. SMB 2.0.2 and 2.1 have no encryption
	// and no way to add it, so a "require encryption" server that still
	// negotiated them would serve those clients in the clear.
	EncryptionMinDialect = "3.0"
)

// dialectFloorOrPanic resolves one of the constants above. Both are in the
// table by construction and TestDialectsMatchNegotiation says so, which makes a
// miss a programming error rather than a runtime condition.
func dialectFloorOrPanic(version string) Dialect {
	d, ok := DialectByName(version)
	if !ok {
		panic("samba: dialect " + version + " is missing from the dialect table")
	}
	return d
}

// Dialects lists the dialects the server negotiates, newest first, in the order
// NEGOTIATE prefers them. The result is a copy: callers may keep or reorder it.
func Dialects() []Dialect {
	return append([]Dialect(nil), dialects...)
}

// Cipher is one SMB3 encryption cipher.
type Cipher struct {
	// Name is the marketing name, e.g. "AES-128-GCM".
	Name string
	// ID is the identifier used in the encryption negotiate context.
	ID uint16
	// KeyBits is the key size in bits.
	KeyBits int
}

// ciphers is the server's own preference order, strongest first. NEGOTIATE
// walks exactly this list when `prefer_aes256` is set; without it the client's
// own order wins.
var ciphers = []Cipher{
	{"AES-256-GCM", CipherAES256GCM, 256},
	{"AES-256-CCM", CipherAES256CCM, 256},
	{"AES-128-GCM", CipherAES128GCM, 128},
	{"AES-128-CCM", CipherAES128CCM, 128},
}

// Ciphers lists the SMB3 encryption ciphers the server supports, strongest
// first. That order is also the preference `prefer_aes256` applies. The result
// is a copy.
func Ciphers() []Cipher {
	return append([]Cipher(nil), ciphers...)
}

// Capability is one thing the server can do, with whether the configuration in
// hand turns it on.
type Capability struct {
	Name    string
	Detail  string
	Enabled bool
}

// SigningAlgorithms lists the signature algorithms, in the dialect order they
// apply: HMAC-SHA256 for SMB 2.x, AES-CMAC and AES-GMAC for SMB 3.x.
func SigningAlgorithms() []string {
	return []string{
		"HMAC-SHA256 (SMB 2.0.2, 2.1)",
		"AES-CMAC (SMB 3.0, 3.0.2, 3.1.1)",
		"AES-GMAC (SMB 3.1.1)",
	}
}

// Capabilities reports what the server implements and which parts this
// configuration enables. It reads the resolved configuration, so it describes
// the server that would actually start — which is what makes it worth printing
// from `--check` and in the startup banner.
func (s *Srv) Capabilities() []Capability {
	cfg := &s.cfg

	conns := fmt.Sprintf("%d connections", DefaultMaxConnections)
	if cfg.MaxConnections != nil {
		switch n := *cfg.MaxConnections; {
		case n < 0:
			conns = "unlimited connections"
		default:
			conns = fmt.Sprintf("%d connections", n)
		}
	}

	signing := "negotiated per session"
	if cfg.RequireSigning {
		signing = "required on authenticated sessions"
	}

	encryption := "when the client asks (e.g. cifs seal)"
	if cfg.Encrypt {
		encryption = "required for all post-auth traffic"
	}
	if cfg.PreferAES256 {
		encryption += ", AES-256 preferred"
	}

	multichannel := "off"
	if cfg.Multichannel {
		n := 0
		for _, i := range s.interfaces {
			if !i.Loopback {
				n++
			}
		}
		multichannel = fmt.Sprintf("%d interface(s) advertised", n)
	}

	return []Capability{
		{Name: "dialects", Detail: "SMB " + cfg.DialectFloor().Version + " through " + dialects[0].Version, Enabled: true},
		{Name: "ntlmv2", Detail: "local user database; the only mechanism", Enabled: true},
		{Name: "guest", Detail: "unauthenticated sessions", Enabled: s.allowGuest},
		{Name: "signing", Detail: signing, Enabled: true},
		{Name: "encryption", Detail: encryption, Enabled: true},
		{Name: "multichannel", Detail: multichannel, Enabled: cfg.Multichannel},
		{Name: "leases", Detail: "read- and handle-caching; write-caching is never granted", Enabled: cfg.Oplocks},
		{Name: "byte-range locks", Detail: "OFD locks, all-or-nothing batches", Enabled: true},
		{Name: "change notification", Detail: "inotify-backed asynchronous completion", Enabled: true},
		{Name: "zero-copy reads", Detail: "splice(2): file pages straight to the socket", Enabled: true},
		{Name: "compound requests", Detail: "related and unrelated chaining", Enabled: true},
		{Name: "resource limits", Detail: conns, Enabled: true},
	}
}

// Stats is a snapshot of a running server, for diagnostics.
type Stats struct {
	// Connections is the number of TCP connections currently served.
	Connections int
	// MaxConnections is the configured cap, or -1 when unlimited.
	MaxConnections int
	// Sessions is the number of live SMB sessions.
	Sessions int
	// Handles is the open file handles across every session.
	Handles int
	// Trees is the share connections across every session.
	Trees int
	// Leases is the number of leases the server currently tracks.
	Leases int
	// Shares and Users are the configured counts (not live state).
	Shares int
	Users  int
}

// Stats returns a snapshot of the server's live state. Each counter is read
// independently and without quiescing the server, so the result is a snapshot
// rather than a consistent instant: it is meant for diagnostics, not for
// accounting.
func (s *Server) Stats() Stats {
	srv := s.srv
	maxConns := DefaultMaxConnections
	if srv.cfg.MaxConnections != nil {
		maxConns = *srv.cfg.MaxConnections
	}
	handles, trees := srv.sessions.Totals()
	return Stats{
		Connections:    srv.conns.Count(),
		MaxConnections: maxConns,
		Sessions:       srv.sessions.Len(),
		Handles:        handles,
		Trees:          trees,
		Leases:         srv.leases.Len(),
		Shares:         len(srv.cfg.Shares),
		Users:          len(srv.cfg.Users),
	}
}
