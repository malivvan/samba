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
	// Revision is the revision code as it appears on the wire.
	Revision uint16
	// Detail is what that dialect adds, in one line.
	Detail string
}

// dialects is the negotiation preference order, newest first. The revisions
// must match the list the NEGOTIATE handler searches (supportedDialects);
// TestDialectsMatchNegotiation pins the two together.
var dialects = []Dialect{
	{"SMB 3.1.1", 0x0311, "pre-authentication integrity, AES-128-GCM, negotiate contexts"},
	{"SMB 3.0.2", 0x0302, "RDMA transport revisions"},
	{"SMB 3.0", 0x0300, "encryption, multichannel, secure negotiate"},
	{"SMB 2.1", 0x0210, "leases, multi-credit, resilient handles"},
	{"SMB 2.0.2", 0x0202, "durable handles, handle-based operations"},
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

	kerberos := "off"
	if cfg.Auth.AllowsKerberos() {
		spn := "cifs/" + cfg.ServerName
		if cfg.Kerberos != nil && cfg.Kerberos.SPN != "" {
			spn = cfg.Kerberos.SPN
		}
		kerberos = "GSS-API/SPNEGO from a keytab, SPN " + spn
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
		{Name: "dialects", Detail: "SMB 2.0.2 through 3.1.1", Enabled: true},
		{Name: "ntlmv2", Detail: "local user database", Enabled: cfg.Auth.AllowsNTLM()},
		{Name: "kerberos", Detail: kerberos, Enabled: cfg.Auth.AllowsKerberos()},
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
