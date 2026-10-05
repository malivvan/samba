package samba

import (
	"net"
	"strings"
	"testing"
)

// The introspection API exists so the CLI, the docs and the code that acts on
// the values cannot disagree. These tests are what makes that claim true: each
// published list is checked against the code that consumes it, not against
// itself.

// TestDialectsMatchNegotiation pins the published dialect list to the one the
// NEGOTIATE handler searches, including the order (both claim to be the server
// preference).
func TestDialectsMatchNegotiation(t *testing.T) {
	got := Dialects()
	if len(got) != len(supportedDialects) {
		t.Fatalf("Dialects() has %d entries, supportedDialects has %d", len(got), len(supportedDialects))
	}
	for i := range got {
		if got[i].Revision != supportedDialects[i] {
			t.Errorf("Dialects()[%d] = %#x, supportedDialects[%d] = %#x",
				i, got[i].Revision, i, supportedDialects[i])
		}
		if got[i].Name == "" || got[i].Detail == "" {
			t.Errorf("Dialects()[%d] (%#x) is missing its name or detail", i, got[i].Revision)
		}
	}
}

// TestCiphersMatchSelection checks that every published cipher is one the
// encryption negotiate context accepts, that the key size matches the
// identifier, and that the list is in the strongest-first order `prefer_aes256`
// applies.
func TestCiphersMatchSelection(t *testing.T) {
	got := Ciphers()
	if len(got) < 4 {
		t.Fatalf("Ciphers() has %d entries, want at least the four defined ciphers", len(got))
	}
	for _, c := range got {
		if !cipherSupported(c.ID) {
			t.Errorf("%s (%#x) is published but negotiate does not accept it", c.Name, c.ID)
		}
		want := 128
		if c.ID == CipherAES256GCM || c.ID == CipherAES256CCM {
			want = 256
		}
		if c.KeyBits != want {
			t.Errorf("%s (%#x) advertises %d key bits, want %d", c.Name, c.ID, c.KeyBits, want)
		}
	}
	// prefer_aes256 walks this list in order, so the strongest must be first
	// and the strength must not increase anywhere along it.
	last := 1 << 30
	for i, c := range got {
		if c.KeyBits > last {
			t.Errorf("Ciphers()[%d] = %s is stronger than the entry before it", i, c.Name)
		}
		last = c.KeyBits
	}
	if got[0].ID != CipherAES256GCM {
		t.Errorf("the first published cipher is %s, want AES-256-GCM", got[0].Name)
	}
}

// TestSigningAlgorithmsCoverEveryDialect checks that the algorithms the server
// advertises cover the dialects it negotiates: SMB 3.0.2 and 3.1.1 sign with
// AES-CMAC, the 2.x dialects with HMAC-SHA256.
func TestSigningAlgorithmsCoverEveryDialect(t *testing.T) {
	algs := strings.Join(SigningAlgorithms(), "\n")
	for _, want := range []string{"HMAC-SHA256", "AES-CMAC"} {
		if !strings.Contains(algs, want) {
			t.Errorf("the signing list omits %s", want)
		}
	}
	// SMB 2.0.2 is in the dialect list and must be covered by a signature.
	if !strings.Contains(algs, "2.0.2") {
		t.Error("no published signature algorithm covers SMB 2.0.2")
	}
}

// TestCapabilitiesReflectConfig checks that the capability report follows the
// configuration rather than printing fixed text: a feature that is switched off
// must say so, and one that is always implemented must not.
func TestCapabilitiesReflectConfig(t *testing.T) {
	cfg := &Config{}
	*cfg = newConfig()
	cfg.ServerName = "SMB-TEST"
	cfg.Shares = []ShareCfg{{Name: "t", Path: t.TempDir()}}
	no := false
	cfg.AllowGuest = &no
	cfg.Oplocks = false
	cfg.Multichannel = false
	eight := 8
	cfg.MaxConnections = &eight
	srv := &Srv{cfg: *cfg, sessions: NewRegistry(), leases: NewLeaseTable(), conns: newConnLimiter(eight)}

	byName := make(map[string]Capability)
	for _, c := range srv.Capabilities() {
		if _, dup := byName[c.Name]; dup {
			t.Errorf("capability %q is reported twice", c.Name)
		}
		if c.Detail == "" {
			t.Errorf("capability %q has no detail", c.Name)
		}
		byName[c.Name] = c
	}

	if !byName["dialects"].Enabled {
		t.Error("the dialect list is always on")
	}
	if byName["leases"].Enabled {
		t.Error("leases must report off when oplocks = false")
	}
	if byName["guest"].Enabled {
		t.Error("guest must report off when allow_guest = false")
	}
	if byName["multichannel"].Enabled {
		t.Error("multichannel must report off when multichannel = false")
	}
	for _, name := range []string{"signing", "encryption", "byte-range locks", "zero-copy reads"} {
		if !byName[name].Enabled {
			t.Errorf("%s is implemented and must report on", name)
		}
	}
	if !strings.Contains(byName["kerberos"].Detail, "cifs/SMB-TEST") {
		t.Errorf("kerberos detail should carry the default SPN, got %q", byName["kerberos"].Detail)
	}
	if !strings.Contains(byName["resource limits"].Detail, "8 connections") {
		t.Errorf("resource limits should report the configured cap, got %q",
			byName["resource limits"].Detail)
	}
}

// TestCapabilitiesUnlimitedConnections covers the documented -1 escape hatch.
func TestCapabilitiesUnlimitedConnections(t *testing.T) {
	cfg := &Config{}
	*cfg = newConfig()
	unlimited := -1
	cfg.MaxConnections = &unlimited
	cfg.Shares = []ShareCfg{{Name: "t", Path: t.TempDir()}}
	no := false
	cfg.AllowGuest = &no
	srv := &Srv{cfg: *cfg, sessions: NewRegistry(), leases: NewLeaseTable(), conns: newConnLimiter(unlimited)}
	for _, c := range srv.Capabilities() {
		if c.Name == "resource limits" {
			if !strings.Contains(c.Detail, "unlimited") {
				t.Errorf("resource limit detail = %q, want unlimited", c.Detail)
			}
			return
		}
	}
	t.Fatal("no resource-limits capability was reported")
}

// TestCapabilitiesWhenEverythingIsOn covers the other half of the report: the
// details an operator sees for a hardened, fully enabled server. The wording
// matters — it is what --check prints.
func TestCapabilitiesWhenEverythingIsOn(t *testing.T) {
	cfg := &Config{}
	*cfg = newConfig()
	cfg.ServerName = "SMB-FULL"
	cfg.Shares = []ShareCfg{{Name: "t", Path: t.TempDir()}}
	cfg.RequireSigning = true
	cfg.Encrypt = true
	cfg.PreferAES256 = true
	cfg.Multichannel = true
	cfg.Oplocks = true
	cfg.Auth = AuthBoth
	cfg.Kerberos = &KerberosCfg{SPN: "cifs/files.example.com"}
	srv := &Srv{
		cfg:      *cfg,
		sessions: NewRegistry(),
		leases:   NewLeaseTable(),
		conns:    newConnLimiter(DefaultMaxConnections),
		// One routable interface and one loopback: the loopback must not be
		// counted in the advertisement.
		interfaces: []Iface{
			{Index: 2, Addr: net.ParseIP("10.0.0.5")},
			{Index: 1, Addr: net.ParseIP("127.0.0.1"), Loopback: true},
		},
	}

	detail := func(name string) string {
		t.Helper()
		for _, c := range srv.Capabilities() {
			if c.Name == name {
				if !c.Enabled {
					t.Fatalf("%s must be enabled in this configuration", name)
				}
				return c.Detail
			}
		}
		t.Fatalf("no %s capability was reported", name)
		return ""
	}

	if d := detail("signing"); !strings.Contains(d, "required") {
		t.Errorf("signing detail = %q, want the required wording", d)
	}
	if d := detail("encryption"); !strings.Contains(d, "required") || !strings.Contains(d, "AES-256 preferred") {
		t.Errorf("encryption detail = %q, want both the requirement and the AES-256 preference", d)
	}
	if d := detail("multichannel"); !strings.Contains(d, "1 interface(s) advertised") {
		t.Errorf("multichannel detail = %q, want only the non-loopback interface counted", d)
	}
	if d := detail("kerberos"); !strings.Contains(d, "cifs/files.example.com") {
		t.Errorf("kerberos detail = %q, want the configured SPN", d)
	}
	if d := detail("leases"); !strings.Contains(d, "handle-caching") {
		t.Errorf("leases detail = %q, want the lease types spelled out", d)
	}
}

// TestServerStats follows the live counters across a real connection: one
// connection, one session, one open handle and one tree.
func TestServerStats(t *testing.T) {
	srv := startTestServer(t, t.TempDir(), nil)

	if got := srv.Stats(); got.Connections != 0 || got.Sessions != 0 || got.Handles != 0 {
		t.Fatalf("an idle server reports %+v", got)
	} else if got.Shares != 1 {
		t.Fatalf("configured shares = %d, want 1", got.Shares)
	}

	c := dialTestClient(t, srv.Addr().String())
	c.establish(0x0302)

	st, dfid := c.create("", fileOpen, 0x1, 0x8000_0000, nil)
	if st != StatusSuccess {
		t.Fatalf("open root status %#x", st)
	}

	got := srv.Stats()
	if got.Connections != 1 {
		t.Errorf("connections = %d, want 1", got.Connections)
	}
	if got.Sessions != 1 {
		t.Errorf("sessions = %d, want 1", got.Sessions)
	}
	if got.Handles != 1 {
		t.Errorf("handles = %d, want 1", got.Handles)
	}
	if got.Trees != 1 {
		t.Errorf("trees = %d, want 1", got.Trees)
	}
	if got.MaxConnections != DefaultMaxConnections {
		t.Errorf("max connections = %d, want %d", got.MaxConnections, DefaultMaxConnections)
	}

	c.close(dfid)
}
