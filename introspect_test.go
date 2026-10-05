package samba

import (
	"net"
	"runtime"
	"strings"
	"testing"

	"github.com/malivvan/samba/pkg/rangelock"
	"github.com/malivvan/samba/pkg/reuseport"
	"github.com/malivvan/samba/pkg/watch"
	"github.com/malivvan/samba/pkg/zerocopy"
)

// The introspection API exists so the CLI, the docs and the code that acts on
// the values cannot disagree. These tests are what makes that claim true: each
// published list is checked against the code that consumes it, not against
// itself.

// TestDialectsMatchNegotiation pins the published dialect list to the one the
// NEGOTIATE handler searches, including the order (both claim to be the server
// preference), and pins the names `min_dialect` accepts to that same table.
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
		if got[i].Name == "" || got[i].Detail == "" || got[i].Version == "" {
			t.Errorf("Dialects()[%d] (%#x) is missing its name, version or detail", i, got[i].Revision)
		}
		// The configuration spelling must resolve back to this dialect: it is
		// what min_dialect takes and what the CLI prints.
		if d, ok := DialectByName(got[i].Version); !ok || d.Revision != got[i].Revision {
			t.Errorf("DialectByName(%q) = %+v, %t", got[i].Version, d, ok)
		}
	}

	// DialectNames is the same set, oldest first, so an error message reads in
	// the order a user would expect.
	names := DialectNames()
	if len(names) != len(got) {
		t.Fatalf("DialectNames() has %d entries, want %d", len(names), len(got))
	}
	for i, n := range names {
		if want := got[len(got)-1-i].Version; n != want {
			t.Errorf("DialectNames()[%d] = %q, want %q", i, n, want)
		}
	}

	// Anything that is not exactly a version spelling must not resolve, so a
	// typo in min_dialect fails instead of silently taking a default.
	for _, bad := range []string{"", "2.0", "4.0", "SMB 3.0", "3.0 ", "3.1.1.1"} {
		if d, ok := DialectByName(bad); ok {
			t.Errorf("DialectByName(%q) must not resolve, got %+v", bad, d)
		}
	}

	// The two floors name real dialects, and the encryption floor is newer than
	// the default one.
	def := dialectFloorOrPanic(DefaultMinDialect)
	enc := dialectFloorOrPanic(EncryptionMinDialect)
	if enc.Revision <= def.Revision {
		t.Fatalf("the encryption floor %s must be newer than the default floor %s", enc.Version, def.Version)
	}
	if enc.Revision != 0x0300 {
		t.Errorf("the encryption floor is %#x, want SMB 3.0 (0x0300)", enc.Revision)
	}
	// And the invariant `encrypt = true` rests on: everything below the
	// encryption floor is a dialect that has no encryption at all.
	for _, d := range got {
		if d.Revision < enc.Revision && d.Revision >= 0x0300 {
			t.Errorf("%s (%#x) sits below the encryption floor and must be a 2.x dialect", d.Version, d.Revision)
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
	// NTLMv2 is the only mechanism, so it is always on and always says so.
	if !byName["ntlmv2"].Enabled {
		t.Error("ntlmv2 must report on: it is the only mechanism")
	}
	if _, reported := byName["kerberos"]; reported {
		t.Error("Kerberos was removed and must not be reported as a capability")
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
	if d := detail("ntlmv2"); !strings.Contains(d, "NTLM") && !strings.Contains(d, "mechanism") {
		t.Errorf("ntlmv2 detail = %q, want it to describe the only mechanism", d)
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

// TestPlatformFacilitiesMatchThePackages pins the platform report to the
// packages that implement the mechanisms. The report exists so an operator can
// see which mechanism this build got; if it were written out as strings here it
// would keep claiming, say, splice(2) on a host that fell back to the buffered
// copy — which is exactly the silent downgrade the report is for.
func TestPlatformFacilitiesMatchThePackages(t *testing.T) {
	got := PlatformFacilities()
	if len(got) != 4 {
		t.Fatalf("PlatformFacilities() reports %d mechanisms, want 4", len(got))
	}
	byName := make(map[string]Facility, len(got))
	for _, f := range got {
		if _, dup := byName[f.Name]; dup {
			t.Errorf("facility %q is reported twice", f.Name)
		}
		if f.Detail == "" {
			t.Errorf("facility %q has no detail", f.Name)
		}
		byName[f.Name] = f
	}

	// Listeners: the fallback is a single shared socket.
	listen, ok := byName["platform listeners"]
	if !ok {
		t.Fatal("the listener mechanism is not reported")
	}
	if listen.Native != reuseport.Available() {
		t.Errorf("listeners report native=%v, reuseport.Available()=%v",
			listen.Native, reuseport.Available())
	}

	// Change notification: the mechanism name is the package's own.
	notify := byName["platform notify"]
	if notify.Detail != watch.Backend() {
		t.Errorf("notify detail = %q, watch.Backend() = %q", notify.Detail, watch.Backend())
	}
	if notify.Native != watch.Supported() {
		t.Errorf("notify reports native=%v, watch.Supported()=%v", notify.Native, watch.Supported())
	}

	// Locks: the mechanism name is the package's own, and "in-process" is the
	// one that is a degradation rather than a second native mechanism.
	locks := byName["platform locks"]
	if locks.Detail != rangelock.Backend() {
		t.Errorf("lock detail = %q, rangelock.Backend() = %q", locks.Detail, rangelock.Backend())
	}
	if want := rangelock.Backend() != "in-process"; locks.Native != want {
		t.Errorf("locks report native=%v, want %v for backend %q", locks.Native, want, rangelock.Backend())
	}
	if locks.Fallbacks != rangelock.Degraded() {
		t.Errorf("locks report %d degraded handles, the package has %d", locks.Fallbacks, rangelock.Degraded())
	}
	if locks.Native && !strings.Contains(lockDetail(), "locks") {
		t.Errorf("the lock capability detail %q does not name the mechanism", lockDetail())
	}
	if !locks.Native && !strings.Contains(lockDetail(), "local processes") {
		t.Errorf("the lock capability detail %q must warn that local processes are not covered", lockDetail())
	}

	// Zero-copy reads: same rule, plus the runtime fallback counter.
	copyF := byName["platform copy"]
	if copyF.Detail != zerocopy.Backend() {
		t.Errorf("copy detail = %q, zerocopy.Backend() = %q", copyF.Detail, zerocopy.Backend())
	}
	if want := zerocopy.Backend() != "buffered"; copyF.Native != want {
		t.Errorf("copy reports native=%v, want %v for backend %q", copyF.Native, want, zerocopy.Backend())
	}
	if copyF.Fallbacks != zerocopy.Fallbacks() {
		t.Errorf("copy reports %d fallbacks, the package has %d", copyF.Fallbacks, zerocopy.Fallbacks())
	}
	if _, ok := byName["platform copy"]; !ok {
		t.Error("the copy mechanism is not reported")
	}

	// The platform name is the GOOS/GOARCH spelling the support table uses.
	if want := runtime.GOOS + "/" + runtime.GOARCH; PlatformName() != want {
		t.Errorf("PlatformName() = %q, want %q", PlatformName(), want)
	}
}

// TestCapabilitiesNameTheHostMechanism checks that a capability whose behaviour
// depends on the host describes the mechanism this build actually has — the
// difference between "byte-range locks: on" and "locks not enforced against local
// processes".
func TestCapabilitiesNameTheHostMechanism(t *testing.T) {
	// Every backend a package can report must have a phrase in the capability
	// detail, so a platform can never end up describing a mechanism it does not
	// have. The mapping is explicit rather than "the detail contains the backend
	// name", because the capability text is prose ("open-file-description locks"
	// for the backend reported as "OFD").
	lockPhrase := map[string]string{
		"OFD":        "open-file-description locks",
		"LockFileEx": "LockFileEx locks",
		"in-process": "local processes",
	}
	if want, ok := lockPhrase[rangelock.Backend()]; !ok {
		t.Fatalf("rangelock.Backend() = %q has no phrase in the capability detail", rangelock.Backend())
	} else if !strings.Contains(lockDetail(), want) {
		t.Errorf("the lock detail %q does not mention %q", lockDetail(), want)
	}

	notifyPhrase := map[string]string{
		"inotify":               "inotify",
		"ReadDirectoryChangesW": "ReadDirectoryChangesW",
		"kqueue":                "kqueue",
		"poll":                  "polling",
	}
	if want, ok := notifyPhrase[watch.Backend()]; !ok {
		t.Fatalf("watch.Backend() = %q has no phrase in the capability detail", watch.Backend())
	} else if !strings.Contains(notifyDetail(), want) {
		t.Errorf("the notify detail %q does not mention %q", notifyDetail(), want)
	}

	copyPhrase := map[string]string{
		"splice":   "splice(2)",
		"sendfile": "sendfile(2)",
		"buffered": "buffered copy",
	}
	if want, ok := copyPhrase[zerocopy.Backend()]; !ok {
		t.Fatalf("zerocopy.Backend() = %q has no phrase in the capability detail", zerocopy.Backend())
	} else if !strings.Contains(zeroCopyDetail(), want) {
		t.Errorf("the zero-copy detail %q does not mention %q", zeroCopyDetail(), want)
	}

	// And the platform whose mechanisms the README table names explicitly must
	// describe exactly those, because that is the claim the table makes.
	if runtime.GOOS == "linux" {
		if rangelock.Backend() != "OFD" || watch.Backend() != "inotify" || zerocopy.Backend() != "splice" {
			t.Errorf("Linux reports %s/%s/%s, want OFD/inotify/splice",
				rangelock.Backend(), watch.Backend(), zerocopy.Backend())
		}
	}
}
