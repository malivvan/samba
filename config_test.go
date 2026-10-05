package samba

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	raw := "[[share]]\nname = \"data\"\npath = \"" + dir + "\"\n"
	cfg, err := ParseConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.ServerName != DefaultServerName {
		t.Errorf("server_name = %q", cfg.ServerName)
	}
	if cfg.LogLevel != LevelInfo {
		t.Errorf("log_level = %d", cfg.LogLevel)
	}
	if !cfg.Oplocks {
		t.Error("oplocks must default on")
	}
	if cfg.Auth != AuthBoth {
		t.Errorf("auth = %q", cfg.Auth)
	}
	if !cfg.GuestAllowed() {
		t.Error("guest must be allowed when no users are defined")
	}
	if _, err := cfg.ListenAddr(); err != nil {
		t.Errorf("listen_addr: %v", err)
	}
}

func TestConfigRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	raw := "[[share]]\nname = \"data\"\npath = \"" + dir + "\"\ntypo_key = 1\n"
	if _, err := ParseConfig([]byte(raw)); err == nil {
		t.Fatal("an unknown key must be rejected")
	}
	// And the io_uring-only knobs the port dropped must not silently load.
	for _, key := range []string{"sqpoll = true\n", "core_pinning = true\n"} {
		raw := key + "[[share]]\nname = \"data\"\npath = \"" + dir + "\"\n"
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Fatalf("%q must be rejected as an unknown key", key)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	dir := t.TempDir()

	if _, err := ParseConfig([]byte("")); err == nil {
		t.Fatal("a config with no share must be rejected")
	}
	cases := []string{
		"[[share]]\nname = \"\"\npath = \"" + dir + "\"\n",
		"[[share]]\nname = \"a/b\"\npath = \"" + dir + "\"\n",
		"[[share]]\nname = \"IPC$\"\npath = \"" + dir + "\"\n",
		"[[share]]\nname = \"a\"\npath = \"" + filepath.Join(dir, "nope") + "\"\n",
		"[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n[[share]]\nname = \"A\"\npath = \"" + dir + "\"\n",
		"listen = \"not-an-address\"\n[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n",
		"auth = \"krb5\"\n[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n",
		"[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n[[user]]\nname = \"u\"\n",
		"[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n[[user]]\nname = \"u\"\npassword = \"p\"\nnt_hash = \"" + "aa" + "\"\n",
		"[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n[[user]]\nname = \"u\"\nnt_hash = \"zz\"\n",
	}
	for _, raw := range cases {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Errorf("config must be rejected:\n%s", raw)
		}
	}
}

func TestConfigUserDB(t *testing.T) {
	dir := t.TempDir()
	raw := "[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n" +
		"[[user]]\nname = \"Alice\"\npassword = \"secret\"\n" +
		"[[user]]\nname = \"bob\"\nnt_hash = \"8846f7eaee8fb117ad06bdd830b7586c\"\n"
	cfg, err := ParseConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	users, err := cfg.UserDB()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("user db has %d entries", len(users))
	}
	// Names are lowercased and passwords are hashed.
	want := ntHash("secret")
	if got, ok := users["alice"]; !ok || got != want {
		t.Fatalf("alice = %x, %v", got, ok)
	}
	if got, ok := users["bob"]; !ok || got != ntHash("password") {
		t.Fatalf("bob = %x", got)
	}
	// A user table turns guest off by default.
	if cfg.GuestAllowed() {
		t.Error("guest must default off when users are defined")
	}
}

func TestConfigGuestOptIn(t *testing.T) {
	dir := t.TempDir()
	raw := "allow_guest = true\n[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n[[user]]\nname = \"u\"\npassword = \"p\"\n"
	cfg, err := ParseConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.GuestAllowed() {
		t.Error("allow_guest = true must be honored")
	}
}

// TestShippedExampleConfigLoads is the guard test for the released example
// config: the file that ships must parse and validate as-is.
func TestShippedExampleConfigLoads(t *testing.T) {
	raw, err := os.ReadFile("samba.toml.example")
	if err != nil {
		t.Fatalf("the example config must exist: %v", err)
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// The example points at real paths; rewrite them to the temp dir so the
	// structure, keys and types are what is validated.
	patched := strings.ReplaceAll(string(raw), `path = "/srv/data"`, `path = "`+sub+`"`)
	cfg, err := ParseConfig([]byte(patched))
	if err != nil {
		t.Fatalf("the example config must load: %v", err)
	}
	if len(cfg.Shares) == 0 {
		t.Fatal("the example config must define a share")
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "samba.toml")
	if err := os.WriteFile(path, []byte("[[share]]\nname = \"s\"\npath = \""+dir+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Shares) != 1 || cfg.Shares[0].Name != "s" {
		t.Fatalf("shares = %+v", cfg.Shares)
	}
	// A missing file is an error, with the path in the message.
	if _, err := LoadConfig(filepath.Join(dir, "absent.toml")); err == nil {
		t.Fatal("a missing config file must be an error")
	}
	// A malformed file is an error too.
	bad := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bad, []byte("this is not = toml = at all\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(bad); err == nil {
		t.Fatal("a malformed config must be an error")
	}
}

func TestConfigListenAddr(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"0.0.0.0:445", false},
		{"127.0.0.1:1445", false},
		{"[::1]:445", false},
		{":445", false},
		{"no-port", true},
		{"not-an-ip:445", true},
		{"", true},
	}
	for _, c := range cases {
		cfg := &Config{}
		*cfg = newConfig()
		cfg.Listen = c.in
		got, err := cfg.ListenAddr()
		if c.wantErr {
			if err == nil {
				t.Errorf("ListenAddr(%q) = %q, want an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ListenAddr(%q): %v", c.in, err)
		}
	}
}

func TestConfigUserDBBadHash(t *testing.T) {
	dir := t.TempDir()
	// ParseConfig's validator already rejects a non-hex hash, so this covers the
	// resolver's own guard for a Config a library user built by hand.
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Shares = []ShareCfg{{Name: "a", Path: dir}}
	cfg.Users = []UserCfg{{Name: "u", NTHash: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}}
	if _, err := cfg.UserDB(); err == nil {
		t.Fatal("a non-hex nt_hash must be rejected when resolved")
	}
	// As does a hash of the wrong decoded length.
	cfg.Users = []UserCfg{{Name: "u", NTHash: "aabb"}}
	if _, err := cfg.UserDB(); err == nil {
		t.Fatal("a short nt_hash must be rejected when resolved")
	}
	// The valid form resolves to the same bytes as the password it matches.
	cfg.Users = []UserCfg{{Name: "u", NTHash: "8846f7eaee8fb117ad06bdd830b7586c"}}
	users, err := cfg.UserDB()
	if err != nil {
		t.Fatal(err)
	}
	if users["u"] != ntHash("password") {
		t.Fatal("the nt_hash must resolve to the same 16 bytes")
	}
}

func TestConfigValidationMore(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		// A share path that is a file, not a directory.
		"[[share]]\nname = \"a\"\npath = \"" + file + "\"\n",
		// Two users with the same name (differing only in case).
		"[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n" +
			"[[user]]\nname = \"Bob\"\npassword = \"p\"\n" +
			"[[user]]\nname = \"bob\"\npassword = \"q\"\n",
		// An empty user name.
		"[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n[[user]]\nname = \"\"\npassword = \"p\"\n",
		// An nt_hash of the wrong length.
		"[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n[[user]]\nname = \"u\"\nnt_hash = \"abcd\"\n",
		// Both a password and a hash.
		"[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n[[user]]\nname = \"u\"\npassword = \"p\"\nnt_hash = \"8846f7eaee8fb117ad06bdd830b7586c\"\n",
	}
	for _, raw := range cases {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Errorf("config should be rejected:\n%s", raw)
		}
	}
}

func TestConfigGuestAndLimits(t *testing.T) {
	dir := t.TempDir()
	// An explicit allow_guest = false with no users.
	raw := "allow_guest = false\n[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n"
	cfg, err := ParseConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GuestAllowed() {
		t.Fatal("allow_guest = false must be honored")
	}
	// Limits default, and can be overridden (including to unlimited).
	if cfg.MaxConnections == nil || *cfg.MaxConnections != DefaultMaxConnections {
		t.Fatalf("max_connections default = %v", cfg.MaxConnections)
	}
	raw = "max_connections = 7\n[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n"
	cfg, err = ParseConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConnections == nil || *cfg.MaxConnections != 7 {
		t.Fatalf("max_connections = %v, want 7", cfg.MaxConnections)
	}
	raw = "max_connections = -1\n[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n"
	if _, err := ParseConfig([]byte(raw)); err != nil {
		t.Fatalf("a negative max_connections means unlimited: %v", err)
	}
	// A hand-built Config with no limits set still gets the default.
	hand := &Config{}
	*hand = newConfig()
	hand.MaxConnections = nil
	hand.Shares = []ShareCfg{{Name: "a", Path: dir}}
	srv, err := NewServer(hand)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Srv().conns.limit != DefaultMaxConnections {
		t.Fatalf("limit = %d, want the default", srv.Srv().conns.limit)
	}
}

func TestSrvAccessors(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Shares = []ShareCfg{{Name: "a", Path: dir}}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := srv.Srv()
	if s.Config() == nil || s.Config().ServerName != cfg.ServerName {
		t.Fatal("Config must expose the resolved configuration")
	}
	if s.MaxRead() != MaxReadTarget {
		t.Fatalf("MaxRead = %d", s.MaxRead())
	}
	if g := s.GUID(); g == ([16]byte{}) {
		t.Fatal("the server GUID must be random, not zero")
	}
	if s.Sessions() == nil || s.Leases() == nil {
		t.Fatal("Sessions and Leases must be present")
	}
	// An advertise_only list filters the interface list deterministically.
	cfg2 := &Config{}
	*cfg2 = newConfig()
	cfg2.Shares = []ShareCfg{{Name: "a", Path: dir}}
	cfg2.AdvertiseOnly = []string{"192.0.2.1"} // not a local address
	srv2, err := NewServer(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if got := srv2.Srv().Interfaces(); len(got) != 0 {
		t.Fatalf("advertise_only must filter everything out here, got %+v", got)
	}
	// With nothing configured, the interfaces are those of the host.
	if got := s.Interfaces(); got == nil {
		t.Fatal("Unfiltered Interfaces returned non-nil")
	}
}

func TestConfigKerberosTable(t *testing.T) {
	dir := t.TempDir()
	raw := "auth = \"kerberos\"\n[kerberos]\nkeytab = \"/tmp/kt\"\nspn = \"cifs/x\"\nrealm = \"R\"\n" +
		"[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n"
	cfg, err := ParseConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Auth.AllowsKerberos() || cfg.Auth.AllowsNTLM() {
		t.Fatalf("auth = %q", cfg.Auth)
	}
	if cfg.Kerberos == nil || cfg.Kerberos.Keytab != "/tmp/kt" || cfg.Kerberos.SPN != "cifs/x" || cfg.Kerberos.Realm != "R" {
		t.Fatalf("kerberos table = %+v", cfg.Kerberos)
	}
	if cfg.Kerberos.Enabled != nil {
		t.Fatal("enabled must default to unset (meaning true)")
	}
	// An unknown key inside the table is rejected.
	raw = "[kerberos]\nnope = 1\n[[share]]\nname = \"a\"\npath = \"" + dir + "\"\n"
	if _, err := ParseConfig([]byte(raw)); err == nil {
		t.Fatal("an unknown [kerberos] key must be rejected")
	}
}
