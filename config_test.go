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
