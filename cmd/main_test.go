package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// writeConfig writes a minimal valid configuration for a temp share.
func writeConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	share := filepath.Join(dir, "share")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "samba.toml")
	body := extra + "[[share]]\nname = \"data\"\npath = \"" + share + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunVersion(t *testing.T) {
	var out, errOut strings.Builder
	if code := run([]string{"--version"}, &out, &errOut, nil); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.HasPrefix(out.String(), "samba ") {
		t.Fatalf("stdout = %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q", errOut.String())
	}
	// -V is the same.
	out.Reset()
	if code := run([]string{"-V"}, &out, &errOut, nil); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
}

func TestRunCheck(t *testing.T) {
	path := writeConfig(t, "log_level = 0\n")
	var out, errOut strings.Builder
	if code := run([]string{"--check", "--config", path}, &out, &errOut, nil); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "config ok: 1 share") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestRunUsageErrors(t *testing.T) {
	cases := [][]string{
		{"--nope"},
		{"--config"},
		{"extra-argument"},
	}
	for _, args := range cases {
		var out, errOut strings.Builder
		if code := run(args, &out, &errOut, nil); code != 2 {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
		if !strings.Contains(errOut.String(), "usage:") {
			t.Errorf("run(%v) stderr = %q", args, errOut.String())
		}
	}
}

func TestRunConfigErrors(t *testing.T) {
	var out, errOut strings.Builder
	// A missing file.
	if code := run([]string{"--config", filepath.Join(t.TempDir(), "absent.toml")}, &out, &errOut, nil); code != 2 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(errOut.String(), "cannot read config") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	// A malformed file.
	bad := filepath.Join(t.TempDir(), "bad.toml")
	if err := os.WriteFile(bad, []byte("= = =\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := run([]string{"--config", bad}, &out, &errOut, nil); code != 2 {
		t.Fatalf("exit code = %d", code)
	}
}

// TestRunServesAndStops runs the real server path: it starts listening and
// stops cleanly when the signal channel closes.
func TestRunServesAndStops(t *testing.T) {
	path := writeConfig(t, "workers = 1\nlog_level = 0\nlisten = \"127.0.0.1:0\"\n")
	sigs := make(chan os.Signal, 1)
	done := make(chan int, 1)
	var out, errOut strings.Builder
	go func() { done <- run([]string{"--config", path}, &out, &errOut, sigs) }()

	// Let it come up, then ask it to stop.
	sigs <- syscall.SIGTERM
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
		}
	case <-timeoutAfter(t, 20):
		t.Fatal("the server did not stop")
	}
}

// TestRunStartupFailure checks that a configuration the server cannot serve
// fails fast with a diagnostic rather than starting half-way.
// TestRunRejectsRemovedAuthSettings is the migration guard: a configuration
// written for the Kerberos-capable build carries `auth` and `[kerberos]`, which
// are no longer known keys. It must fail loudly at startup rather than start
// with the operator's authentication policy silently dropped.
func TestRunRejectsRemovedAuthSettings(t *testing.T) {
	for _, extra := range []string{
		"auth = \"kerberos\"\n",
		"auth = \"both\"\n",
		"[kerberos]\nkeytab = \"/etc/krb5.keytab\"\nspn = \"cifs/files.example.com\"\n",
	} {
		path := writeConfig(t, extra)
		var out, errOut strings.Builder
		if code := run([]string{"--config", path}, &out, &errOut, nil); code != 2 {
			t.Errorf("%q: exit code = %d, want 2", extra, code)
		}
		if !strings.Contains(errOut.String(), "unknown key") {
			t.Errorf("%q: stderr = %q, want the unknown key named", extra, errOut.String())
		}
	}
}

// TestRunLogsServingDetails covers the informational path (users, multichannel
// advertisement) as well as the clean shutdown.
func TestRunLogsServingDetails(t *testing.T) {
	path := writeConfig(t, "workers = 1\nlog_level = 0\nlisten = \"127.0.0.1:0\"\nmultichannel = true\nallow_guest = false\n[[user]]\nname = \"alice\"\npassword = \"secret\"\n")
	sigs := make(chan os.Signal, 1)
	done := make(chan int, 1)
	var out, errOut strings.Builder
	go func() { done <- run([]string{"--config", path}, &out, &errOut, sigs) }()
	close(sigs) // a closed channel stops the server
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
		}
	case <-timeoutAfter(t, 20):
		t.Fatal("the server did not stop")
	}
}
