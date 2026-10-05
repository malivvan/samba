package main

import (
	"strings"
	"testing"

	"github.com/malivvan/samba"
)

// runCLI runs the command with no signal channel — every case here either does
// not serve or would be stopped by a signal — and returns the exit status and
// both output streams.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut strings.Builder
	code = run(args, &out, &errOut, nil)
	return code, out.String(), errOut.String()
}

// field returns the value reported for name in the `--check` report: the first
// line whose first column is exactly name (so "encrypt" does not match
// "encryption").
func field(t *testing.T, report, name string) string {
	t.Helper()
	for _, line := range strings.Split(report, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, name)
		if !ok || (rest != "" && rest[0] != ' ') {
			continue
		}
		return strings.TrimSpace(rest)
	}
	t.Fatalf("the report has no %q field:\n%s", name, report)
	return ""
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}} {
		code, out, errOut := runCLI(t, args...)
		if code != 0 {
			t.Fatalf("%v exit = %d", args, code)
		}
		// Every documented flag must be in the help text: the help is the only
		// place a user learns about --dump-config or --list-interfaces.
		for _, want := range []string{
			"usage: samba", "--config", "--check", "--dump-config",
			"--list-dialects", "--list-ciphers", "--list-interfaces",
			"--log-level", "--listen", "--workers", "--version", "--help",
			"SIGINT", "Exit status",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%v: help omits %q", args, want)
			}
		}
		if errOut != "" {
			t.Errorf("%v: help wrote to stderr: %q", args, errOut)
		}
	}
}

// TestListDialectsAndCiphers checks that the negotiation reports come from the
// library rather than from strings written here: every dialect and cipher the
// package publishes must appear.
func TestListDialectsAndCiphers(t *testing.T) {
	code, out, errOut := runCLI(t, "--list-dialects")
	if code != 0 || errOut != "" {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	for _, d := range samba.Dialects() {
		if !strings.Contains(out, d.Name) {
			t.Errorf("--list-dialects omits %s", d.Name)
		}
	}
	// The revision must be printed in wire form, not just the name.
	if !strings.Contains(out, "0x0311") || !strings.Contains(out, "0x0202") {
		t.Errorf("--list-dialects does not print the revision codes:\n%s", out)
	}

	code, out, errOut = runCLI(t, "--list-ciphers")
	if code != 0 || errOut != "" {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	for _, c := range samba.Ciphers() {
		if !strings.Contains(out, c.Name) {
			t.Errorf("--list-ciphers omits %s", c.Name)
		}
	}
	if !strings.Contains(out, "0x0004") || !strings.Contains(out, "256-bit") {
		t.Errorf("--list-ciphers does not print the identifiers and key sizes:\n%s", out)
	}
	for _, a := range samba.SigningAlgorithms() {
		// Only the algorithm name, not the dialect list that follows it.
		name, _, _ := strings.Cut(a, " (")
		if !strings.Contains(out, name) {
			t.Errorf("--list-ciphers omits the %s signature", name)
		}
	}
}

func TestListInterfaces(t *testing.T) {
	want := samba.AdvertisedInterfaces(nil)
	path := writeConfig(t, "multichannel = true\n")
	code, out, errOut := runCLI(t, "--list-interfaces", "--config", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	if !strings.Contains(out, "multichannel advertisement") {
		t.Fatalf("no advertisement header:\n%s", out)
	}
	for _, i := range want {
		if !strings.Contains(out, i.Addr.String()) {
			t.Errorf("--list-interfaces omits %s", i.Addr)
		}
	}
}

// TestListInterfacesHonoursAdvertiseOnly covers the filter an operator uses to
// pin multichannel to one storage NIC: only the listed address may be reported.
func TestListInterfacesHonoursAdvertiseOnly(t *testing.T) {
	all := samba.AdvertisedInterfaces(nil)
	if len(all) < 2 {
		t.Skipf("needs at least two interfaces, host has %d", len(all))
	}
	keep := all[0].Addr.String()
	path := writeConfig(t, "multichannel = true\nadvertise_only = [\""+keep+"\"]\n")
	code, out, errOut := runCLI(t, "--list-interfaces", "--config", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	if !strings.Contains(out, keep) {
		t.Fatalf("advertise_only dropped the wanted address %s:\n%s", keep, out)
	}
	for _, i := range all[1:] {
		if i.Addr.String() != keep && strings.Contains(out, i.Addr.String()) {
			t.Errorf("advertise_only did not filter out %s", i.Addr)
		}
	}
}

func TestCheckReportsCapabilities(t *testing.T) {
	path := writeConfig(t, "workers = 1\nrequire_signing = true\nencrypt = true\n")
	code, out, errOut := runCLI(t, "--check", "--config", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	for _, want := range []string{
		"config ok: 1 share",
		"dialects", "ntlmv2", "kerberos", "guest", "signing", "encryption",
		"multichannel", "leases", "byte-range locks", "change notification",
		"zero-copy reads", "compound requests", "resource limits",
		"required on authenticated sessions",
		"share", "data",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--check omits %q:\n%s", want, out)
		}
	}
	if got := field(t, out, "workers"); got != "1" {
		t.Errorf("workers = %q, want 1", got)
	}
	if got := field(t, out, "require_signing"); got != "true" {
		t.Errorf("require_signing = %q, want true", got)
	}
}

// TestOverridesWinOverConfig covers the three overrides: they must be applied
// on top of the file, and must be visible in the report.
func TestOverridesWinOverConfig(t *testing.T) {
	path := writeConfig(t, "workers = 1\nlog_level = 0\nlisten = \"127.0.0.1:1\"\n")
	code, out, errOut := runCLI(t,
		"--check", "--config", path,
		"--workers", "5", "--log-level", "2", "--listen", "127.0.0.1:4455")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	if got := field(t, out, "workers"); got != "5" {
		t.Errorf("workers = %q, want the override 5", got)
	}
	if got := field(t, out, "log_level"); got != "debug" {
		t.Errorf("log_level = %q, want debug", got)
	}
	if got := field(t, out, "listen"); got != "127.0.0.1:4455" {
		t.Errorf("listen = %q, want the override", got)
	}
}

// TestDumpConfigRedactsSecrets is the important one: --dump-config is meant to
// be attached to a bug report, so it must never print a credential.
func TestDumpConfigRedactsSecrets(t *testing.T) {
	path := writeConfig(t,
		"require_signing = true\n"+
			"[[user]]\nname = \"alice\"\npassword = \"hunter2\"\n"+
			"[[user]]\nname = \"bob\"\nnt_hash = \"8846f7eaee8fb117ad06bdd830b7586c\"\n")
	code, out, errOut := runCLI(t, "--dump-config", "--config", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	for _, secret := range []string{"hunter2", "8846f7eaee8fb117ad06bdd830b7586c"} {
		if strings.Contains(out, secret) {
			t.Fatalf("--dump-config leaked %q:\n%s", secret, out)
		}
	}
	for _, want := range []string{
		"<redacted>", `name = "alice"`, `name = "bob"`,
		"require_signing = true", "listen =", "[[share]]", "[[user]]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--dump-config omits %q:\n%s", want, out)
		}
	}
}

func TestDumpConfigRendersKerberos(t *testing.T) {
	path := writeConfig(t, "[kerberos]\nenabled = false\nspn = \"cifs/files.example.com\"\nkeytab = \"/etc/krb5.keytab\"\n")
	code, out, errOut := runCLI(t, "--dump-config", "--config", path)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	for _, want := range []string{"[kerberos]", "enabled = false", `spn = "cifs/files.example.com"`, `keytab = "/etc/krb5.keytab"`} {
		if !strings.Contains(out, want) {
			t.Errorf("--dump-config omits %q:\n%s", want, out)
		}
	}
}

// TestDescribeMatchesCapabilities is what keeps the banner honest: the report
// the CLI prints and logs must carry every capability the library reports, with
// the matching state and detail. A capability added to the library but not
// surfaced here is exactly the drift this catches.
func TestDescribeMatchesCapabilities(t *testing.T) {
	cfg, err := samba.LoadConfig(writeConfig(t, "workers = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := samba.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := describe(cfg, srv, resolvedWorkers(cfg))

	for _, c := range srv.Srv().Capabilities() {
		state := "off"
		if c.Enabled {
			state = "on"
		}
		found := false
		for _, line := range report {
			// The capability line is the one that starts with the name and
			// carries the detail; the settings lines share some names but never
			// the detail text.
			if !strings.HasPrefix(line, c.Name) || !strings.Contains(line, c.Detail) {
				continue
			}
			found = true
			if !strings.Contains(line, state+" "+c.Detail) {
				t.Errorf("capability %q reports the wrong state: %q", c.Name, line)
			}
		}
		if !found {
			t.Errorf("the report omits capability %q", c.Name)
		}
	}
}
