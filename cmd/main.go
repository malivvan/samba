// Command samba is a from-scratch SMB2/SMB3 file server.
//
// It speaks SMB 2.0.2 through 3.1.1 with NTLMv2 authentication, SMB2/3 signing,
// SMB 3.1.1 preauth integrity, SMB3 multichannel, and SMB3 encryption
// (AES-128/256-GCM and -CCM), plus
// byte-range locks, leases, directory change notification and zero-copy reads.
// It is written in pure Go — no CGO, no unsafe — so the whole server is
// statically linkable and memory safe.
//
// Besides serving, the command is a window onto everything the package can do:
// --check reports the resolved configuration, every capability the server would
// advertise and the platform mechanisms it was built to use, --dump-config prints
// the resolved configuration, the --list-* flags report the negotiation facts,
// and the startup banner logs all of it. Those reports come from the library's
// introspection API (samba.Capabilities, samba.Dialects, samba.Ciphers,
// samba.PlatformFacilities), never from strings duplicated here, so the CLI cannot
// drift from the server it describes.
//
// Usage:
//
//	samba [--config <path>] [--check] [--version]
package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/malivvan/samba"
)

const usage = "usage: samba [options]"

const help = `samba — a from-scratch SMB2/SMB3 file server.

` + usage + `

  -c, --config <path>     TOML configuration file (default ./samba.toml)
      --check             validate the configuration, report what it enables,
                          and exit
      --dump-config       print the resolved configuration (secrets redacted)
                          and exit
      --list-dialects     print the SMB dialects this build negotiates and exit
      --list-ciphers      print the SMB3 ciphers it supports and exit
      --list-interfaces   print the multichannel interface advertisement and
                          exit
      --list-platform     print the platform mechanisms this build uses
                          (listeners, change notification, locks, zero-copy
                          reads) and exit
      --log-level <n>     override log_level: 0 warn, 1 info, 2 debug
      --listen <addr>     override listen
      --workers <n>       override workers (0 = one per CPU core)
  -V, --version           print the version and exit
  -h, --help              print this help and exit

The overrides are applied on top of the configuration file, so they win.

Exit status: 0 after a clean shutdown; 2 for a usage, configuration or startup
error. SIGINT and SIGTERM stop the server: listeners close, connections drain,
and the workers are waited for before the process exits.
`

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, sigs))
}

// options is the parsed command line. A negative logLevel or workers means
// "not given", so the configuration file decides.
type options struct {
	configPath     string
	check          bool
	dumpConfig     bool
	listDialects   bool
	listCiphers    bool
	listInterfaces bool
	listPlatform   bool
	help           bool
	version        bool
	logLevel       int
	listen         string
	workers        int
}

// run parses the command line, acts on it, and returns the process exit status:
// 0 for success, 2 for a usage, configuration or startup error.
//
// Everything it reports goes to the given writers, and the signal channel is
// injected, so the whole command is testable without a process, a terminal or a
// real signal.
func run(args []string, stdout, stderr io.Writer, sigs <-chan os.Signal) int {
	opt, err := parseArgs(args)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	switch {
	case opt.help:
		fmt.Fprint(stdout, help)
		return 0
	case opt.version:
		fmt.Fprintf(stdout, "samba %s\n", samba.Version)
		return 0
	case opt.listDialects:
		printDialects(stdout)
		return 0
	case opt.listCiphers:
		printCiphers(stdout)
		return 0
	case opt.listPlatform:
		printPlatform(stdout)
		return 0
	}

	cfg, err := samba.LoadConfig(opt.configPath)
	if err != nil {
		return fail(stderr, err.Error())
	}
	// Command-line overrides win over the file.
	if opt.logLevel >= 0 {
		cfg.LogLevel = uint8(opt.logLevel)
	}
	if opt.listen != "" {
		cfg.Listen = opt.listen
	}
	if opt.workers >= 0 {
		cfg.Workers = opt.workers
	}
	samba.SetLogLevel(cfg.LogLevel)

	switch {
	case opt.listInterfaces:
		printInterfaces(stdout, cfg)
		return 0
	case opt.dumpConfig:
		printConfig(stdout, cfg)
		return 0
	case opt.check:
		return check(stdout, stderr, cfg)
	}
	if err := serve(cfg, sigs); err != nil {
		return fail(stderr, err.Error())
	}
	return 0
}

// parseArgs turns the argument list into options. It takes the long and short
// spellings, `--name value` only (a bare `--flag=value` is an unknown
// argument), and rejects anything it does not understand rather than guessing.
func parseArgs(args []string) (options, error) {
	opt := options{configPath: "samba.toml", logLevel: -1, workers: -1}
	next := func(i *int) (string, bool) {
		if *i+1 >= len(args) {
			return "", false
		}
		*i++
		return args[*i], true
	}
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "--config", "-c":
			v, ok := next(&i)
			if !ok {
				return opt, fmt.Errorf("%s needs a path", arg)
			}
			opt.configPath = v
		case "--log-level":
			v, ok := next(&i)
			if !ok {
				return opt, fmt.Errorf("%s needs a value", arg)
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 2 {
				return opt, fmt.Errorf("--log-level takes 0 (warn), 1 (info) or 2 (debug), not %q", v)
			}
			opt.logLevel = n
		case "--listen":
			v, ok := next(&i)
			if !ok {
				return opt, fmt.Errorf("%s needs an address", arg)
			}
			opt.listen = v
		case "--workers":
			v, ok := next(&i)
			if !ok {
				return opt, fmt.Errorf("%s needs a count", arg)
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return opt, fmt.Errorf("--workers takes a non-negative count, not %q", v)
			}
			opt.workers = n
		case "--check":
			opt.check = true
		case "--dump-config":
			opt.dumpConfig = true
		case "--list-dialects":
			opt.listDialects = true
		case "--list-ciphers":
			opt.listCiphers = true
		case "--list-interfaces":
			opt.listInterfaces = true
		case "--list-platform":
			opt.listPlatform = true
		case "--version", "-V":
			opt.version = true
		case "--help", "-h":
			opt.help = true
		default:
			return opt, fmt.Errorf("unknown argument %q", arg)
		}
	}
	return opt, nil
}

// usageError reports a command-line problem.
func usageError(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "samba: %s\n%s\nrun 'samba --help' for the options\n", msg, usage)
	return 2
}

// fail reports a configuration or startup problem.
func fail(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "samba: %s\n", msg)
	return 2
}

// resolvedWorkers is the listener count the server will actually use: the
// configured value, or one per CPU core when it is 0 (or absent).
func resolvedWorkers(cfg *samba.Config) int {
	if cfg.Workers > 0 {
		return cfg.Workers
	}
	return runtime.NumCPU()
}

// describe renders everything the server will advertise — the resolved settings
// and every capability — as plain lines.
//
// `--check` prints them, the startup banner logs them, and the tests read them,
// so the three cannot disagree about what a configuration means. The capability
// lines come straight from the library's samba.Capabilities, which describes
// the same server the negotiation code acts on.
func describe(cfg *samba.Config, srv *samba.Server, workers int) []string {
	conns := strconv.Itoa(samba.DefaultMaxConnections)
	if cfg.MaxConnections != nil {
		switch n := *cfg.MaxConnections; {
		case n < 0:
			conns = "unlimited"
		default:
			conns = strconv.Itoa(n)
		}
	}

	line := func(name, value string) string {
		return fmt.Sprintf("%-20s %s", name, value)
	}

	lines := []string{
		line("listen", cfg.Listen),
		line("workers", strconv.Itoa(workers)),
		line("server_name", cfg.ServerName),
		line("max_read", strconv.Itoa(int(samba.MaxReadTarget)/1024)+" KiB"),
		line("max_connections", conns),
		line("min_dialect", dialectFloorText(cfg)),
		line("log_level", logLevelName(cfg.LogLevel)),
		line("allow_guest", strconv.FormatBool(cfg.GuestAllowed())),
		line("require_signing", strconv.FormatBool(cfg.RequireSigning)),
		line("encrypt", strconv.FormatBool(cfg.Encrypt)),
		line("prefer_aes256", strconv.FormatBool(cfg.PreferAES256)),
		line("multichannel", strconv.FormatBool(cfg.Multichannel)),
		line("oplocks", strconv.FormatBool(cfg.Oplocks)),
	}
	for _, c := range srv.Srv().Capabilities() {
		state := "off"
		if c.Enabled {
			state = "on"
		}
		lines = append(lines, line(c.Name, fmt.Sprintf("%s %s", state, c.Detail)))
	}
	// The platform mechanisms a capability depends on are reported next to the
	// capabilities, so a `--check` on a host whose kernel cannot do one of them
	// says so instead of implying the server has it.
	for _, f := range samba.PlatformFacilities() {
		how := "native"
		if !f.Native {
			how = "fallback"
		}
		lines = append(lines, line(f.Name, fmt.Sprintf("%s %s", how, f.Detail)))
	}
	for _, sh := range cfg.Shares {
		mode := "read-write"
		if sh.ReadOnly {
			mode = "read-only"
		}
		lines = append(lines, line("share", fmt.Sprintf("%s -> %s (%s)", sh.Name, sh.Path, mode)))
	}
	for _, u := range cfg.Users {
		how := "password"
		if u.Password == "" {
			how = "nt_hash"
		}
		lines = append(lines, line("user", fmt.Sprintf("%s (%s)", u.Name, how)))
	}
	return lines
}

// check validates the configuration the way startup would, reports everything
// it enables, and exits without binding anything.
//
// It builds the real server context (samba.NewServer), so a configuration that
// cannot start — an unusable keytab, a bad bind address, a malformed user
// database — fails here exactly as it would at startup.
func check(stdout, stderr io.Writer, cfg *samba.Config) int {
	srv, err := samba.NewServer(cfg)
	if err != nil {
		return fail(stderr, err.Error())
	}
	fmt.Fprintf(stdout, "config ok: %d share(s)\n", len(cfg.Shares))
	for _, line := range describe(cfg, srv, resolvedWorkers(cfg)) {
		fmt.Fprintf(stdout, "  %s\n", line)
	}
	return 0
}

// serve runs the server until sigs yields a signal or is closed.
func serve(cfg *samba.Config, sigs <-chan os.Signal) error {
	srv, err := samba.NewServer(cfg)
	if err != nil {
		return err
	}
	workers := resolvedWorkers(cfg)
	for _, line := range describe(cfg, srv, workers) {
		samba.LogInfo("  %s", line)
	}
	if err := srv.Start(); err != nil {
		return err
	}
	samba.LogInfo("samba %s listening on %s (%d workers, max_read %d KiB)",
		samba.Version, srv.Addr(), workers, samba.MaxReadTarget/1024)
	if sigs != nil {
		<-sigs
	}
	start := time.Now()
	samba.LogInfo("shutting down")
	srv.Stop()
	srv.Wait()
	samba.LogInfo("stopped in %s", time.Since(start).Round(time.Millisecond))
	return nil
}

// printDialects reports the negotiation facts, straight from the library.
func printDialects(w io.Writer) {
	fmt.Fprintln(w, "SMB dialects this build negotiates, newest first (the NEGOTIATE preference order):")
	for _, d := range samba.Dialects() {
		fmt.Fprintf(w, "  %-11s 0x%04x  %s\n", d.Name, d.Revision, d.Detail)
	}
	fmt.Fprintln(w, "\nThe server picks the first of these the client offers.")
}

// printCiphers reports the encryption and signing facts, straight from the
// library.
func printCiphers(w io.Writer) {
	fmt.Fprintln(w, "SMB3 encryption ciphers, strongest first (the order prefer_aes256 applies):")
	for _, c := range samba.Ciphers() {
		fmt.Fprintf(w, "  %-12s 0x%04x  %d-bit\n", c.Name, c.ID, c.KeyBits)
	}
	fmt.Fprintln(w, "\nWithout prefer_aes256 the client's own order is honored.")
	fmt.Fprintln(w, "Signing:")
	for _, a := range samba.SigningAlgorithms() {
		fmt.Fprintf(w, "  %s\n", a)
	}
}

// printPlatform reports the mechanisms the host provides, straight from the
// library.
//
// It exists because four parts of the server cannot be implemented in Go alone —
// sharing a listening port, watching a directory, locking a byte range, and
// moving file bytes to a socket — and each has a native answer on some platforms
// and a documented fallback on others. Printing which one this binary got is how
// an operator finds out that, say, locks are not being enforced against local
// processes on this host.
func printPlatform(w io.Writer) {
	fmt.Fprintf(w, "platform mechanisms in use (%s):\n", samba.PlatformName())
	for _, f := range samba.PlatformFacilities() {
		how := "native"
		if !f.Native {
			how = "fallback"
		}
		line := fmt.Sprintf("  %-20s %-8s %s", f.Name, how, f.Detail)
		if f.Fallbacks > 0 {
			line += fmt.Sprintf(" (%d runtime fallback(s))", f.Fallbacks)
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "\nA fallback is documented, not a failure: it says what the host could not provide.")
	fmt.Fprintln(w, "The consequences per platform are in the README support table.")
}

// printInterfaces reports the multichannel advertisement: the interfaces a
// client is told about after the advertise_only filter, with the link speeds it
// uses to decide how many channels to open.
func printInterfaces(w io.Writer, cfg *samba.Config) {
	ifaces := samba.AdvertisedInterfaces(cfg.AdvertiseOnly)
	filter := "all"
	if len(cfg.AdvertiseOnly) > 0 {
		filter = strings.Join(cfg.AdvertiseOnly, ", ")
	}
	fmt.Fprintf(w, "multichannel advertisement (advertise_only = %s):\n", filter)
	if !cfg.Multichannel {
		fmt.Fprintln(w, "  note: multichannel = false, so this list is not advertised")
	}
	if len(ifaces) == 0 {
		fmt.Fprintln(w, "  (no interfaces)")
		return
	}
	fmt.Fprintf(w, "  %-5s %-40s %-12s %-6s %s\n", "index", "address", "speed", "caps", "loopback")
	for _, i := range ifaces {
		var caps []string
		if i.Capability&samba.IfaceCapRSS != 0 {
			caps = append(caps, "rss")
		}
		if i.Capability&samba.IfaceCapRDMA != 0 {
			caps = append(caps, "rdma")
		}
		loopback := "no"
		if i.Loopback {
			loopback = "yes"
		}
		fmt.Fprintf(w, "  %-5d %-40s %-12s %-6s %s\n",
			i.Index, i.Addr.String(), speedText(i.Speed), strings.Join(caps, ","), loopback)
	}
}

// printConfig prints the resolved configuration as TOML, with every secret
// redacted. It is a report for a human or a bug report, not a usable config.
func printConfig(w io.Writer, cfg *samba.Config) {
	fmt.Fprintf(w, "# samba %s resolved configuration\n", samba.Version)
	fmt.Fprintln(w, "# Secrets are redacted: this is a report, not a usable config.")
	fmt.Fprintf(w, "listen = %q\n", cfg.Listen)
	fmt.Fprintf(w, "workers = %d\n", cfg.Workers)
	if cfg.Workers <= 0 {
		fmt.Fprintf(w, "# resolved: %d worker(s), one per CPU core\n", runtime.NumCPU())
	}
	fmt.Fprintf(w, "server_name = %q\n", cfg.ServerName)
	fmt.Fprintf(w, "log_level = %d\n", cfg.LogLevel)
	fmt.Fprintf(w, "allow_guest = %t\n", cfg.GuestAllowed())
	fmt.Fprintf(w, "require_signing = %t\n", cfg.RequireSigning)
	fmt.Fprintf(w, "encrypt = %t\n", cfg.Encrypt)
	fmt.Fprintf(w, "prefer_aes256 = %t\n", cfg.PreferAES256)
	fmt.Fprintf(w, "multichannel = %t\n", cfg.Multichannel)
	fmt.Fprintf(w, "oplocks = %t\n", cfg.Oplocks)
	if cfg.MaxConnections != nil {
		fmt.Fprintf(w, "max_connections = %d\n", *cfg.MaxConnections)
	}
	if cfg.MinDialect != "" {
		fmt.Fprintf(w, "min_dialect = %q\n", cfg.MinDialect)
	}
	if len(cfg.AdvertiseOnly) > 0 {
		fmt.Fprintf(w, "advertise_only = [%s]\n", quoteList(cfg.AdvertiseOnly))
	}

	for _, sh := range cfg.Shares {
		fmt.Fprintf(w, "\n[[share]]\nname = %q\npath = %q\nread_only = %t\n", sh.Name, sh.Path, sh.ReadOnly)
	}
	for _, u := range cfg.Users {
		fmt.Fprintf(w, "\n[[user]]\nname = %q\n", u.Name)
		if u.Password != "" {
			fmt.Fprintf(w, "password = %q\n", "<redacted>")
		}
		if u.NTHash != "" {
			fmt.Fprintf(w, "nt_hash = %q\n", "<redacted>")
		}
	}
}

// dialectFloorText renders the effective dialect floor: what `min_dialect`
// resolved to, saying where it came from when it was not set explicitly.
func dialectFloorText(cfg *samba.Config) string {
	floor := cfg.DialectFloor().Version
	switch {
	case cfg.MinDialect == floor:
		return floor
	case floor == samba.DefaultMinDialect:
		return floor + " (default)"
	default:
		return floor + " (required by encrypt = true)"
	}
}

// logLevelName renders a log_level the way the configuration documents it.
func logLevelName(l uint8) string {
	switch l {
	case samba.LevelWarn:
		return "warn"
	case samba.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

// speedText renders a link speed in bits per second.
func speedText(bps uint64) string {
	if bps >= 1_000_000_000 {
		return fmt.Sprintf("%.1f Gb/s", float64(bps)/1e9)
	}
	return fmt.Sprintf("%.0f Mb/s", float64(bps)/1e6)
}

// quoteList renders the body of a TOML string array.
func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = strconv.Quote(s)
	}
	return strings.Join(quoted, ", ")
}
