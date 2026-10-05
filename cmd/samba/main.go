// Command samba is a from-scratch SMB2/SMB3 file server.
//
// It speaks SMB 2.0.2 through 3.1.1 with NTLMv2 and Kerberos
// (GSS-API/SPNEGO) authentication, SMB2/3 signing, SMB 3.1.1 preauth
// integrity, SMB3 multichannel, and SMB3 encryption (AES-128/256-GCM and
// -CCM), and it is written in pure Go — no CGO, no unsafe — so the whole
// server is statically linkable and memory safe.
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
	"syscall"

	"github.com/malivvan/samba"
)

const usage = "usage: samba [--config <path>] [--check] [--version]"

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, sigs))
}

// run parses the command line, loads the configuration and runs the server
// until sigs yields a signal (or is closed). It returns the process exit
// status: 0 for success, 2 for a usage, configuration or startup error.
func run(args []string, stdout, stderr io.Writer, sigs <-chan os.Signal) int {
	configPath := "samba.toml"
	checkOnly := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config", "-c":
			if i+1 >= len(args) {
				return fail(stderr, usage)
			}
			i++
			configPath = args[i]
		case "--check":
			checkOnly = true
		case "--version", "-V":
			fmt.Fprintf(stdout, "samba %s\n", samba.Version)
			return 0
		default:
			return fail(stderr, usage)
		}
	}

	cfg, err := samba.LoadConfig(configPath)
	if err != nil {
		return fail(stderr, err.Error())
	}
	samba.SetLogLevel(cfg.LogLevel)
	if checkOnly {
		fmt.Fprintf(stdout, "config ok: %d share(s)\n", len(cfg.Shares))
		return 0
	}
	if err := serve(cfg, sigs); err != nil {
		return fail(stderr, err.Error())
	}
	return 0
}

func fail(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "samba: %s\n", msg)
	return 2
}

// serve starts the server, reports what it is serving, and blocks until the
// signal channel yields or is closed.
func serve(cfg *samba.Config, sigs <-chan os.Signal) error {
	srv, err := samba.NewServer(cfg)
	if err != nil {
		return err
	}
	if allowGuest := cfg.GuestAllowed(); len(cfg.Users) > 0 {
		guest := "denied"
		if allowGuest {
			guest = "allowed"
		}
		samba.LogInfo("%d user(s) loaded, guest %s", len(cfg.Users), guest)
	}
	if cfg.Multichannel {
		var advertised []string
		for _, i := range srv.Srv().Interfaces() {
			if !i.Loopback {
				advertised = append(advertised, i.Addr.String())
			}
		}
		samba.LogInfo("multichannel enabled, advertising %v", advertised)
	}
	if err := srv.Start(); err != nil {
		return err
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	samba.LogInfo(
		"samba %s listening on %s (%d workers, max_read %d KiB)",
		samba.Version, cfg.Listen, workers, samba.MaxReadTarget/1024,
	)
	if sigs != nil {
		<-sigs
	}
	samba.LogInfo("shutting down")
	srv.Stop()
	srv.Wait()
	return nil
}
