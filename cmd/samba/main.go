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
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/malivvan/samba"
)

const usage = "usage: samba [--config <path>] [--check] [--version]"

func main() {
	configPath := "samba.toml"
	checkOnly := false

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config", "-c":
			if i+1 >= len(args) {
				die(usage)
			}
			i++
			configPath = args[i]
		case "--check":
			checkOnly = true
		case "--version", "-V":
			fmt.Printf("samba %s\n", samba.Version)
			return
		default:
			die(usage)
		}
	}

	cfg, err := samba.LoadConfig(configPath)
	if err != nil {
		die(err.Error())
	}
	samba.SetLogLevel(cfg.LogLevel)
	if checkOnly {
		fmt.Printf("config ok: %d share(s)\n", len(cfg.Shares))
		return
	}

	if err := run(cfg); err != nil {
		die(err.Error())
	}
}

func die(msg string) {
	fmt.Fprintf(os.Stderr, "samba: %s\n", msg)
	os.Exit(2)
}

func run(cfg *samba.Config) error {
	srv, err := samba.NewServer(cfg)
	if err != nil {
		return err
	}
	users := cfg.Users
	allowGuest := cfg.GuestAllowed()
	if len(users) > 0 {
		guest := "denied"
		if allowGuest {
			guest = "allowed"
		}
		samba.LogInfo("%d user(s) loaded, guest %s", len(users), guest)
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

	// Run until interrupted.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	samba.LogInfo("shutting down")
	srv.Stop()
	srv.Wait()
	return nil
}
