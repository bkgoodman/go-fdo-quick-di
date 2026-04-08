// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	debug := flag.Bool("debug", false, "Enable debug output")
	dryRun := flag.Bool("dry-run", false, "Validate config and show what would happen, but don't execute")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `go-fdo-quick-di: Self-contained FDO Device Initialization

Performs the entire DI protocol locally without a manufacturing server.
Creates device credentials, builds an Ownership Voucher, optionally
extends it to a next owner, and saves/pushes the result.

Manufacturer key modes:
  file       Load key from PEM file (default). Real provenance but key
             is exposed on disk.
  ephemeral  Generate a random key in memory per run, never written to
             disk. No key to steal but no persistent manufacturer
             identity. Trust shifts to the next party in the chain.

See TRUST_MODELS.md for a detailed discussion of the security trade-offs.

Usage:
  quick-di [flags]

Flags:
`)
		flag.PrintDefaults()
	}

	flag.Parse()

	// Load and validate config
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Config validation error: %v\n", err)
		os.Exit(1)
	}

	if *debug {
		fmt.Printf("Config loaded from: %s\n", *configPath)
		fmt.Printf("  Mfg key mode:     %s\n", cfg.ManufacturerKeyMode)
		if cfg.ManufacturerKeyMode == MfgKeyModeFile {
			fmt.Printf("  Mfg key file:     %s\n", cfg.ManufacturerKeyFile)
		} else {
			fmt.Printf("  Mfg key type:     %s (ephemeral)\n", cfg.ManufacturerKeyType)
		}
		fmt.Printf("  Device key type:  %s\n", cfg.Device.KeyType)
		fmt.Printf("  Device info:      %s\n", cfg.Device.DeviceInfo)
		fmt.Printf("  Credential path:  %s\n", cfg.Device.CredentialPath)
		fmt.Printf("  Voucher output:   %s\n", cfg.VoucherOutput.Directory)
		fmt.Printf("  Owner signover:   %v\n", cfg.OwnerSignover.Enabled)
		fmt.Printf("  Push enabled:     %v\n", cfg.Push.Enabled)
		fmt.Printf("  RV entries:       %d\n", len(cfg.Rendezvous.Entries))
	}

	if *dryRun {
		fmt.Println("Dry run: config valid, would perform DI with above settings")
		os.Exit(0)
	}

	// Perform DI
	if err := performDI(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "DI failed: %v\n", err)
		os.Exit(1)
	}
}
