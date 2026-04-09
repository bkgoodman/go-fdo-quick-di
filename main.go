// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// --- Config file mode ---
	configPath := flag.String("config", "", "Path to configuration `file`")

	// --- Quick mode (no config file) ---
	quick := flag.Bool("quick", false, "Run with sensible defaults, no config file needed (ephemeral key, ec256, local output)")

	// --- CLI overrides (work with both -config and -quick) ---
	keyType := flag.String("key-type", "", "Device key type: ec256, ec384, rsa2048, rsa3072")
	deviceInfo := flag.String("device-info", "", "Device info `string` embedded in voucher")
	rv := flag.String("rv", "", "Rendezvous `entry` as host:port:scheme (e.g. rv.example.com:443:https)")
	outputDir := flag.String("output-dir", "", "Output `directory` for vouchers and credential")

	// --- TPM overrides ---
	tpmHierarchy := flag.String("tpm-hierarchy", "", "TPM hierarchy: owner (default) or platform")
	tpmKeyMethod := flag.String("tpm-key-method", "", "TPM key method: child (default) or primary")

	// --- Operational modes ---
	debug := flag.Bool("debug", false, "Enable debug output")
	dryRun := flag.Bool("dry-run", false, "Validate config and show what would happen, don't execute")
	inspect := flag.Bool("inspect", false, "Inspect stored device credential and exit")
	inspectVoucher := flag.String("inspect-voucher", "", "Inspect a .fdoov voucher `file` and exit")
	verify := flag.String("verify", "", "Verify a .fdoov voucher `file` against stored credential and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `go-fdo-quick-di: Self-contained FDO Device Initialization

Quick mode (no config file needed):
  quick-di -quick                           Ephemeral key, ec256, local output
  quick-di -quick -key-type ec384           Override key type
  quick-di -quick -device-info "My Edge"    Override device info
  quick-di -quick -rv rv.corp.com:443:https Override rendezvous
  quick-di -quick -output-dir /mnt/usb/out  Override output location

Config file mode:
  quick-di -config config.yaml              Full config from YAML file
  quick-di -config config.yaml -key-type ec256  Override specific fields

Inspection and verification (no DI, just examine existing artifacts):
  quick-di -config config.yaml -inspect              Show stored credential
  quick-di -inspect-voucher path/to/voucher.fdoov    Show voucher contents
  quick-di -config config.yaml -verify voucher.fdoov Verify voucher vs credential

Flags:
`)
		flag.PrintDefaults()
	}

	flag.Parse()

	// --- Build config: either from file or from -quick defaults ---
	var cfg *Config
	var err error

	switch {
	case *quick:
		cfg = quickConfig()
		if *debug {
			fmt.Println("Using quick mode (no config file)")
		}

	case *configPath != "":
		cfg, err = LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

	default:
		// No -config or -quick specified. If config.yaml exists, use it.
		// Otherwise, tell the user what to do.
		if _, statErr := os.Stat("config.yaml"); statErr == nil {
			cfg, err = LoadConfig("config.yaml")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config.yaml: %v\n", err)
				os.Exit(1)
			}
		} else if *inspect || *inspectVoucher != "" || *verify != "" {
			// Inspection modes can work with defaults (just need credential_path)
			cfg = DefaultConfig()
		} else {
			fmt.Fprintf(os.Stderr, "No -config or -quick specified and no config.yaml found.\n")
			fmt.Fprintf(os.Stderr, "Run with -quick for simple mode, or -config <file> for full config.\n")
			fmt.Fprintf(os.Stderr, "Run with -help for usage.\n")
			os.Exit(1)
		}
	}

	// --- Apply CLI overrides ---
	if *keyType != "" {
		cfg.Device.KeyType = *keyType
		// In ephemeral mode, match manufacturer key type to device key type
		if cfg.ManufacturerKeyMode == MfgKeyModeEphemeral {
			cfg.ManufacturerKeyType = *keyType
		}
	}
	if *deviceInfo != "" {
		cfg.Device.DeviceInfo = *deviceInfo
	}
	if *rv != "" {
		entry, parseErr := parseRVFlag(*rv)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "Invalid -rv value %q: %v\n", *rv, parseErr)
			fmt.Fprintf(os.Stderr, "Format: host:port:scheme  (e.g. rv.example.com:443:https)\n")
			os.Exit(1)
		}
		cfg.Rendezvous.Entries = []RendezvousEntry{entry}
	}
	if *outputDir != "" {
		cfg.VoucherOutput.Directory = *outputDir
		if credentialBackend == "blob" {
			cfg.Device.CredentialPath = *outputDir + "/cred.bin"
		}
	}
	if *tpmHierarchy != "" {
		cfg.TPM.Hierarchy = *tpmHierarchy
	}
	if *tpmKeyMethod != "" {
		cfg.TPM.KeyMethod = *tpmKeyMethod
	}

	// Bridge config → env vars for go-fdo's TPM store.
	// Done early so inspect/verify can use TPM before full validation.
	applyTPMEnv(cfg)

	// --- Inspect/verify modes (run and exit) ---
	// These only need credential_path and TPM settings, not manufacturer
	// key config. Run them before full validation so they work standalone.
	if *inspect {
		if err := inspectCredential(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Inspect failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if *inspectVoucher != "" {
		if err := inspectVoucherFile(*inspectVoucher); err != nil {
			fmt.Fprintf(os.Stderr, "Inspect voucher failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if *verify != "" {
		if err := verifyVoucherAgainstCredential(*verify, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Verify FAILED: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// --- Full validation (only needed for DI) ---
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Config validation error: %v\n", err)
		os.Exit(1)
	}

	// --- Debug output ---
	if *debug {
		if *configPath != "" {
			fmt.Printf("Config loaded from: %s\n", *configPath)
		} else {
			fmt.Println("Config: quick mode defaults")
		}
		fmt.Printf("  Credential store: %s\n", credentialBackend)
		fmt.Printf("  Mfg key mode:     %s\n", cfg.ManufacturerKeyMode)
		if cfg.ManufacturerKeyMode == MfgKeyModeFile {
			fmt.Printf("  Mfg key file:     %s\n", cfg.ManufacturerKeyFile)
		} else {
			fmt.Printf("  Mfg key type:     %s (ephemeral)\n", cfg.ManufacturerKeyType)
		}
		fmt.Printf("  Device key type:  %s\n", cfg.Device.KeyType)
		fmt.Printf("  Device info:      %s\n", cfg.Device.DeviceInfo)
		if credentialBackend == "blob" {
			fmt.Printf("  Credential path:  %s\n", cfg.Device.CredentialPath)
		} else {
			fmt.Printf("  Credential path:  (ignored -- using %s)\n", credentialBackend)
			fmt.Printf("  TPM hierarchy:    %s\n", cfg.TPM.Hierarchy)
			fmt.Printf("  TPM key method:   %s\n", cfg.TPM.KeyMethod)
		}
		fmt.Printf("  Voucher output:   %s\n", cfg.VoucherOutput.Directory)
		fmt.Printf("  Owner signover:   %v\n", cfg.OwnerSignover.Enabled)
		fmt.Printf("  Push enabled:     %v\n", cfg.Push.Enabled)
		fmt.Printf("  RV entries:       %d\n", len(cfg.Rendezvous.Entries))
		for i, e := range cfg.Rendezvous.Entries {
			fmt.Printf("    [%d] %s:%d (%s)\n", i, e.Host, e.Port, e.Scheme)
		}
	}

	if *dryRun {
		fmt.Println("Dry run: config valid, would perform DI with above settings")
		os.Exit(0)
	}

	// --- Perform DI ---
	if err := performDI(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "DI failed: %v\n", err)
		os.Exit(1)
	}
}

// quickConfig returns a Config for simple/quick mode: ephemeral manufacturer
// key, ec256, local output, rvserver.local, no push, no signover.
func quickConfig() *Config {
	return &Config{
		ManufacturerKeyMode: MfgKeyModeEphemeral,
		ManufacturerKeyType: "ec256",
		Device: DeviceConfig{
			KeyType:        "ec256",
			KeyEncoding:    "x509",
			CredentialPath: "cred.bin",
			DeviceInfo:     "FDO Device",
		},
		TPM: TPMConfig{
			Hierarchy: "owner",
			KeyMethod: "child",
		},
		Rendezvous: RendezvousConfig{
			Entries: []RendezvousEntry{
				{Host: "rvserver.local", Port: 8080, Scheme: "http"},
			},
		},
		VoucherOutput: VoucherOutputConfig{
			Directory: ".",
		},
	}
}

// parseRVFlag parses a rendezvous flag value in the format host:port:scheme.
// The scheme defaults to "http" if omitted. Port defaults to 8080 for http,
// 443 for https.
func parseRVFlag(s string) (RendezvousEntry, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 1 || parts[0] == "" {
		return RendezvousEntry{}, fmt.Errorf("host is required")
	}

	entry := RendezvousEntry{Host: parts[0]}

	switch len(parts) {
	case 1:
		// host only → default port and scheme
		entry.Port = 8080
		entry.Scheme = "http"
	case 2:
		// host:port
		port, err := parsePort(parts[1])
		if err != nil {
			return RendezvousEntry{}, err
		}
		entry.Port = port
		entry.Scheme = "http"
	case 3:
		// host:port:scheme
		port, err := parsePort(parts[1])
		if err != nil {
			return RendezvousEntry{}, err
		}
		entry.Port = port
		entry.Scheme = parts[2]
		if entry.Scheme != "http" && entry.Scheme != "https" {
			return RendezvousEntry{}, fmt.Errorf("scheme must be http or https, got %q", entry.Scheme)
		}
	default:
		return RendezvousEntry{}, fmt.Errorf("too many colons; expected host:port:scheme")
	}

	return entry, nil
}

func parsePort(s string) (int, error) {
	var port int
	if _, err := fmt.Sscanf(s, "%d", &port); err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("port %d out of range", port)
	}
	return port, nil
}

// applyTPMEnv translates config/flag TPM settings into the environment
// variables that go-fdo's cred/tpm_store.go reads at Open() time.
func applyTPMEnv(cfg *Config) {
	if cfg.TPM.Hierarchy == "owner" {
		os.Setenv("FDO_TPM_OWNER_HIERARCHY", "1")
	} else {
		os.Unsetenv("FDO_TPM_OWNER_HIERARCHY")
	}
	if cfg.TPM.KeyMethod == "primary" {
		os.Setenv("FDO_TPM_KEY_METHOD", "primary")
	} else {
		os.Unsetenv("FDO_TPM_KEY_METHOD")
	}
}
