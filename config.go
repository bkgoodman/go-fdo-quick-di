// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Manufacturer key modes.
const (
	// MfgKeyModeFile loads the manufacturer private key from a PEM file.
	// The key persists on disk (e.g. USB key). Provides real manufacturer
	// provenance but the key is exposed to theft.
	MfgKeyModeFile = "file"

	// MfgKeyModeEphemeral generates a random manufacturer key in memory
	// for each run. The key is never written to disk and is discarded when
	// the process exits. No key to steal, but no persistent manufacturer
	// identity either -- trust must come from the next party in the chain.
	MfgKeyModeEphemeral = "ephemeral"
)

// Config represents the quick-di configuration.
type Config struct {
	// Manufacturing key mode: "file" (default) or "ephemeral"
	// See TRUST_MODELS.md for detailed discussion of the trade-offs.
	ManufacturerKeyMode string `yaml:"manufacturer_key_mode"`

	// Manufacturing key file (required when mode=file, ignored when mode=ephemeral)
	ManufacturerKeyFile  string `yaml:"manufacturer_key_file"`
	ManufacturerCertFile string `yaml:"manufacturer_cert_file"`

	// Manufacturing key type (used only for mode=ephemeral; defaults to
	// matching device.key_type so ExtendVoucher key-type constraints are met)
	ManufacturerKeyType string `yaml:"manufacturer_key_type"`

	// Device credential storage
	Device DeviceConfig `yaml:"device"`

	// TPM settings (only relevant for builds with -tags=tpm)
	TPM TPMConfig `yaml:"tpm"`

	// Rendezvous info baked into voucher
	Rendezvous RendezvousConfig `yaml:"rendezvous"`

	// Ownership extension (optional)
	OwnerSignover OwnerSignoverConfig `yaml:"owner_signover"`

	// Voucher output
	VoucherOutput VoucherOutputConfig `yaml:"voucher_output"`

	// Voucher push (optional)
	Push PushConfig `yaml:"push"`
}

// DeviceConfig configures device credential generation.
type DeviceConfig struct {
	KeyType        string `yaml:"key_type"`        // ec256, ec384, rsa2048, rsa3072
	KeyEncoding    string `yaml:"key_encoding"`    // x509, x5chain, cose
	CredentialPath string `yaml:"credential_path"` // Blob file path (ignored for TPM)
	DeviceInfo     string `yaml:"device_info"`     // Device info string for voucher
	SerialNumber   string `yaml:"serial_number"`   // Optional; auto-generated if empty
}

// RendezvousConfig configures rendezvous info embedded in the voucher.
type RendezvousConfig struct {
	Entries []RendezvousEntry `yaml:"entries"`
}

// RendezvousEntry represents a single rendezvous endpoint.
type RendezvousEntry struct {
	Host   string `yaml:"host"`   // IP address or DNS name
	Port   int    `yaml:"port"`   // Port number
	Scheme string `yaml:"scheme"` // "http" or "https"
}

// OwnerSignoverConfig configures optional ownership extension.
type OwnerSignoverConfig struct {
	Enabled                bool   `yaml:"enabled"`
	NextOwnerPublicKeyFile string `yaml:"next_owner_public_key_file"`
}

// TPMConfig configures TPM behavior (only used in builds with -tags=tpm).
type TPMConfig struct {
	// Hierarchy selects the TPM hierarchy for NV index operations.
	//   "owner"    -- Owner hierarchy (default). Works in Linux userspace.
	//   "platform" -- Platform hierarchy. Requires firmware-level access;
	//                 locked after boot on Linux even as root.
	Hierarchy string `yaml:"hierarchy"`

	// KeyMethod selects how device keys are created inside the TPM.
	//   "child"   -- Keys created as children of the SRK (default).
	//                WinPE-compatible, RNG-based.
	//   "primary" -- Primary keys with unique strings.
	//                Rollback-resistant but WinPE-incompatible.
	KeyMethod string `yaml:"key_method"`
}

// VoucherOutputConfig configures where vouchers are saved.
type VoucherOutputConfig struct {
	Directory string `yaml:"directory"` // Where to save .fdoov files
}

// PushConfig configures optional voucher push to a remote endpoint.
type PushConfig struct {
	Enabled         bool          `yaml:"enabled"`
	URL             string        `yaml:"url"`               // Remote endpoint URL
	AuthMethod      string        `yaml:"auth_method"`       // "bearer" or "fdokeyauth"
	AuthToken       string        `yaml:"auth_token"`        // For bearer auth
	SupplierKeyFile string        `yaml:"supplier_key_file"` // For fdokeyauth
	Timeout         time.Duration `yaml:"timeout"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ManufacturerKeyMode: MfgKeyModeFile,
		Device: DeviceConfig{
			KeyType:        "ec384",
			KeyEncoding:    "x509",
			CredentialPath: "cred.bin",
			DeviceInfo:     "FDO-Device",
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
			Directory: "vouchers",
		},
		Push: PushConfig{
			AuthMethod: "bearer",
			Timeout:    30 * time.Second,
		},
	}
}

// LoadConfig loads configuration from a YAML file, falling back to defaults.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}

	return cfg, nil
}

// Validate checks that required configuration is present and consistent.
func (c *Config) Validate() error {
	// Default mode to "file" for backward compatibility
	if c.ManufacturerKeyMode == "" {
		if c.ManufacturerKeyFile != "" {
			c.ManufacturerKeyMode = MfgKeyModeFile
		} else {
			return fmt.Errorf("manufacturer_key_mode is required (\"file\" or \"ephemeral\")")
		}
	}

	switch c.ManufacturerKeyMode {
	case MfgKeyModeFile:
		if c.ManufacturerKeyFile == "" {
			return fmt.Errorf("manufacturer_key_file is required when manufacturer_key_mode is \"file\"")
		}

	case MfgKeyModeEphemeral:
		// Default ephemeral key type to match device key type
		if c.ManufacturerKeyType == "" {
			c.ManufacturerKeyType = c.Device.KeyType
		}
		switch c.ManufacturerKeyType {
		case "ec256", "ec384", "rsa2048", "rsa3072":
			// valid
		default:
			return fmt.Errorf("unsupported manufacturer_key_type %q for ephemeral mode", c.ManufacturerKeyType)
		}

	default:
		return fmt.Errorf("unsupported manufacturer_key_mode %q (valid: \"file\", \"ephemeral\")", c.ManufacturerKeyMode)
	}

	switch c.Device.KeyType {
	case "ec256", "ec384", "rsa2048", "rsa3072":
		// valid
	default:
		return fmt.Errorf("unsupported device key_type %q (valid: ec256, ec384, rsa2048, rsa3072)", c.Device.KeyType)
	}

	switch c.Device.KeyEncoding {
	case "x509", "x5chain", "cose":
		// valid
	default:
		return fmt.Errorf("unsupported device key_encoding %q (valid: x509, x5chain, cose)", c.Device.KeyEncoding)
	}

	switch c.TPM.Hierarchy {
	case "owner", "platform":
		// valid
	default:
		return fmt.Errorf("unsupported tpm.hierarchy %q (valid: owner, platform)", c.TPM.Hierarchy)
	}

	switch c.TPM.KeyMethod {
	case "child", "primary":
		// valid
	default:
		return fmt.Errorf("unsupported tpm.key_method %q (valid: child, primary)", c.TPM.KeyMethod)
	}

	if len(c.Rendezvous.Entries) == 0 {
		return fmt.Errorf("at least one rendezvous entry is required")
	}
	for i, entry := range c.Rendezvous.Entries {
		if entry.Host == "" {
			return fmt.Errorf("rendezvous entry %d: host is required", i+1)
		}
		if entry.Port <= 0 || entry.Port > 65535 {
			return fmt.Errorf("rendezvous entry %d: invalid port %d", i+1, entry.Port)
		}
		if entry.Scheme != "http" && entry.Scheme != "https" {
			return fmt.Errorf("rendezvous entry %d: scheme must be http or https, got %q", i+1, entry.Scheme)
		}
	}

	if c.OwnerSignover.Enabled && c.OwnerSignover.NextOwnerPublicKeyFile == "" {
		return fmt.Errorf("owner_signover.next_owner_public_key_file is required when owner_signover is enabled")
	}

	if c.Push.Enabled {
		if c.Push.URL == "" {
			return fmt.Errorf("push.url is required when push is enabled")
		}
		switch c.Push.AuthMethod {
		case "bearer":
			if c.Push.AuthToken == "" {
				return fmt.Errorf("push.auth_token is required for bearer auth")
			}
		case "fdokeyauth":
			if c.Push.SupplierKeyFile == "" {
				return fmt.Errorf("push.supplier_key_file is required for fdokeyauth")
			}
		default:
			return fmt.Errorf("unsupported push.auth_method %q (valid: bearer, fdokeyauth)", c.Push.AuthMethod)
		}
	}

	return nil
}
