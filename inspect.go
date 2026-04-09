// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cred"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// inspectCredential opens the credential store and prints its contents.
func inspectCredential(cfg *Config) error {
	store, err := cred.Open(cfg.Device.CredentialPath)
	if err != nil {
		return fmt.Errorf("opening credential store: %w", err)
	}
	defer func() { _ = store.Close() }()

	dc, _, _, key, err := store.Load()
	if err != nil {
		return fmt.Errorf("loading credential: %w", err)
	}

	fmt.Println("=== Device Credential ===")
	fmt.Printf("  Version          : %d\n", dc.Version)
	fmt.Printf("  GUID             : %s\n", dc.GUID)
	fmt.Printf("  Device Info      : %s\n", dc.DeviceInfo)
	fmt.Printf("  Device Key       : %s\n", keyTypeName(key.Public()))
	fmt.Printf("  PublicKeyHash alg: %s\n", dc.PublicKeyHash.Algorithm)
	fmt.Printf("  PublicKeyHash    : %x\n", dc.PublicKeyHash.Value)
	fmt.Printf("  RV Directives    : %d\n", len(dc.RvInfo))
	for i, directive := range dc.RvInfo {
		fmt.Printf("    Directive %d:\n", i)
		for _, inst := range directive {
			fmt.Printf("      %s = %s\n", rvVarName(inst.Variable), rvValueString(inst))
		}
	}

	// Print DAK public key fingerprint for cross-reference
	dakDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err == nil {
		fp := sha256.Sum256(dakDER)
		fmt.Printf("  DAK fingerprint  : %x\n", fp[:16])
	}

	fmt.Printf("  Credential store : %s\n", credentialBackend)

	// For TPM builds, show detailed TPM storage info
	if err := inspectTPMDetails(cfg); err != nil {
		fmt.Printf("\n  TPM inspection error: %v\n", err)
	}

	return nil
}

// inspectVoucherFile parses and displays a .fdoov voucher file.
func inspectVoucherFile(path string) error {
	ov, err := loadVoucherFile(path)
	if err != nil {
		return err
	}

	h := ov.Header.Val
	fmt.Println("=== Ownership Voucher ===")
	fmt.Printf("  File             : %s\n", path)
	fmt.Printf("  Protocol Version : %d\n", ov.Version)
	fmt.Printf("  GUID             : %s\n", h.GUID)
	fmt.Printf("  Device Info      : %s\n", h.DeviceInfo)

	mfgPub, err := h.ManufacturerKey.Public()
	if err == nil {
		fmt.Printf("  Manufacturer Key : %s (encoding=%d)\n", keyTypeName(mfgPub), h.ManufacturerKey.Encoding)
	}

	if h.CertChainHash != nil {
		fmt.Printf("  CertChain Hash   : %s (%d bytes)\n", h.CertChainHash.Algorithm, len(h.CertChainHash.Value))
	}
	fmt.Printf("  HMAC             : %s (%d bytes)\n", ov.Hmac.Algorithm, len(ov.Hmac.Value))

	fmt.Printf("  RV Directives    : %d\n", len(h.RvInfo))
	for i, directive := range h.RvInfo {
		fmt.Printf("    Directive %d:\n", i)
		for _, inst := range directive {
			fmt.Printf("      %s = %s\n", rvVarName(inst.Variable), rvValueString(inst))
		}
	}

	if ov.CertChain != nil {
		fmt.Printf("  Device Cert Chain: %d certificate(s)\n", len(*ov.CertChain))
		for i, cert := range *ov.CertChain {
			c := (*x509.Certificate)(cert)
			fp := sha256.Sum256(c.Raw)
			fmt.Printf("    [%d] CN=%-30s Issuer=%-30s SHA256=%x...\n",
				i, c.Subject.CommonName, c.Issuer.CommonName, fp[:8])
		}
	}

	fmt.Printf("  OV Entries       : %d\n", len(ov.Entries))
	for i, e := range ov.Entries {
		nextPub, err := e.Payload.Val.PublicKey.Public()
		nextKeyStr := "(error)"
		if err == nil {
			nextKeyStr = keyTypeName(nextPub)
		}
		fmt.Printf("    Entry %d:\n", i)
		fmt.Printf("      Next owner   : %s\n", nextKeyStr)
		fmt.Printf("      PrevHash     : %s (%d bytes)\n",
			e.Payload.Val.PreviousHash.Algorithm, len(e.Payload.Val.PreviousHash.Value))
		fmt.Printf("      HeaderHash   : %s (%d bytes)\n",
			e.Payload.Val.HeaderHash.Algorithm, len(e.Payload.Val.HeaderHash.Value))
	}

	raw, _ := cbor.Marshal(ov)
	fp := sha256.Sum256(raw)
	fmt.Printf("  Voucher SHA-256  : %x\n", fp)

	return nil
}

// verifyVoucherAgainstCredential loads a voucher and the device credential,
// then verifies the voucher's HMAC and manufacturer key hash match.
func verifyVoucherAgainstCredential(voucherPath string, cfg *Config) error {
	// Load credential
	store, err := cred.Open(cfg.Device.CredentialPath)
	if err != nil {
		return fmt.Errorf("opening credential store: %w", err)
	}
	defer func() { _ = store.Close() }()

	dc, hmac256, hmac384, _, err := store.Load()
	if err != nil {
		return fmt.Errorf("loading credential: %w", err)
	}

	// Load voucher
	ov, err := loadVoucherFile(voucherPath)
	if err != nil {
		return err
	}

	fmt.Printf("Credential GUID    : %s\n", dc.GUID)
	fmt.Printf("Voucher GUID       : %s\n", ov.Header.Val.GUID)

	// Check GUID match
	if dc.GUID != ov.Header.Val.GUID {
		return fmt.Errorf("GUID MISMATCH: credential %s != voucher %s", dc.GUID, ov.Header.Val.GUID)
	}
	fmt.Println("  GUID match       : OK")

	// Verify HMAC (proves voucher header was not tampered with)
	if err := ov.VerifyHeader(hmac256, hmac384); err != nil {
		return fmt.Errorf("HMAC verification FAILED: %w", err)
	}
	fmt.Println("  HMAC verify      : OK")

	// Verify manufacturer key hash
	if err := ov.VerifyManufacturerKey(dc.PublicKeyHash); err != nil {
		return fmt.Errorf("manufacturer key verification FAILED: %w", err)
	}
	fmt.Println("  Mfg key hash     : OK")

	// Verify cert chain hash
	if err := ov.VerifyCertChainHash(); err != nil {
		return fmt.Errorf("cert chain hash verification FAILED: %w", err)
	}
	fmt.Println("  Cert chain hash  : OK")

	// Verify entry chain signatures
	if err := ov.VerifyEntries(); err != nil {
		return fmt.Errorf("entry chain verification FAILED: %w", err)
	}
	fmt.Printf("  Entry chain      : OK (%d entries)\n", len(ov.Entries))

	// For TPM builds: prove the TPM holds the DAK private key that matches
	// the device certificate in the voucher (live cryptographic challenge).
	// For blob builds: this is a no-op.
	if credentialBackend != "blob" {
		fmt.Println("\n  --- DAK Possession Proof (TPM challenge-response) ---")
		if err := verifyDAKBinding(ov); err != nil {
			return fmt.Errorf("DAK possession proof FAILED: %w", err)
		}
	}

	fmt.Println("\nVoucher verification PASSED")
	return nil
}

// loadVoucherFile reads and parses a PEM-encoded .fdoov file.
func loadVoucherFile(path string) (*fdo.Voucher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading voucher %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		// Try raw CBOR
		var ov fdo.Voucher
		if err := cbor.Unmarshal(data, &ov); err != nil {
			return nil, fmt.Errorf("no PEM block and not valid CBOR in %q", path)
		}
		return &ov, nil
	}

	var ov fdo.Voucher
	if err := cbor.Unmarshal(block.Bytes, &ov); err != nil {
		return nil, fmt.Errorf("decoding voucher from %q: %w", path, err)
	}
	return &ov, nil
}

// rvVarName returns a human-readable name for an RV variable.
func rvVarName(v protocol.RvVar) string {
	switch v {
	case protocol.RVDevOnly:
		return "DevOnly"
	case protocol.RVOwnerOnly:
		return "OwnerOnly"
	case protocol.RVIPAddress:
		return "IPAddress"
	case protocol.RVDevPort:
		return "DevPort"
	case protocol.RVOwnerPort:
		return "OwnerPort"
	case protocol.RVDns:
		return "DNS"
	case protocol.RVProtocol:
		return "Protocol"
	case protocol.RVDelaysec:
		return "DelaySec"
	case protocol.RVBypass:
		return "Bypass"
	default:
		return fmt.Sprintf("RvVar(%d)", v)
	}
}

// rvValueString decodes an RV instruction value to a human-readable string.
func rvValueString(inst protocol.RvInstruction) string {
	switch inst.Variable {
	case protocol.RVDns:
		var s string
		if err := cbor.Unmarshal(inst.Value, &s); err == nil {
			return s
		}
	case protocol.RVIPAddress:
		var b []byte
		if err := cbor.Unmarshal(inst.Value, &b); err == nil {
			return net.IP(b).String()
		}
	case protocol.RVDevPort, protocol.RVOwnerPort:
		var p uint16
		if err := cbor.Unmarshal(inst.Value, &p); err == nil {
			return fmt.Sprintf("%d", p)
		}
	case protocol.RVProtocol:
		var p uint8
		if err := cbor.Unmarshal(inst.Value, &p); err == nil {
			switch p {
			case 1:
				return "HTTP"
			case 2:
				return "HTTPS"
			default:
				return fmt.Sprintf("%d", p)
			}
		}
	case protocol.RVBypass:
		return "(flag)"
	}
	return fmt.Sprintf("%x", inst.Value)
}
