// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build tpm || tpmsim

package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

// dctpmNVDisplay mirrors the DCTPM NV structure for decoding during inspection.
type dctpmNVDisplay struct {
	Magic           uint32                     `cbor:"0,keyasint"`
	Active          bool                       `cbor:"1,keyasint"`
	Version         uint16                     `cbor:"2,keyasint"`
	DeviceInfo      string                     `cbor:"3,keyasint"`
	GUID            protocol.GUID              `cbor:"4,keyasint"`
	RvInfo          [][]protocol.RvInstruction `cbor:"5,keyasint"`
	PublicKeyHash   protocol.Hash              `cbor:"6,keyasint"`
	KeyType         protocol.KeyType           `cbor:"7,keyasint"`
	DeviceKeyHandle uint32                     `cbor:"8,keyasint"`
	HMACKeyHandle   uint32                     `cbor:"9,keyasint,omitempty"`
}

// inspectTPMDetails reads raw TPM NV indices and persistent handles
// and prints detailed information about what's stored where.
func inspectTPMDetails(_ *Config) error {
	t, err := tpm.DefaultOpen()
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer func() { _ = t.Close() }()

	fmt.Println("\n=== TPM Storage Details ===")

	// Read NV credential info
	info, err := tpm.ReadNVCredentials(t)
	if err != nil {
		fmt.Printf("  Error reading NV: %v\n", err)
	}

	// --- NV Index: DCTPM ---
	fmt.Printf("\n  NV Index 0x%08X (DCTPM consolidated):\n", tpm.DCTPMIndex)
	if info != nil && info.HasDCTPM {
		fmt.Printf("    Status         : DEFINED (%d bytes)\n", info.DCTPMSize)

		var dctpm dctpmNVDisplay
		if err := cbor.Unmarshal(info.RawDCTPM, &dctpm); err != nil {
			fmt.Printf("    Decode error   : %v\n", err)
		} else {
			magicStr := fmt.Sprintf("0x%08X", dctpm.Magic)
			if dctpm.Magic == tpm.DCTPMMagic {
				magicStr += " (FDO1 - valid)"
			} else {
				magicStr += " (INVALID - expected FDO1)"
			}
			fmt.Printf("    Magic          : %s\n", magicStr)
			fmt.Printf("    Active         : %v\n", dctpm.Active)
			fmt.Printf("    Version        : %d\n", dctpm.Version)
			fmt.Printf("    GUID           : %s\n", dctpm.GUID)
			fmt.Printf("    Device Info    : %s\n", dctpm.DeviceInfo)
			fmt.Printf("    Key Type       : %s\n", dctpm.KeyType)
			fmt.Printf("    DAK Handle     : 0x%08X\n", dctpm.DeviceKeyHandle)
			fmt.Printf("    HMAC Handle    : 0x%08X\n", dctpm.HMACKeyHandle)
			fmt.Printf("    PubKeyHash alg : %s\n", dctpm.PublicKeyHash.Algorithm)
			fmt.Printf("    PubKeyHash     : %x\n", dctpm.PublicKeyHash.Value)
			fmt.Printf("    RV Directives  : %d\n", len(dctpm.RvInfo))
			for i, dir := range dctpm.RvInfo {
				fmt.Printf("      Directive %d:\n", i)
				for _, inst := range dir {
					fmt.Printf("        %s = %s\n", rvVarName(inst.Variable), rvValueString(inst))
				}
			}
		}
	} else {
		fmt.Printf("    Status         : NOT DEFINED\n")
	}

	// --- Persistent Handle: DAK ---
	fmt.Printf("\n  Persistent Handle 0x%08X (DAK):\n", tpm.DAKHandle)
	if info != nil && info.HasDAK {
		fmt.Printf("    Status         : PRESENT\n")

		pubKey, err := tpm.ReadDAKPublicKey(t)
		if err != nil {
			fmt.Printf("    Public key     : (error: %v)\n", err)
		} else {
			fmt.Printf("    Key type       : %s\n", keyTypeName(pubKey))
			der, err := x509.MarshalPKIXPublicKey(pubKey)
			if err == nil {
				fp := sha256.Sum256(der)
				fmt.Printf("    Fingerprint    : %x\n", fp[:])
			}
			switch k := pubKey.(type) {
			case *ecdsa.PublicKey:
				fmt.Printf("    Curve          : %s\n", k.Curve.Params().Name)
				fmt.Printf("    X              : %x\n", k.X.Bytes())
				fmt.Printf("    Y              : %x\n", k.Y.Bytes())
			case *rsa.PublicKey:
				fmt.Printf("    Size           : %d bits\n", k.Size()*8)
				fmt.Printf("    Exponent       : %d\n", k.E)
			}
		}
	} else {
		fmt.Printf("    Status         : NOT PRESENT\n")
	}

	// --- Persistent Handle: HMAC Key ---
	fmt.Printf("\n  Persistent Handle 0x%08X (HMAC Key):\n", tpm.HMACKeyHandle)
	if info != nil && info.HasHMACKey {
		fmt.Printf("    Status         : PRESENT\n")
		fmt.Printf("    Algorithm      : HMAC-SHA256 (spec-compliant persistent key)\n")
	} else {
		fmt.Printf("    Status         : NOT PRESENT\n")
	}

	// --- Handle range summary ---
	fmt.Printf("\n  Handle Map:\n")
	fmt.Printf("    0x%08X     DCTPM NV index (credential metadata)\n", tpm.DCTPMIndex)
	fmt.Printf("    0x%08X     DAK (Device Attestation Key, persistent)\n", tpm.DAKHandle)
	fmt.Printf("    0x%08X     HMAC key (persistent)\n", tpm.HMACKeyHandle)

	return nil
}
