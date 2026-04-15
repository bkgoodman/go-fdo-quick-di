// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build tpm || tpmsim

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

// verifyDAKBinding proves the TPM holds the DAK private key that matches
// the device certificate in the voucher.
//
// This performs a live cryptographic challenge:
//  1. Generate a random challenge
//  2. Have the TPM sign it with the DAK (empty password auth)
//  3. Extract the device public key from the voucher's cert chain
//  4. Verify the TPM's signature against the voucher's device public key
//
// If this passes, it proves: this TPM is the one the voucher was created for.
func verifyDAKBinding(ov *fdo.Voucher) error {
	// Open TPM
	t, err := tpm.DefaultOpen()
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer func() { _ = t.Close() }()

	// Challenge the TPM: sign a random nonce with the DAK
	proof, err := tpm.ProveDAKPossession(t, nil) // nil = random challenge
	if err != nil {
		return fmt.Errorf("DAK challenge failed: %w", err)
	}

	// Extract device public key from voucher's cert chain
	if ov.CertChain == nil || len(*ov.CertChain) == 0 {
		return fmt.Errorf("voucher has no device certificate chain")
	}
	leafCert := (*x509.Certificate)((*ov.CertChain)[0])
	voucherDeviceKey := leafCert.PublicKey

	// Verify the TPM's DAK public key matches the voucher's device cert
	tpmPubKey := proof.PublicKey
	if !publicKeysEqual(tpmPubKey, voucherDeviceKey) {
		return fmt.Errorf("DAK public key MISMATCH: TPM key does not match voucher device cert")
	}

	// Verify the signature over the challenge
	switch key := tpmPubKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, proof.Challenge[:], proof.Signature) {
			return fmt.Errorf("DAK signature verification FAILED: TPM signed challenge but signature is invalid")
		}
	default:
		return fmt.Errorf("unsupported DAK key type for verification: %T", tpmPubKey)
	}

	// Print details
	dakDER, _ := x509.MarshalPKIXPublicKey(tpmPubKey)
	fp := sha256.Sum256(dakDER)
	fmt.Printf("  Challenge sent   : %x... (random nonce)\n", proof.Challenge[:8])
	fmt.Printf("  TPM signature    : %x... (%d bytes)\n", proof.Signature[:16], len(proof.Signature))
	fmt.Printf("  DAK fingerprint  : %x\n", fp[:16])
	fmt.Printf("  Voucher cert CN  : %s\n", leafCert.Subject.CommonName)
	fmt.Printf("  DAK proof        : OK  (TPM signed challenge; signature verified against voucher device cert)\n")

	return nil
}

// publicKeysEqual compares two crypto.PublicKey values for equality.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch ak := a.(type) {
	case *ecdsa.PublicKey:
		bk, ok := b.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return ak.Curve == bk.Curve && ak.X.Cmp(bk.X) == 0 && ak.Y.Cmp(bk.Y) == 0
	default:
		// Fallback: compare DER encodings
		aDER, aErr := x509.MarshalPKIXPublicKey(a)
		bDER, bErr := x509.MarshalPKIXPublicKey(b)
		if aErr != nil || bErr != nil {
			return false
		}
		if len(aDER) != len(bDER) {
			return false
		}
		for i := range aDER {
			if aDER[i] != bDER[i] {
				return false
			}
		}
		return true
	}
}
