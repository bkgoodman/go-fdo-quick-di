// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// loadPrivateKey reads a PEM-encoded private key from a file.
func loadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	var key crypto.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q in %q", block.Type, path)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing key from %q: %w", path, err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key from %q does not implement crypto.Signer", path)
	}
	return signer, nil
}

// loadPublicKey reads a PEM-encoded public key from a file.
func loadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing public key from %q: %w", path, err)
		}
		return key, nil
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate from %q: %w", path, err)
		}
		return cert.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q in %q (expected PUBLIC KEY or CERTIFICATE)", block.Type, path)
	}
}

// loadCertChain reads a PEM-encoded certificate chain from a file.
// Returns the chain in order (leaf first). If the file doesn't exist,
// returns nil (caller can generate a self-signed cert).
func loadCertChain(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading cert file %q: %w", path, err)
	}

	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate from %q: %w", path, err)
		}
		chain = append(chain, cert)
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in %q", path)
	}
	return chain, nil
}

// keyTypeName returns a human-readable name for a public key type.
func keyTypeName(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", k.Size()*8)
	default:
		return fmt.Sprintf("%T", pub)
	}
}
