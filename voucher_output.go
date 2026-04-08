// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// saveVoucherPEM saves a voucher as a PEM-encoded .fdoov file.
// Returns the path to the saved file.
func saveVoucherPEM(voucher *fdo.Voucher, guid protocol.GUID, dir string) (string, error) {
	if dir == "" {
		dir = "."
	}

	// Ensure output directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("creating output directory %q: %w", dir, err)
	}

	// Encode voucher to CBOR
	data, err := cbor.Marshal(voucher)
	if err != nil {
		return "", fmt.Errorf("encoding voucher: %w", err)
	}

	// PEM-encode
	block := &pem.Block{
		Type:  "FDO OWNERSHIP VOUCHER",
		Bytes: data,
	}

	filename := guid.String() + ".fdoov"
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("creating %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("writing PEM: %w", err)
	}

	return path, nil
}
