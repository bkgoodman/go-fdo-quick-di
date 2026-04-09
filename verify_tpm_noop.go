// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build !tpm && !tpmsim

package main

import "github.com/fido-device-onboard/go-fdo"

// verifyDAKBinding is a no-op for blob builds -- blob credentials have no
// hardware-bound key to challenge.
func verifyDAKBinding(_ *fdo.Voucher) error {
	return nil
}
