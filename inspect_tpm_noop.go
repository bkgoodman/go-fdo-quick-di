// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build !tpm && !tpmsim

package main

// inspectTPMDetails is a no-op for blob builds.
func inspectTPMDetails(_ *Config) error {
	return nil
}
