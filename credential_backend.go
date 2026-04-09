// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build !tpm && !tpmsim

package main

// credentialBackend identifies the compiled-in credential storage backend.
const credentialBackend = "blob"
