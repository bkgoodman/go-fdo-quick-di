// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"fmt"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

// pushVoucher sends a voucher to a remote endpoint using the configured
// authentication method.
func pushVoucher(cfg *Config, voucher *fdo.Voucher, guid protocol.GUID) error {
	raw, err := cbor.Marshal(voucher)
	if err != nil {
		return fmt.Errorf("encoding voucher: %w", err)
	}

	data := &transfer.VoucherData{
		VoucherInfo: transfer.VoucherInfo{
			GUID:       guid.String(),
			DeviceInfo: voucher.Header.Val.DeviceInfo,
		},
		Voucher: voucher,
		Raw:     raw,
	}

	token, err := getPushToken(cfg)
	if err != nil {
		return fmt.Errorf("getting auth token: %w", err)
	}

	sender := transfer.NewHTTPPushSender()
	dest := transfer.PushDestination{
		URL:   cfg.Push.URL,
		Token: token,
	}

	return sender.Push(context.Background(), dest, data)
}

// getPushToken returns the authentication token for the push endpoint.
func getPushToken(cfg *Config) (string, error) {
	switch cfg.Push.AuthMethod {
	case "bearer":
		return cfg.Push.AuthToken, nil

	case "fdokeyauth":
		supplierKey, err := loadPrivateKey(cfg.Push.SupplierKeyFile)
		if err != nil {
			return "", fmt.Errorf("loading supplier key: %w", err)
		}

		client := &transfer.FDOKeyAuthClient{
			CallerKey: supplierKey,
			BaseURL:   cfg.Push.URL,
		}

		result, err := client.Authenticate()
		if err != nil {
			return "", fmt.Errorf("FDOKeyAuth authentication failed: %w", err)
		}
		return result.SessionToken, nil

	default:
		return "", fmt.Errorf("unsupported auth method: %q", cfg.Push.AuthMethod)
	}
}
