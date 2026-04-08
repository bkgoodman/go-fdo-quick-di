# AGENTS.md

## Project Overview

`go-fdo-quick-di` is a self-contained FDO Device Initialization tool that
performs both the device and manufacturing sides of DI in a single process.
It uses the go-fdo library (git submodule) but does NOT modify it.

## Agent Rules

- **Do NOT modify files under `go-fdo/`** -- that is a git submodule
- **NEVER stage or commit code** -- the user handles commits
- Run `gofmt` on all Go files before calling anything "done"
- Run `go build ./...` to verify compilation

## Build & Test

```bash
go build -o quick-di .                 # Build
go run . -config config_example.yaml   # Run with example config
go run . -config test-config.yaml      # Run with test config
gofmt -l *.go                          # Check formatting
```

## Architecture

This is a single-flow tool, NOT a client/server application. It directly
calls go-fdo library functions to assemble vouchers without HTTP transport.

### Key Files

| File | Purpose |
|------|---------|
| `main.go` | Entry point, flag parsing |
| `config.go` | YAML config struct and validation |
| `di.go` | Core DI logic (credential gen, cert signing, voucher assembly) |
| `keys.go` | PEM key loading utilities |
| `voucher_output.go` | PEM .fdoov file writing |
| `push.go` | Optional voucher push to remote endpoint |

### Dependencies (from go-fdo)

- `fdo` -- Voucher, VoucherHeader, ExtendVoucher, DeviceCredential
- `cred` -- Credential store (blob/TPM via build tags)
- `cbor` -- CBOR encoding for protocol messages
- `protocol` -- Key types, hash algorithms, RV instructions, GUID
- `custom` -- DeviceMfgInfo, SignDeviceCertificate patterns
- `transfer` -- HTTPPushSender, FDOKeyAuthClient for voucher push

## Testing

Test keys and configs are in `test-keys/` and `test-config*.yaml`.
Test output goes to `test-output/` (gitignored).

```bash
# Basic DI test
go run . -config test-config.yaml

# DI with owner signover test
go run . -config test-config-signover.yaml

# Dry run (validate config only)
go run . -config test-config.yaml -dry-run
```
