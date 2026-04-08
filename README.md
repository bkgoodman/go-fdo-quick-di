# go-fdo-quick-di

Self-contained FDO 2.0 Device Initialization tool. Performs both the device
("client") and manufacturing ("server") sides of the DI protocol in a single
integrated flow, without requiring a separate manufacturing server.

## Use Cases

### Factory floor without HSM

Some device manufacturers don't have the infrastructure for a full
manufacturing station (server + HSM on the factory floor). This tool provides
a simpler alternative:

1. Load it onto a USB key along with config (and optionally a manufacturer key)
2. Insert the USB key into each device
3. Run the tool -- it creates device credentials and an Ownership Voucher
4. Collect the vouchers (on the USB key or push to a remote endpoint)

### User-initiated in-field DI

End-users or IT administrators can run DI on devices they physically possess.
The trust anchor is the **user's identity** (authenticated to a management
system via SSO, API key, etc.), not a manufacturer key. The user runs
`quick-di`, then uploads the voucher to their fleet management system using
their own credentials. The management system trusts the user, not the
manufacturer key.

### Manufacturer key modes

| Mode | Description |
|------|-------------|
| `file` | Manufacturer private key loaded from PEM file. Real provenance but key theft risk. |
| `ephemeral` | Key generated in memory per run, never on disk. No theft risk, no provenance. |

See [TRUST_MODELS.md](TRUST_MODELS.md) for a detailed analysis of when to
use each mode and the security trade-offs vs. a proper HSM-backed
manufacturing station.

## Quick Walkthrough

To build and see a quick walkthrough of it running, just do:

`./walkthrough.sh`

## Building

```bash
# Standard build (software credential storage)
go build -o quick-di .

# TPM build (credentials stored in TPM hardware)
go build -tags=tpm -o quick-di-tpm .

# TPM simulator build (for testing without hardware)
go build -tags=tpmsim -o quick-di-tpmsim .
```

## Usage

```bash
# Basic usage with config file
./quick-di -config config.yaml

# Validate config without executing
./quick-di -config config.yaml -dry-run

# With debug output
./quick-di -config config.yaml -debug
```

## Configuration

See `config_example.yaml` for a fully commented example. Key settings:

```yaml
# Required: manufacturer private key (PEM)
manufacturer_key_file: "keys/manufacturer_private.pem"

# Optional: manufacturer certificate chain (PEM)
# If omitted, a self-signed certificate is generated.
manufacturer_cert_file: "keys/manufacturer_cert.pem"

# Device key type and storage
device:
  key_type: "ec384"          # ec256, ec384, rsa2048, rsa3072
  credential_path: "cred.bin"
  device_info: "MyDevice"

# Rendezvous info (where the device will look for owner during TO1)
rendezvous:
  entries:
    - host: "rvserver.local"
      port: 8080
      scheme: "http"

# Optional: extend voucher to next owner
owner_signover:
  enabled: true
  next_owner_public_key_file: "keys/next_owner_public.pem"

# Where to save .fdoov files
voucher_output:
  directory: "vouchers"

# Optional: push vouchers to a remote endpoint
push:
  enabled: false
  url: "https://owner-service.example.com/api/v1/vouchers"
  auth_method: "bearer"   # or "fdokeyauth"
  auth_token: "secret"
```

## What It Does

The tool performs these steps in a single run:

1. **Loads manufacturer key** from PEM file
2. **Opens credential store** (blob file or TPM)
3. **Generates device key** and HMAC secrets via the credential store
4. **Signs a device certificate** using the manufacturer CA key
5. **Builds a VoucherHeader** with GUID, rendezvous info, manufacturer key
6. **Computes HMAC** of the VoucherHeader using the device's HMAC secret
7. **Assembles a complete Ownership Voucher**
8. *(Optional)* **Extends the voucher** to a next owner (signs it over)
9. **Saves device credentials** to blob file or TPM
10. **Saves the voucher** as a PEM-encoded `.fdoov` file
11. *(Optional)* **Pushes the voucher** to a remote endpoint

## Output

- **Device credential**: Stored at `device.credential_path` (default: `cred.bin`)
- **Ownership Voucher**: Saved as `{GUID}.fdoov` in `voucher_output.directory`

## Voucher Push

Two authentication methods are supported for pushing vouchers:

- **Bearer token**: Simple `Authorization: Bearer <token>` header
- **FDOKeyAuth**: Cryptographic challenge-response handshake using the
  FDO Voucher Transfer Protocol (requires a supplier private key)

## Dependencies

This project uses the [go-fdo](https://github.com/fido-device-onboard/go-fdo)
library as a git submodule. The `cred` package provides credential storage
with build-tag-selected backends (blob, TPM, TPM simulator).
