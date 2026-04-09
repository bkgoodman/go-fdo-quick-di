# go-fdo-quick-di

Self-contained FDO 2.0 Device Initialization tool. Performs both the device
("client") and manufacturing ("server") sides of the DI protocol in a single
integrated flow, without requiring a separate manufacturing server.

## Quickstart

**No config file needed.** Copy the binary to the device and run:

```bash
# Perform DI with sensible defaults (ephemeral key, EC P-256, local output)
./quick-di -quick

# That's it. You now have:
#   cred.bin                          - device credential (stays on device)
#   <guid>.fdoov                      - ownership voucher (take this with you)
```

Override just what you need:

```bash
# Different key type
./quick-di -quick -key-type ec384

# Custom device info and rendezvous server
./quick-di -quick -device-info "Edge Gateway 7" -rv rv.mycompany.com:443:https

# Output to a specific directory (e.g. USB key)
./quick-di -quick -output-dir /mnt/usb/vouchers
```

The `-quick` flag implies: ephemeral manufacturer key (generated in memory,
never on disk), EC P-256, rendezvous at `rvserver.local:8080`, output in
the current directory. See [TRUST_MODELS.md](TRUST_MODELS.md) for why
ephemeral mode is appropriate for many deployments.

## Inspecting What Was Created

After DI, you can examine the device credential and voucher -- no config
file needed for any of these:

```bash
# Show what's stored in the device credential (blob file or TPM)
./quick-di -inspect

# Show the contents of a voucher file
./quick-di -inspect-voucher <guid>.fdoov
```

Example `-inspect` output:

```
=== Device Credential ===
  Version          : 101
  GUID             : 2719a3e914266b86e0937fa19e6244e8
  Device Info      : FDO Device
  Device Key       : ECDSA P-256
  PublicKeyHash alg: Sha256Hash
  PublicKeyHash    : 01d8773732b494bb...
  RV Directives    : 1
    Directive 0:
      DNS = rvserver.local
      DevPort = 8080
      Protocol = HTTP
  DAK fingerprint  : 1d2a715951928d6b...
  Credential store : blob
```

On TPM builds, `-inspect` additionally shows the raw TPM storage layout:
NV index addresses, persistent key handles, DCTPM magic, hierarchy info,
and the DAK public key curve/coordinates.

Example `-inspect-voucher` output:

```
=== Ownership Voucher ===
  GUID             : 2719a3e914266b86e0937fa19e6244e8
  Device Info      : FDO Device
  Manufacturer Key : ECDSA P-256 (encoding=1)
  HMAC             : HmacSha256Hash (32 bytes)
  RV Directives    : 1
    Directive 0:
      DNS = rvserver.local
      DevPort = 8080
      Protocol = HTTP
  Device Cert Chain: 2 certificate(s)
    [0] CN=device.quick-di  Issuer=Quick-DI Ephemeral CA  SHA256=a2aba8de...
    [1] CN=Quick-DI Ephemeral CA  Issuer=Quick-DI Ephemeral CA  SHA256=b0281ab1...
  OV Entries       : 0
  Voucher SHA-256  : d65da32d61edee2f...
```

## Verifying a Voucher Against the Device

Verify that a voucher matches the credential stored on this device:

```bash
./quick-di -verify <guid>.fdoov
```

This checks:
- **GUID match** -- credential and voucher refer to the same device
- **HMAC integrity** -- voucher header was not tampered with
- **Manufacturer key hash** -- matches what the device stored during DI
- **Cert chain hash** -- device certificate chain is intact
- **Entry chain signatures** -- ownership extensions are cryptographically valid

On **TPM builds**, verification also performs a live **DAK possession proof**:
the TPM signs a random challenge with the Device Attestation Key, and the
signature is verified against the public key in the voucher's device
certificate. This proves *this specific TPM* is the one the voucher was
created for.

```
  --- DAK Possession Proof (TPM challenge-response) ---
  DAK challenge    : a1b2c3d4... (random nonce)
  DAK signature    : 3045022100... (72 bytes)
  DAK fingerprint  : 9f81330944bfad30...
  Voucher cert CN  : device.quick-di
  DAK key match    : OK (TPM key == voucher device cert key)
  DAK proof        : OK (TPM proved possession of private key)
```

## Use Cases

### Factory floor without HSM

Some device manufacturers don't have the infrastructure for a full
manufacturing station (server + HSM). Load `quick-di` onto a USB key,
plug it into each device, run it, collect the vouchers.

### User-initiated in-field DI

IT administrators can run DI on devices they physically possess.
The trust anchor is the **user's identity** (authenticated to a management
system via SSO, API key, etc.), not a manufacturer key. Run `quick-di`,
upload the voucher to fleet management using your own credentials.

### Manufacturer key modes

| Mode | Description |
|------|-------------|
| `file` | Manufacturer private key loaded from PEM file. Real provenance but key theft risk. |
| `ephemeral` | Key generated in memory per run, never on disk. No theft risk, no provenance. `-quick` uses this. |

See [TRUST_MODELS.md](TRUST_MODELS.md) for a detailed analysis of the
security trade-offs.

## Config File Mode

For full control, use a YAML config file instead of `-quick`:

```bash
./quick-di -config config.yaml
```

See `config_example.yaml` for a fully commented example. Key settings:

```yaml
# Manufacturer key mode: "file" or "ephemeral"
manufacturer_key_mode: "file"
manufacturer_key_file: "keys/manufacturer_private.pem"

device:
  key_type: "ec384"
  credential_path: "cred.bin"
  device_info: "MyDevice"

rendezvous:
  entries:
    - host: "rvserver.local"
      port: 8080
      scheme: "http"

owner_signover:
  enabled: true
  next_owner_public_key_file: "keys/next_owner_public.pem"

voucher_output:
  directory: "vouchers"

push:
  enabled: false
  url: "https://owner-service.example.com/api/v1/vouchers"
  auth_method: "bearer"
  auth_token: "secret"
```

CLI flags override config file values -- useful for per-device overrides:

```bash
./quick-di -config config.yaml -device-info "Unit SN-12345" -output-dir /mnt/usb
```

## Building

### Credential storage backends

| Build tag | Credential storage | Notes |
|-----------|--------------------|-------|
| *(none)* | **Blob file** -- CBOR on disk | Default. Pure software. |
| `tpm` | **Hardware TPM** -- keys in TPM NV | Requires `/dev/tpmrm0`. |
| `tpmsim` | **TPM simulator** | Requires CGO. For testing. |

### Native builds

```bash
go build -o quick-di .                              # Blob (default)
go build -tags=tpm -o quick-di-tpm .                # Hardware TPM
CGO_ENABLED=1 go build -tags=tpmsim -o quick-di-tpmsim .  # TPM sim
```

### Cross-compilation

```bash
# ARM64 Linux (Raspberry Pi, edge gateways, ARM servers)
GOOS=linux GOARCH=arm64 go build -o quick-di-linux-arm64 .
GOOS=linux GOARCH=arm64 go build -tags=tpm -o quick-di-linux-arm64-tpm .

# ARMv7 Linux (32-bit, older Raspberry Pi)
GOOS=linux GOARCH=arm GOARM=7 go build -o quick-di-linux-armv7 .
GOOS=linux GOARCH=arm GOARM=7 go build -tags=tpm -o quick-di-linux-armv7-tpm .

# x86-64 Linux
GOOS=linux GOARCH=amd64 go build -o quick-di-linux-amd64 .
GOOS=linux GOARCH=amd64 go build -tags=tpm -o quick-di-linux-amd64-tpm .
```

All builds are **statically linked** -- copy the binary to a USB key or
target device and run. No Go installation or shared libraries needed.

### Running with a hardware TPM

TPM builds need read/write access to `/dev/tpmrm0` (run as root or add
user to `tss` group). **No special environment variables needed** -- the
default uses Owner hierarchy, which works in Linux userspace:

```bash
./quick-di-tpm -quick
```

TPM settings via config file or flags:

```yaml
tpm:
  hierarchy: "owner"    # "owner" (default) or "platform"
  key_method: "child"   # "child" (default) or "primary"
```

```bash
./quick-di-tpm -quick -tpm-hierarchy platform -tpm-key-method primary
```

**Why Owner hierarchy by default?** The FDO spec calls for Platform
hierarchy, but on Linux it's locked after boot -- even as root. Owner
hierarchy is the practical default for userspace tools.

## Walkthrough

For a scripted demo that generates keys, runs DI in multiple modes,
and introspects everything under the covers:

```bash
./walkthrough.sh
```

## All Flags

```
Quick mode (no config file needed):
  quick-di -quick                           Ephemeral key, ec256, local output
  quick-di -quick -key-type ec384           Override key type
  quick-di -quick -device-info "My Edge"    Override device info
  quick-di -quick -rv rv.corp.com:443:https Override rendezvous
  quick-di -quick -output-dir /mnt/usb/out  Override output location

Config file mode:
  quick-di -config config.yaml              Full config from YAML file
  quick-di -config config.yaml -key-type ec256  Override specific fields

Inspection and verification:
  quick-di -inspect                          Show stored credential
  quick-di -inspect-voucher path/to.fdoov    Show voucher contents
  quick-di -verify path/to.fdoov             Verify voucher vs credential

Other:
  quick-di -dry-run -debug                   Show config without executing
  quick-di -help                             Full flag reference
```

## Further Reading

- [TRUST_MODELS.md](TRUST_MODELS.md) -- Security trade-offs: HSM vs PEM file vs ephemeral vs user-initiated DI
- [TPM_HANDLES.md](TPM_HANDLES.md) -- TPM handle configuration and IDevID/LDevID reuse (design)
- [config_example.yaml](config_example.yaml) -- Fully commented config reference
