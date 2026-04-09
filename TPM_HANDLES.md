# TPM Handle Configuration & IDevID/LDevID Reuse

## Current State

The go-fdo `cred/tpm_store.go` uses hardcoded persistent handles:

| Handle | Object | Value |
|--------|--------|-------|
| `DAKHandle` | Device Attestation Key (ECC signing key) | `0x81020002` |
| `HMACKeyHandle` | HMAC key | `0x81020003` |
| `DCTPMIndex` | NV index for credential metadata (CBOR) | `0x01D10001` |

These are defined in `go-fdo/tpm/nv.go` as constants. The DCTPM NV
structure stores the handles it used, so `Load()` reads them back --
but `NewDI()` always creates at the hardcoded addresses.

## Desired Capabilities

### 1. Configurable handle placement

Some devices have existing TPM objects at the default handles, or
organizational policy requires specific handle ranges. Users should be
able to specify:

```yaml
tpm:
  dak_handle: 0x81020010       # Custom DAK persistent handle
  hmac_handle: 0x81020011      # Custom HMAC persistent handle
  nv_index: 0x01D10010         # Custom NV index for DCTPM
```

**Impact:** Requires changes to `go-fdo/cred/tpm_store.go` and
`go-fdo/tpm/nv.go`. The constants would become configurable fields
on `tpmStore`, passed through `Open()` or a new options struct.

### 2. Use existing key (IDevID / LDevID)

Some devices ship from the factory with an IDevID (Initial Device
Identity) or LDevID (Locally Significant Device Identity) already
provisioned in the TPM. These are ECC or RSA signing keys with
certificates issued by the device manufacturer or a CA.

Instead of creating a new DAK, quick-di should be able to USE an
existing persistent key as the device attestation key:

```yaml
tpm:
  dak_handle: 0x81010001       # Use existing IDevID at this handle
  dak_mode: "use_existing"     # Don't create, just reference
  # hmac_handle and nv_index still created/managed by quick-di
```

**Implications:**
- `NewDI()` would skip DAK creation and just load the existing key
- The DCTPM NV structure already stores `DeviceKeyHandle`, so it
  would record whatever handle was used
- The device certificate chain in the voucher would need to come
  from the IDevID cert, not a freshly-signed CSR
- HMAC key still needs to be created (IDevID doesn't provide HMAC)

### 3. IDevID certificate extraction

When using an existing IDevID, the certificate chain may be stored:
- In a TPM NV index alongside the key
- In a file on the filesystem
- Nowhere (must be obtained out-of-band)

Configuration would need:

```yaml
tpm:
  dak_mode: "use_existing"
  dak_handle: 0x81010001
  dak_cert_source: "nv"          # Read cert from TPM NV index
  dak_cert_nv_index: 0x01C90000  # NV index containing IDevID cert
  # OR
  dak_cert_source: "file"
  dak_cert_file: "/etc/idevid/cert.pem"
```

## Implementation Plan

### Phase 1: go-fdo library changes (in go-fdo repo)

1. **Make handles configurable in `tpm/nv.go`**
   - Change `DAKHandle`, `HMACKeyHandle`, `DCTPMIndex` from constants
     to default values
   - Add `type HandleConfig struct` with fields for each handle
   - Update `ReadNVCredentials`, `CleanupFDOState`, etc. to accept
     handle config

2. **Add options to `cred/tpm_store.go`**
   - New `type TPMOptions struct` with handle config + dak_mode
   - Change `Open(path)` to `Open(path, ...Option)` or similar
   - `NewDI()` checks `dak_mode`:
     - `"create"` (default): current behavior
     - `"use_existing"`: skip creation, load from configured handle
   - Env vars remain as fallback for backward compat

3. **IDevID cert loading**
   - New function `ReadCertFromNV(t TPM, index uint32)` in tpm package
   - `NewDI()` in `use_existing` mode uses the IDevID cert chain
     instead of signing a new CSR

### Phase 2: quick-di integration

1. Add `dak_handle`, `hmac_handle`, `nv_index`, `dak_mode`,
   `dak_cert_source`, `dak_cert_file`, `dak_cert_nv_index` to
   `TPMConfig` in `config.go`

2. Pass options through to `cred.Open()` when the library supports it

3. Update `-inspect` to show custom handles and IDevID details

### Phase 3: Inspection enhancements

With configurable handles, `-inspect` should:
- Scan a range of persistent handles for any FDO-related keys
- Show which handles are in use and which are available
- For IDevID keys, show the certificate subject/issuer
- Compare the DAK in the DCTPM NV against the actual key at the handle

## Workaround (Current)

Until go-fdo library changes are made, users with IDevID keys can:

1. Run quick-di normally (creates a new DAK at the default handle)
2. The IDevID remains untouched at its original handle
3. FDO onboarding uses the quick-di-created DAK, not the IDevID
4. Post-onboarding, the owner service can reference the IDevID
   through service info modules

This is functional but doesn't leverage the existing IDevID as the
FDO device attestation key, which would be the ideal configuration
for devices that already have strong factory-provisioned identity.
