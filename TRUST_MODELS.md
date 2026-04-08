# Trust Models for Quick-DI

This document discusses the security trade-offs of the different manufacturer
key modes available in `quick-di`, and how they compare to a proper
manufacturing station with HSM.

## Who Runs This Tool?

`quick-di` is not exclusively a factory tool. It may be run by:

- **A manufacturer** on a factory floor (the original FDO use case)
- **A supply chain intermediary** (reseller, distributor, VAR)
- **An end-user or IT administrator** onboarding a device themselves

The same binary and the same config options serve all three cases. What
changes is the *trust model* -- who is the trust anchor, and why should
a management system believe the resulting voucher?

## Background: What the Manufacturer Key Does

In FDO Device Initialization, the **manufacturer key** serves two purposes:

1. **Signs the device certificate** -- the device's attestation key (DAK) is
   certified by a CA chain rooted at the manufacturer key.

2. **Appears in the Ownership Voucher header** -- the voucher's
   `ManufacturerKey` field identifies who created the voucher. Every party
   in the supply chain can see this field.

During TO2 (Transfer of Ownership), the device verifies that the voucher it
receives contains the same manufacturer key hash it stored during DI. This
binds the device to its voucher. The ownership entry chain then proves an
unbroken sequence of signovers from the DI originator to the current owner.

## The Trust Models

When someone receives an Ownership Voucher, they must answer: **"Why should
I trust this voucher is legitimate?"** There are several possible answers,
corresponding to different deployment models:

---

### Model 1: HSM on the Factory Floor (Gold Standard)

```
                   ┌──────────────┐
                   │   HSM        │
 Manufacturer Key  │  (never      │──── signs voucher
 is KNOWN, PUBLIC  │   leaves)    │
                   └──────────────┘
                          │
        ┌─────────────────┼────────────────────┐
        │                 │                    │
   Published in      Signs device         Voucher header
   trust registry    certificates         identifies mfg
```

**Trust anchor:** The manufacturer's well-known public key.

Anyone receiving a voucher can verify: *"This device was initialized by
Manufacturer X, whose public key I know from an out-of-band registry or
business relationship."*

| Property | Value |
|----------|-------|
| Key exposure risk | None (key never leaves HSM) |
| Manufacturer provenance | Full -- cryptographically verifiable |
| Who trusts whom | Recipient trusts the manufacturer identity |
| Infrastructure needed | HSM, manufacturing server, key ceremony |

**This is the model used by `go-fdo-manufacturing-station`.** It is
always preferred when the infrastructure exists.

---

### Model 2: PEM File on USB Key (`manufacturer_key_mode: file`)

```
                   ┌──────────────┐
                   │  USB Key     │
 Manufacturer Key  │  (PEM file   │──── signs voucher
 is KNOWN, but     │   on disk)   │
 EXPOSED           └──────────────┘
                          │
        ┌─────────────────┼────────────────────┐
        │                 │                    │
   Same key used     Signs device         Voucher header
   across devices    certificates         identifies mfg
```

**Trust anchor:** Same as HSM -- the manufacturer's known public key.

The voucher is cryptographically identical to one produced by an HSM. A
recipient verifies provenance the same way. The difference is purely
operational: the private key exists as a file that could be copied or
stolen.

| Property | Value |
|----------|-------|
| Key exposure risk | **HIGH** -- PEM file on removable media |
| Manufacturer provenance | Full -- same as HSM from verifier's perspective |
| Who trusts whom | Recipient trusts the manufacturer identity |
| Infrastructure needed | Just the USB key with quick-di |
| Key theft impact | Attacker can forge vouchers for any device |

**Mitigations:** Physical security of the USB key. Rotation/revocation
procedures. Audit logging of USB key usage. Encryption of the USB key at
rest.

**When to use:** Manufacturer has a known identity and key pair (perhaps
generated in a secure ceremony), but lacks the infrastructure for an
on-floor HSM server. The key is loaded onto USB keys that are physically
controlled.

---

### Model 3: Ephemeral Key (`manufacturer_key_mode: ephemeral`)

```
                   ┌──────────────┐
                   │   Memory     │
 Manufacturer Key  │  (generated, │──── signs voucher
 is RANDOM,        │   used once, │
 UNKNOWN,          │   discarded) │
 UNRECOVERABLE     └──────────────┘
                          │
                          │  (key is gone after process exits)
                          │
                   Voucher header contains
                   an ephemeral key that
                   nobody recognizes
```

**Trust anchor:** NOT the manufacturer key. Trust must come from elsewhere.

No one can verify *"This came from Manufacturer X"* because the key that
signed the voucher is random and gone. Instead, trust comes from one of:

#### 3a. Transit Trust (the next party in the chain)

```
 Ephemeral DI ──→ ExtendVoucher ──→ Known Recipient
   (factory)     (mfg key signs     (their public key
                  over to them)      is well-known)
```

The recipient's identity IS the trust anchor. An end-customer trusts
the voucher not because a known factory made it, but because a known
*party* (reseller, supply chain system, enterprise IT) signed it.

This is analogous to a large company with many physical factories:
- You don't trust "Dell Austin Factory #3"
- You trust "Dell"
- Dell's voucher management system extends the voucher to itself,
  and THAT signature is the trust anchor
- The individual factory's key is irrelevant to the end customer

#### 3b. Delivery Channel Trust

Even without signover, if vouchers are delivered through a trusted
channel (hand-carried USB, VPN, authenticated API), the delivery
mechanism itself provides trust.

| Property | Value |
|----------|-------|
| Key exposure risk | **NONE** -- key never exists on disk |
| Manufacturer provenance | **NONE** -- no persistent manufacturer identity |
| Who trusts whom | Recipient trusts the *delivery channel* or *next signer* |
| Infrastructure needed | Just quick-di; signover strongly recommended |
| Key theft impact | Impossible -- nothing to steal |

**When to use:** The manufacturer's identity doesn't matter to the
supply chain. What matters is that a trusted intermediary (corporate
IT, reseller, supply chain management system) vouches for the device.
The factory is just a step in the process.

---

### Model 4: User-Initiated DI (End-User as Trust Anchor)

```
                   ┌──────────────┐
                   │  End User    │
                   │  runs DI on  │──── creates voucher
                   │  their own   │     (ephemeral or file key)
                   │  device      │
                   └──────┬───────┘
                          │
                          │  User uploads voucher to their
                          │  management system using THEIR
                          │  credentials (SSO, API key, etc.)
                          │
                   ┌──────▼───────┐
                   │  Management  │
                   │  System      │
                   │  (trusts the │
                   │   USER, not  │
                   │   the mfg    │
                   │   key)       │
                   └──────────────┘
```

**Trust anchor:** The *user's identity* as authenticated by the
management system.

This is a fundamentally different use case from factory DI. An IT
administrator (or end-user) runs `quick-di` on a device they
physically possess, then uploads the resulting voucher to their
management service. The management service trusts the voucher not
because of anything cryptographic in the voucher itself, but because
**the authenticated user is asserting: "I ran DI on this device; it
should be onboarded to my organization."**

The manufacturer key in the voucher is irrelevant to the trust
decision. What matters is:

1. The user is authenticated to the management system (SSO, mTLS,
   API key, physical presence)
2. The user is authorized to enroll devices
3. The user is making an explicit claim of possession

This is analogous to how you register a new laptop with your
corporate IT portal -- IT trusts you (the employee) to honestly
report that this is a legitimate company device. They don't verify
the laptop manufacturer's signing key.

| Property | Value |
|----------|-------|
| Key exposure risk | N/A -- key mode doesn't matter |
| Manufacturer provenance | N/A -- not the trust model |
| Who trusts whom | Management system trusts the **authenticated user** |
| Infrastructure needed | quick-di + user's credentials to management system |
| Threat model | Compromised user credentials, or user enrolling rogue device |

**Ephemeral mode is ideal here** -- there's no reason to carry a
manufacturer key file when the user IS the trust anchor. The user runs
`quick-di` with ephemeral mode, gets a voucher, and uploads it. The
management system doesn't care about the manufacturer key; it cares that
User X (whom it authenticated) uploaded it.

**Both modes work:** Ephemeral is cleaner (nothing to manage), but file
mode is fine too (the management system ignores the manufacturer key
either way). The user might also configure signover to the management
system's public key before uploading, though this is optional -- the
management system already trusts the user.

#### Example: IT admin onboarding edge devices

```yaml
# IT admin's USB key / laptop config
manufacturer_key_mode: "ephemeral"

device:
  key_type: "ec384"
  device_info: "edge-node-warehouse-7"
  credential_path: "/mnt/device/cred.bin"

rendezvous:
  entries:
    - host: "rv.mycompany.com"
      port: 443
      scheme: "https"

voucher_output:
  directory: "vouchers"

# Optional: push directly to management API using user's token
push:
  enabled: true
  url: "https://fleet-mgmt.mycompany.com/api/v1/vouchers"
  auth_method: "bearer"
  auth_token: "eyJhbGciOi..."   # User's JWT from SSO
```

The admin:
1. Boots the device
2. Inserts USB key with quick-di
3. Runs `quick-di` -- device gets credentials, voucher is created
4. Voucher is pushed to fleet management using the admin's JWT
5. Fleet management associates voucher with admin's identity
6. Device can now do TO1/TO2 to onboard with the fleet

#### Trust comparison: factory DI vs. user DI

| | Factory DI | User-Initiated DI |
|---|---|---|
| Who runs DI | Manufacturer | End user / IT admin |
| Trust anchor | Manufacturer key or supply chain | User's authenticated identity |
| Voucher value | "This device was made by X" | "User Y claims this device" |
| Mfg key matters? | Yes (Models 1-2) or No (Model 3) | No |
| Threat model | Key theft, supply chain attack | Credential compromise, rogue enrollment |
| Revocation | Revoke manufacturer key | Revoke user credentials |

---

## Comparison Matrix

```
                        HSM          PEM File       Ephemeral      User-Initiated
                     ─────────    ─────────────    ───────────    ────────────────
Key theft risk         None          HIGH            None           N/A

Manufacturer           Full          Full            None           None
provenance                                                         (not the point)

Trust anchor           Mfg key       Mfg key         Next signer    User identity
                                                     or channel

Requires signover?     No            No              Strongly       Optional
                                                     recommended

Infrastructure         HSM +         USB key         Just the       quick-di +
                       server                        binary         user creds

Forensic value of      Traces to     Traces to       Random --      Random or
mfg key in voucher     known mfg     known mfg       no trace       irrelevant

Key rotation           HSM ceremony  Generate new    Automatic      N/A
                                     PEM file        (every run)

Multi-device           Same key      Same key        Different key  Different key
correlation            (traceable)   (traceable)     per device     per device

Who is liable          Manufacturer  Manufacturer    Next signer    The user who
                                                                    enrolled it
```

## Recommendations

### Use HSM / Manufacturing Station when:
- You need verifiable manufacturer provenance
- Compliance or audit requirements mandate it
- You have the infrastructure

### Use PEM file mode when:
- You have a known manufacturer identity and key pair
- You lack on-floor HSM infrastructure
- Physical security of the USB key is manageable
- You need devices traceable to a specific manufacturer key

### Use ephemeral mode when:
- The factory's identity is irrelevant to the trust chain
- Trust comes from a downstream party (enterprise IT, reseller)
- You want zero risk of manufacturer key theft
- You are signing vouchers over to a known next-owner anyway
- The voucher delivery channel is already trusted
- You want no cryptographic correlation between devices
  (each device gets a unique, untraceable manufacturer key)

### Use user-initiated DI when:
- An end-user or IT admin is onboarding a device they physically possess
- The management system authenticates and trusts the *user*, not the
  manufacturer key
- No factory supply chain is involved -- the user IS the supply chain
- The user's credentials (JWT, SSO, API key) are the trust anchor
- Ephemeral mode is the natural fit (no manufacturer identity needed)

### Common ephemeral + signover pattern:

```yaml
# Factory USB key config: ephemeral + signover to corporate IT
manufacturer_key_mode: "ephemeral"

owner_signover:
  enabled: true
  next_owner_public_key_file: "keys/corporate_it_public.pem"
```

The factory creates vouchers with throwaway manufacturer keys, immediately
signs them over to Corporate IT's well-known key, and either pushes them
to Corporate IT's API or collects them on the USB key. Corporate IT then
extends the voucher to the end customer. The end customer trusts Corporate
IT's key, not the factory's (nonexistent) key.

## What "Provenance" Means in Practice

In traditional FDO, a device owner can look at a voucher and answer:

> "Who manufactured this device?"

With ephemeral mode, that question becomes unanswerable from the voucher
alone. But a different question IS answerable:

> "Who vouched for this device entering my supply chain?"

And with user-initiated DI, the question shifts again:

> "Which authenticated user claimed this device for onboarding?"

In many real-world deployments, the second or third question is the one
that actually matters. A datacenter operator doesn't care which specific
factory floor produced a server -- they care that their procurement
system approved it. An IT admin onboarding edge devices in the field
doesn't have a factory at all -- they ARE the provenance.

## The Same Tool, Different Trust Statements

What's notable is that `quick-di` produces the same artifacts in every
case -- a device credential and an ownership voucher. The FDO protocol
doesn't distinguish between a voucher created by a factory HSM and one
created by an IT admin's laptop. The trust model is entirely a function
of the *context* in which the tool is used and how the voucher is
delivered:

| Context | Trust Statement |
|---------|-----------------|
| Factory floor + HSM | "Manufacturer X made this device" |
| Factory floor + PEM file | "Manufacturer X made this device (less securely)" |
| Factory floor + ephemeral | "This device passed through a factory we trust" |
| IT admin + ephemeral + push | "Admin Y enrolled this device" |
| IT admin + ephemeral + USB | "Someone with physical access enrolled this device" |
