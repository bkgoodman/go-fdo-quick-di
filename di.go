// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"hash"
	"math/big"
	"net"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cred"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// performDI executes the entire Device Initialization flow locally.
//
// This performs both the "client" and "server" sides of DI in a single
// integrated flow, without any network transport. It directly calls the
// go-fdo library functions to:
//  1. Generate device key material and HMAC secrets
//  2. Sign a device certificate using the manufacturer key
//  3. Build a VoucherHeader (GUID, RV info, manufacturer key)
//  4. Compute HMAC of the VoucherHeader
//  5. Assemble a complete Ownership Voucher
//  6. Optionally extend the voucher to a next owner
//  7. Save device credentials and voucher to disk
//  8. Optionally push the voucher to a remote endpoint
func performDI(cfg *Config) error {
	// --- Obtain manufacturer key (file or ephemeral) ---
	mfgKey, err := obtainManufacturerKey(cfg)
	if err != nil {
		return fmt.Errorf("manufacturer key: %w", err)
	}
	fmt.Printf("Manufacturer key: %s [mode: %s]\n", keyTypeName(mfgKey.Public()), cfg.ManufacturerKeyMode)

	// --- Load or generate manufacturer certificate chain ---
	mfgChain, err := loadOrGenerateMfgCert(cfg, mfgKey)
	if err != nil {
		return fmt.Errorf("manufacturer certificate: %w", err)
	}
	fmt.Printf("Manufacturer cert: CN=%s\n", mfgChain[0].Subject.CommonName)

	// --- Determine key types ---
	keyType, err := parseKeyType(cfg.Device.KeyType)
	if err != nil {
		return err
	}
	keyEncoding, err := parseKeyEncoding(cfg.Device.KeyEncoding)
	if err != nil {
		return err
	}

	// --- Open credential store and generate device key + HMAC ---
	fmt.Printf("Credential store: %s\n", credentialBackend)
	store, err := cred.Open(cfg.Device.CredentialPath)
	if err != nil {
		return fmt.Errorf("opening credential store: %w", err)
	}
	defer func() { _ = store.Close() }()

	hmac256, hmac384, deviceKey, err := store.NewDI(keyType)
	if err != nil {
		return fmt.Errorf("generating device credentials: %w", err)
	}
	fmt.Printf("Device key: %s\n", keyTypeName(deviceKey.Public()))

	// --- Sign device certificate ---
	deviceCertChain, err := signDeviceCert(mfgKey, mfgChain, deviceKey)
	if err != nil {
		return fmt.Errorf("signing device certificate: %w", err)
	}
	fmt.Printf("Device cert: CN=%s (chain length %d)\n",
		deviceCertChain[0].Subject.CommonName, len(deviceCertChain))

	// --- Build VoucherHeader ---
	mfgPubKey, err := encodeMfgPublicKey(keyType, keyEncoding, mfgKey.Public(), mfgChain)
	if err != nil {
		return fmt.Errorf("encoding manufacturer public key: %w", err)
	}

	rvInfo, err := buildRvInfo(cfg)
	if err != nil {
		return fmt.Errorf("building rendezvous info: %w", err)
	}

	deviceInfo := cfg.Device.DeviceInfo
	if deviceInfo == "" {
		deviceInfo = "FDO-Device"
	}

	// Generate GUID
	var guid protocol.GUID
	if _, err := rand.Read(guid[:]); err != nil {
		return fmt.Errorf("generating GUID: %w", err)
	}

	// Compute cert chain hash
	alg, err := selectHashAlg(deviceKey.Public(), mfgKey.Public())
	if err != nil {
		return fmt.Errorf("selecting hash algorithm: %w", err)
	}
	certChainHash := alg.HashFunc().New()
	for _, cert := range deviceCertChain {
		_, _ = certChainHash.Write(cert.Raw)
	}

	ovh := &fdo.VoucherHeader{
		Version:         101,
		GUID:            guid,
		RvInfo:          rvInfo,
		DeviceInfo:      deviceInfo,
		ManufacturerKey: *mfgPubKey,
		CertChainHash: &protocol.Hash{
			Algorithm: alg,
			Value:     certChainHash.Sum(nil),
		},
	}

	// --- Compute HMAC of VoucherHeader ---
	hmacValue, err := computeHMAC(hmac256, hmac384, alg, ovh)
	if err != nil {
		return fmt.Errorf("computing HMAC: %w", err)
	}

	// --- Compute manufacturer public key hash (for device credential) ---
	ownerKeyDigest := alg.HashFunc().New()
	if err := cbor.NewEncoder(ownerKeyDigest).Encode(mfgPubKey); err != nil {
		return fmt.Errorf("hashing manufacturer key: %w", err)
	}
	ownerKeyHash := protocol.Hash{Algorithm: alg, Value: ownerKeyDigest.Sum(nil)}

	// --- Assemble complete Voucher ---
	certChainCBOR := make([]*cbor.X509Certificate, len(deviceCertChain))
	for i, cert := range deviceCertChain {
		certChainCBOR[i] = (*cbor.X509Certificate)(cert)
	}

	voucher := &fdo.Voucher{
		Version:   101,
		Header:    *cbor.NewBstr(*ovh),
		Hmac:      hmacValue,
		CertChain: &certChainCBOR,
		Entries:   nil,
	}

	fmt.Printf("Voucher created: GUID=%s\n", guid)

	// --- Optional: extend voucher to next owner ---
	if cfg.OwnerSignover.Enabled {
		voucher, err = extendToNextOwner(cfg, voucher, mfgKey)
		if err != nil {
			return fmt.Errorf("extending voucher: %w", err)
		}
		fmt.Println("Voucher extended to next owner")
	}

	// --- Save device credential ---
	dc := fdo.DeviceCredential{
		Version:       101,
		DeviceInfo:    deviceInfo,
		GUID:          guid,
		RvInfo:        rvInfo,
		PublicKeyHash: ownerKeyHash,
	}
	if err := store.Save(dc); err != nil {
		return fmt.Errorf("saving device credential: %w", err)
	}
	if credentialBackend == "blob" {
		fmt.Printf("Device credential saved: %s\n", cfg.Device.CredentialPath)
	} else {
		fmt.Printf("Device credential saved: %s (TPM NV indices)\n", credentialBackend)
	}

	// --- Save voucher as PEM .fdoov ---
	ovPath, err := saveVoucherPEM(voucher, guid, cfg.VoucherOutput.Directory)
	if err != nil {
		return fmt.Errorf("saving voucher: %w", err)
	}
	fmt.Printf("Voucher saved: %s\n", ovPath)

	// --- Optional: push voucher ---
	if cfg.Push.Enabled {
		if err := pushVoucher(cfg, voucher, guid); err != nil {
			return fmt.Errorf("pushing voucher: %w", err)
		}
		fmt.Printf("Voucher pushed to: %s\n", cfg.Push.URL)
	}

	fmt.Println("DI completed successfully")
	return nil
}

// obtainManufacturerKey returns a manufacturer private key based on the
// configured mode.
//
// In "file" mode, the key is loaded from a PEM file on disk.
// In "ephemeral" mode, a fresh key is generated in memory and never persisted.
func obtainManufacturerKey(cfg *Config) (crypto.Signer, error) {
	switch cfg.ManufacturerKeyMode {
	case MfgKeyModeFile:
		return loadPrivateKey(cfg.ManufacturerKeyFile)

	case MfgKeyModeEphemeral:
		return generateEphemeralKey(cfg.ManufacturerKeyType)

	default:
		return nil, fmt.Errorf("unsupported manufacturer_key_mode: %q", cfg.ManufacturerKeyMode)
	}
}

// generateEphemeralKey creates a random private key in memory.
// The key is never written to disk and is discarded when the process exits.
func generateEphemeralKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case "ec256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	default:
		return nil, fmt.Errorf("unsupported ephemeral key type: %q", keyType)
	}
}

// loadOrGenerateMfgCert loads a manufacturer certificate chain from config,
// or generates a self-signed certificate if none is configured.
// In ephemeral mode, the cert file is always ignored.
func loadOrGenerateMfgCert(cfg *Config, mfgKey crypto.Signer) ([]*x509.Certificate, error) {
	// In file mode, try loading from disk first
	if cfg.ManufacturerKeyMode == MfgKeyModeFile {
		chain, err := loadCertChain(cfg.ManufacturerCertFile)
		if err != nil {
			return nil, err
		}
		if chain != nil {
			return chain, nil
		}
	}

	// Generate self-signed CA certificate
	cn := "Quick-DI Manufacturer CA"
	if cfg.ManufacturerKeyMode == MfgKeyModeEphemeral {
		cn = "Quick-DI Ephemeral CA"
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, mfgKey.Public(), mfgKey)
	if err != nil {
		return nil, fmt.Errorf("creating self-signed cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing self-signed cert: %w", err)
	}
	if cfg.ManufacturerKeyMode == MfgKeyModeEphemeral {
		fmt.Println("Note: ephemeral mode -- manufacturer key exists only in memory")
	} else {
		fmt.Println("Note: using auto-generated self-signed manufacturer certificate")
	}
	return []*x509.Certificate{cert}, nil
}

// signDeviceCert creates a device certificate by signing a CSR with the
// manufacturer CA key. This replicates the server-side DI behavior from
// custom.SignDeviceCertificate.
func signDeviceCert(mfgKey crypto.Signer, mfgChain []*x509.Certificate, deviceKey crypto.Signer) ([]*x509.Certificate, error) {
	// Create CSR from device key
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device.quick-di"},
	}, deviceKey)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}

	// Sign with manufacturer CA
	template := &x509.Certificate{
		Issuer:    mfgChain[0].Subject,
		Subject:   csr.Subject,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(30 * 360 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, mfgChain[0], csr.PublicKey, mfgKey)
	if err != nil {
		return nil, fmt.Errorf("signing device cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing device cert: %w", err)
	}
	return append([]*x509.Certificate{cert}, mfgChain...), nil
}

// encodeMfgPublicKey creates a protocol.PublicKey from the manufacturer's key.
func encodeMfgPublicKey(keyType protocol.KeyType, keyEncoding protocol.KeyEncoding, pub crypto.PublicKey, chain []*x509.Certificate) (*protocol.PublicKey, error) {
	switch keyEncoding {
	case protocol.X509KeyEnc, protocol.CoseKeyEnc:
		asCOSE := keyEncoding == protocol.CoseKeyEnc
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			return protocol.NewPublicKey(keyType, k, asCOSE)
		case *rsa.PublicKey:
			return protocol.NewPublicKey(keyType, k, asCOSE)
		default:
			return nil, fmt.Errorf("unsupported public key type: %T", pub)
		}
	case protocol.X5ChainKeyEnc:
		return protocol.NewPublicKey(keyType, chain, false)
	default:
		return nil, fmt.Errorf("unsupported key encoding: %d", keyEncoding)
	}
}

// buildRvInfo converts config rendezvous entries to protocol RvInstruction format.
func buildRvInfo(cfg *Config) ([][]protocol.RvInstruction, error) {
	var allDirectives [][]protocol.RvInstruction

	for i, entry := range cfg.Rendezvous.Entries {
		var rvInstructions []protocol.RvInstruction

		// Host: IP or DNS
		if ip := net.ParseIP(entry.Host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			ipBytes, err := cbor.Marshal([]byte(ip))
			if err != nil {
				return nil, fmt.Errorf("entry %d: encoding IP: %w", i+1, err)
			}
			rvInstructions = append(rvInstructions, protocol.RvInstruction{
				Variable: protocol.RVIPAddress, Value: ipBytes,
			})
		} else {
			dnsBytes, err := cbor.Marshal(entry.Host)
			if err != nil {
				return nil, fmt.Errorf("entry %d: encoding DNS: %w", i+1, err)
			}
			rvInstructions = append(rvInstructions, protocol.RvInstruction{
				Variable: protocol.RVDns, Value: dnsBytes,
			})
		}

		// Port (device and owner)
		portBytes, err := cbor.Marshal(uint16(entry.Port)) //nolint:gosec // validated in config
		if err != nil {
			return nil, fmt.Errorf("entry %d: encoding port: %w", i+1, err)
		}
		rvInstructions = append(rvInstructions,
			protocol.RvInstruction{Variable: protocol.RVDevPort, Value: portBytes},
			protocol.RvInstruction{Variable: protocol.RVOwnerPort, Value: portBytes},
		)

		// Protocol
		var protoVal uint8 = 1 // HTTP
		if entry.Scheme == "https" {
			protoVal = 2
		}
		protoBytes, err := cbor.Marshal(protoVal)
		if err != nil {
			return nil, fmt.Errorf("entry %d: encoding protocol: %w", i+1, err)
		}
		rvInstructions = append(rvInstructions, protocol.RvInstruction{
			Variable: protocol.RVProtocol, Value: protoBytes,
		})

		allDirectives = append(allDirectives, rvInstructions)
	}

	return allDirectives, nil
}

// selectHashAlg determines the appropriate hash algorithm based on device
// and owner key types, matching the logic in go-fdo's hashAlgFor.
func selectHashAlg(devicePubKey, ownerPubKey crypto.PublicKey) (protocol.HashAlg, error) {
	deviceSize, err := hashSizeForKey(devicePubKey)
	if err != nil {
		return 0, fmt.Errorf("device key: %w", err)
	}
	ownerSize, err := hashSizeForKey(ownerPubKey)
	if err != nil {
		return 0, fmt.Errorf("owner key: %w", err)
	}
	if deviceSize < ownerSize {
		return protocol.Sha256Hash, nil
	}
	if ownerSize < deviceSize {
		return protocol.Sha256Hash, nil
	}
	// Equal sizes
	switch deviceSize {
	case 256:
		return protocol.Sha256Hash, nil
	case 384:
		return protocol.Sha384Hash, nil
	default:
		return protocol.Sha256Hash, nil
	}
}

func hashSizeForKey(pub crypto.PublicKey) (int, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return 256, nil
		case elliptic.P384():
			return 384, nil
		default:
			return 0, fmt.Errorf("unsupported curve: %s", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return k.Size(), nil
	default:
		return 0, fmt.Errorf("unsupported key type: %T", pub)
	}
}

// computeHMAC computes the HMAC of a VoucherHeader, matching go-fdo's
// hmacHash function (which CBOR-encodes the header then HMACs it).
func computeHMAC(hmac256, hmac384 hash.Hash, alg protocol.HashAlg, ovh *fdo.VoucherHeader) (protocol.Hmac, error) {
	var h hash.Hash
	var hmacAlg protocol.HashAlg

	switch alg {
	case protocol.Sha256Hash:
		h = hmac256
		hmacAlg = protocol.HmacSha256Hash
	case protocol.Sha384Hash:
		if hmac384 == nil {
			h = hmac256
			hmacAlg = protocol.HmacSha256Hash
		} else {
			h = hmac384
			hmacAlg = protocol.HmacSha384Hash
		}
	default:
		return protocol.Hmac{}, fmt.Errorf("unsupported hash algorithm: %s", alg)
	}

	// Match go-fdo: CBOR-encode the VoucherHeader, then HMAC it
	h.Reset()
	if err := cbor.NewEncoder(h).Encode(ovh); err != nil {
		return protocol.Hmac{}, fmt.Errorf("CBOR-encoding header for HMAC: %w", err)
	}

	return protocol.Hmac{
		Algorithm: hmacAlg,
		Value:     h.Sum(nil),
	}, nil
}

// extendToNextOwner loads the next-owner public key and extends the voucher.
func extendToNextOwner(cfg *Config, voucher *fdo.Voucher, mfgKey crypto.Signer) (*fdo.Voucher, error) {
	nextOwnerPub, err := loadPublicKey(cfg.OwnerSignover.NextOwnerPublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading next-owner key: %w", err)
	}
	fmt.Printf("Next owner key: %s\n", keyTypeName(nextOwnerPub))

	switch k := nextOwnerPub.(type) {
	case *ecdsa.PublicKey:
		return fdo.ExtendVoucher(voucher, mfgKey, k, nil)
	case *rsa.PublicKey:
		return fdo.ExtendVoucher(voucher, mfgKey, k, nil)
	default:
		return nil, fmt.Errorf("unsupported next-owner key type: %T", nextOwnerPub)
	}
}

// parseKeyType converts a config string to protocol.KeyType.
func parseKeyType(s string) (protocol.KeyType, error) {
	switch s {
	case "ec256":
		return protocol.Secp256r1KeyType, nil
	case "ec384":
		return protocol.Secp384r1KeyType, nil
	case "rsa2048":
		return protocol.Rsa2048RestrKeyType, nil
	case "rsa3072":
		return protocol.RsaPkcsKeyType, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %q", s)
	}
}

// parseKeyEncoding converts a config string to protocol.KeyEncoding.
func parseKeyEncoding(s string) (protocol.KeyEncoding, error) {
	switch s {
	case "x509":
		return protocol.X509KeyEnc, nil
	case "x5chain":
		return protocol.X5ChainKeyEnc, nil
	case "cose":
		return protocol.CoseKeyEnc, nil
	default:
		return 0, fmt.Errorf("unsupported key encoding: %q", s)
	}
}

// computeVoucherFingerprint returns a hex-encoded SHA-256 hash of the CBOR-encoded voucher.
func computeVoucherFingerprint(voucher *fdo.Voucher) string {
	data, err := cbor.Marshal(voucher)
	if err != nil {
		return "(error)"
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:8])
}

// Ensure sha512 import is used (for SHA-384 size constant reference in selectHashAlg)
var _ = sha512.New384
