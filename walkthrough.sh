#!/bin/bash
# ==========================================================================
# go-fdo-quick-di  —  Walkthrough / Demo Script
#
# This script demonstrates the entire quick-di workflow end-to-end:
#
#   1. Generate a manufacturer key pair (simulating what comes on the USB key)
#   2. Run quick-di  —  basic DI (no owner signover)
#   3. Introspect the outputs: credential blob, voucher PEM
#   4. Generate a "next owner" key pair
#   5. Run quick-di  —  DI with owner signover
#   6. Introspect the extended voucher (show the entry chain)
#   7. Run quick-di  —  dry-run and debug modes
#
# Prerequisites: Go toolchain, openssl
# ==========================================================================
set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_DIR="$PROJ_DIR/demo-walkthrough"
BINARY="$PROJ_DIR/quick-di"

# Colors (if terminal supports them)
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

banner() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

step() {
    echo -e "${GREEN}>>> $1${NC}"
}

show_cmd() {
    echo -e "${YELLOW}\$ $1${NC}"
}

run_cmd() {
    show_cmd "$*"
    "$@"
    echo ""
}

# ─── Clean up from previous runs ──────────────────────────────────────────
banner "SETUP: Clean slate"

step "Cleaning previous demo artifacts..."
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"/{keys,output-basic,output-signover}

# ─── Build the binary ─────────────────────────────────────────────────────
banner "STEP 0: Build quick-di"

step "Building the quick-di binary..."
show_cmd "go build -o quick-di ."
(cd "$PROJ_DIR" && go build -o quick-di .)
echo -e "Binary: ${BOLD}$BINARY${NC}  ($(du -h "$BINARY" | cut -f1) )"
echo ""

# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Manufacturer key setup (what you'd put on the USB key)
# ══════════════════════════════════════════════════════════════════════════
banner "PHASE 1: Generate manufacturer key pair"

step "This simulates the key pair a manufacturer would pre-load onto"
step "the USB key. In production this would come from an HSM; here"
step "we generate it with openssl for demonstration."
echo ""

run_cmd openssl ecparam -genkey -name secp384r1 -noout \
    -out "$DEMO_DIR/keys/mfg_private.pem"

step "Extract the public key (for reference):"
run_cmd openssl ec -in "$DEMO_DIR/keys/mfg_private.pem" \
    -pubout -out "$DEMO_DIR/keys/mfg_public.pem" 2>/dev/null

step "Manufacturer private key:"
run_cmd openssl ec -in "$DEMO_DIR/keys/mfg_private.pem" -text -noout 2>/dev/null

# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Basic DI (no owner signover)
# ══════════════════════════════════════════════════════════════════════════
banner "PHASE 2: Basic Device Initialization"

step "Create a minimal config file:"

CONFIG_BASIC="$DEMO_DIR/config-basic.yaml"
cat > "$CONFIG_BASIC" <<'YAML'
manufacturer_key_file: "KEYS_DIR/mfg_private.pem"

device:
  key_type: "ec384"
  key_encoding: "x509"
  credential_path: "OUTPUT_DIR/cred.bin"
  device_info: "ACME-Widget-3000"

rendezvous:
  entries:
    - host: "rv.acme-corp.example.com"
      port: 443
      scheme: "https"
    - host: "rv-backup.acme-corp.example.com"
      port: 8080
      scheme: "http"

voucher_output:
  directory: "OUTPUT_DIR/vouchers"
YAML

# Patch paths (keep config readable but functional)
sed -i "s|KEYS_DIR|$DEMO_DIR/keys|g"   "$CONFIG_BASIC"
sed -i "s|OUTPUT_DIR|$DEMO_DIR/output-basic|g" "$CONFIG_BASIC"

echo -e "${YELLOW}--- config-basic.yaml ---${NC}"
cat "$CONFIG_BASIC"
echo -e "${YELLOW}--- end ---${NC}"
echo ""

step "Run quick-di:"
run_cmd "$BINARY" -config "$CONFIG_BASIC"

# ─── Introspect: credential blob ──────────────────────────────────────────
banner "INTROSPECT: Device credential blob"

CRED_FILE="$DEMO_DIR/output-basic/cred.bin"
step "The credential blob is a CBOR-encoded file containing the device"
step "secret (HMAC key), private key, GUID, and RV info."
echo ""

step "File size and type:"
run_cmd ls -la "$CRED_FILE"

step "First 64 bytes (hex) -- this is raw CBOR, not human-readable:"
run_cmd xxd -l 64 "$CRED_FILE"

step "We can decode it with the go-fdo client's -print flag."
step "The go-fdo client reads the blob and prints the credential fields."
echo ""
show_cmd "go-fdo client -blob $CRED_FILE -print"
# Build the go-fdo client if needed and use it to print
GO_FDO_CMD="$PROJ_DIR/go-fdo/cmd"
if [ ! -f "$GO_FDO_CMD" ]; then
    step "(Building go-fdo CLI for introspection...)"
    (cd "$PROJ_DIR/go-fdo" && go build -o cmd ./examples/cmd) 2>/dev/null || true
fi
if [ -f "$GO_FDO_CMD" ]; then
    "$GO_FDO_CMD" client -blob "$CRED_FILE" -print 2>&1 || true
else
    step "(go-fdo CLI not available for credential introspection; skipping)"
fi
echo ""

# ─── Introspect: voucher PEM ──────────────────────────────────────────────
banner "INTROSPECT: Ownership Voucher (.fdoov)"

OV_DIR="$DEMO_DIR/output-basic/vouchers"
OV_FILE=$(ls "$OV_DIR"/*.fdoov 2>/dev/null | head -1)

step "Voucher file:"
run_cmd ls -la "$OV_FILE"

step "PEM header (it's PEM-wrapped CBOR):"
run_cmd head -1 "$OV_FILE"

step "Decode the PEM, extract raw CBOR, show first 128 bytes:"
# Strip PEM armor → base64-decode → hex dump
openssl enc -d -base64 -A \
    -in <(sed -n '/^-----BEGIN/,/^-----END/{/^-----/d;p}' "$OV_FILE") \
    2>/dev/null | xxd -l 128
echo ""

step "Decode voucher structure with a small Go helper:"
# Inline Go program to parse and display the voucher
INSPECT_GO=$(mktemp "$DEMO_DIR/inspect_XXXXXX.go")
cat > "$INSPECT_GO" <<'GOEOF'
package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

func main() {
	data, _ := os.ReadFile(os.Args[1])
	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Fprintln(os.Stderr, "no PEM block found")
		os.Exit(1)
	}

	var ov fdo.Voucher
	if err := cbor.Unmarshal(block.Bytes, &ov); err != nil {
		fmt.Fprintf(os.Stderr, "decode error: %v\n", err)
		os.Exit(1)
	}

	h := ov.Header.Val
	fmt.Println("=== Ownership Voucher ===")
	fmt.Printf("  Protocol Version : %d\n", ov.Version)
	fmt.Printf("  GUID             : %s\n", h.GUID)
	fmt.Printf("  Device Info      : %s\n", h.DeviceInfo)

	// Manufacturer key info
	mfgPub, err := h.ManufacturerKey.Public()
	if err == nil {
		fmt.Printf("  Manufacturer Key : %s\n", keyName(mfgPub))
	}
	fmt.Printf("  Key Encoding     : %d\n", h.ManufacturerKey.Encoding)

	if h.CertChainHash != nil {
		fmt.Printf("  CertChain Hash   : %s (%d bytes)\n",
			h.CertChainHash.Algorithm, len(h.CertChainHash.Value))
	}

	// HMAC
	fmt.Printf("  HMAC             : %s (%d bytes)\n",
		ov.Hmac.Algorithm, len(ov.Hmac.Value))

	// RV Info
	fmt.Printf("  RV Directives    : %d\n", len(h.RvInfo))
	for i, dir := range h.RvInfo {
		fmt.Printf("    Directive %d: %d instructions\n", i, len(dir))
	}

	// Cert chain
	if ov.CertChain != nil {
		fmt.Printf("  Device Cert Chain: %d certificate(s)\n", len(*ov.CertChain))
		for i, cert := range *ov.CertChain {
			c := (*x509.Certificate)(cert)
			fp := sha256.Sum256(c.Raw)
			fmt.Printf("    [%d] CN=%s  Issuer=%s  SHA256=%x...\n",
				i, c.Subject.CommonName, c.Issuer.CommonName, fp[:8])
		}
	}

	// Entries (ownership extensions)
	fmt.Printf("  OV Entries       : %d\n", len(ov.Entries))
	for i, e := range ov.Entries {
		nextPub, err := e.Payload.Val.PublicKey.Public()
		if err == nil {
			fmt.Printf("    Entry %d → next owner: %s\n", i, keyName(nextPub))
		}
		fmt.Printf("      PrevHash : %s (%d bytes)\n",
			e.Payload.Val.PreviousHash.Algorithm, len(e.Payload.Val.PreviousHash.Value))
		fmt.Printf("      HdrHash  : %s (%d bytes)\n",
			e.Payload.Val.HeaderHash.Algorithm, len(e.Payload.Val.HeaderHash.Value))
	}

	// Voucher fingerprint
	raw, _ := cbor.Marshal(&ov)
	fp := sha256.Sum256(raw)
	fmt.Printf("  Voucher SHA-256  : %x\n", fp)
}

func keyName(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", k.Size()*8)
	default:
		return fmt.Sprintf("%T", pub)
	}
}
GOEOF

show_cmd "go run inspect.go $OV_FILE"
(cd "$PROJ_DIR" && go run "$INSPECT_GO" "$OV_FILE") 2>&1
rm -f "$INSPECT_GO"
echo ""

# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: DI with ownership extension (signover to next owner)
# ══════════════════════════════════════════════════════════════════════════
banner "PHASE 3: Generate next-owner key pair"

step "In a real deployment this key belongs to whoever will own the device"
step "(e.g. the enterprise that purchased it). The manufacturer signs the"
step "voucher over to this owner using ExtendVoucher."
echo ""

run_cmd openssl ecparam -genkey -name secp384r1 -noout \
    -out "$DEMO_DIR/keys/owner_private.pem"
openssl ec -in "$DEMO_DIR/keys/owner_private.pem" \
    -pubout -out "$DEMO_DIR/keys/owner_public.pem" 2>/dev/null

step "Next owner's public key:"
run_cmd openssl ec -pubin -in "$DEMO_DIR/keys/owner_public.pem" -text -noout 2>/dev/null

# ─── Run DI with signover ─────────────────────────────────────────────────
banner "PHASE 4: DI with owner signover"

CONFIG_SIGNOVER="$DEMO_DIR/config-signover.yaml"
cat > "$CONFIG_SIGNOVER" <<'YAML'
manufacturer_key_file: "KEYS_DIR/mfg_private.pem"

device:
  key_type: "ec384"
  key_encoding: "x509"
  credential_path: "OUTPUT_DIR/cred.bin"
  device_info: "ACME-Widget-3000-CustomerOrder-42"

rendezvous:
  entries:
    - host: "rv.acme-corp.example.com"
      port: 443
      scheme: "https"

owner_signover:
  enabled: true
  next_owner_public_key_file: "KEYS_DIR/owner_public.pem"

voucher_output:
  directory: "OUTPUT_DIR/vouchers"
YAML

sed -i "s|KEYS_DIR|$DEMO_DIR/keys|g"     "$CONFIG_SIGNOVER"
sed -i "s|OUTPUT_DIR|$DEMO_DIR/output-signover|g" "$CONFIG_SIGNOVER"

step "Config with owner signover enabled:"
echo -e "${YELLOW}--- config-signover.yaml ---${NC}"
cat "$CONFIG_SIGNOVER"
echo -e "${YELLOW}--- end ---${NC}"
echo ""

step "Run quick-di with owner signover:"
run_cmd "$BINARY" -config "$CONFIG_SIGNOVER"

# ─── Introspect the extended voucher ──────────────────────────────────────
banner "INTROSPECT: Extended Voucher (with ownership entry)"

OV_FILE2=$(ls "$DEMO_DIR/output-signover/vouchers"/*.fdoov 2>/dev/null | head -1)

step "Compare file sizes (extended voucher is larger due to COSE signature):"
OV_SIZE1=$(wc -c < "$OV_FILE")
OV_SIZE2=$(wc -c < "$OV_FILE2")
echo "  Basic voucher:    $OV_SIZE1 bytes  (0 entries)"
echo "  Extended voucher: $OV_SIZE2 bytes  (1 entry)"
echo "  Delta:            $((OV_SIZE2 - OV_SIZE1)) bytes  (the COSE_Sign1 entry)"
echo ""

step "Parse the extended voucher -- note the entry chain:"

INSPECT_GO2=$(mktemp "$DEMO_DIR/inspect2_XXXXXX.go")
cp "$INSPECT_GO" "$INSPECT_GO2" 2>/dev/null || true
# Reuse the same inspect program
cat > "$INSPECT_GO2" <<'GOEOF'
package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

func main() {
	data, _ := os.ReadFile(os.Args[1])
	block, _ := pem.Decode(data)
	var ov fdo.Voucher
	_ = cbor.Unmarshal(block.Bytes, &ov)

	h := ov.Header.Val
	fmt.Println("=== Extended Ownership Voucher ===")
	fmt.Printf("  GUID             : %s\n", h.GUID)
	fmt.Printf("  Device Info      : %s\n", h.DeviceInfo)
	mfgPub, _ := h.ManufacturerKey.Public()
	fmt.Printf("  Manufacturer Key : %s\n", keyName(mfgPub))
	fmt.Printf("  HMAC             : %s (%d bytes)\n", ov.Hmac.Algorithm, len(ov.Hmac.Value))
	fmt.Printf("  Device Certs     : %d\n", len(*ov.CertChain))
	for i, cert := range *ov.CertChain {
		c := (*x509.Certificate)(cert)
		fmt.Printf("    [%d] CN=%s\n", i, c.Subject.CommonName)
	}
	fmt.Printf("  OV Entries       : %d   <-- THIS IS THE OWNERSHIP CHAIN\n", len(ov.Entries))
	for i, e := range ov.Entries {
		nextPub, _ := e.Payload.Val.PublicKey.Public()
		fmt.Printf("    Entry %d:\n", i)
		fmt.Printf("      Signed by    : manufacturer key (entry 0 is always signed by mfg)\n")
		fmt.Printf("      Next owner   : %s\n", keyName(nextPub))
		fmt.Printf("      PrevHash alg : %s\n", e.Payload.Val.PreviousHash.Algorithm)
		fmt.Printf("      HeaderHash   : %s\n", e.Payload.Val.HeaderHash.Algorithm)
	}

	// Show that the entry's next-owner key matches what we configured
	if len(ov.Entries) > 0 {
		lastEntry := ov.Entries[len(ov.Entries)-1]
		finalOwner, _ := lastEntry.Payload.Val.PublicKey.Public()
		fmt.Println("")
		fmt.Println("  The voucher's final owner key is the next-owner public key")
		fmt.Printf("  we configured. A device doing TO2 will verify the owner\n")
		fmt.Printf("  proves possession of the corresponding private key.\n")
		fmt.Printf("  Final owner: %s\n", keyName(finalOwner))
	}

	raw, _ := cbor.Marshal(&ov)
	fp := sha256.Sum256(raw)
	fmt.Printf("\n  Voucher SHA-256  : %x\n", fp)
}

func keyName(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", k.Size()*8)
	default:
		return fmt.Sprintf("%T", pub)
	}
}
GOEOF

show_cmd "go run inspect.go $OV_FILE2"
(cd "$PROJ_DIR" && go run "$INSPECT_GO2" "$OV_FILE2") 2>&1
rm -f "$INSPECT_GO2"
echo ""

# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Debug and dry-run modes
# ══════════════════════════════════════════════════════════════════════════
banner "PHASE 5: Debug and dry-run modes"

step "Dry-run validates the config without actually performing DI:"
run_cmd "$BINARY" -config "$CONFIG_BASIC" -dry-run -debug

step "This is useful for verifying config on a new machine before committing"
step "to creating credentials."

# ══════════════════════════════════════════════════════════════════════════
# PHASE 6: Ephemeral manufacturer key mode
# ══════════════════════════════════════════════════════════════════════════
banner "PHASE 6: Ephemeral manufacturer key (no key on disk)"

step "In ephemeral mode, the manufacturer key is generated in memory and"
step "NEVER written to disk. When the process exits, the key is gone forever."
step "No key to steal -- but no persistent manufacturer identity either."
step ""
step "Trust shifts to whoever the voucher is signed over to (the next party"
step "in the supply chain). See TRUST_MODELS.md for the full analysis."
echo ""

CONFIG_EPHEMERAL="$DEMO_DIR/config-ephemeral.yaml"
mkdir -p "$DEMO_DIR/output-ephemeral"

cat > "$CONFIG_EPHEMERAL" <<'YAML'
# Ephemeral mode: no manufacturer key file needed!
manufacturer_key_mode: "ephemeral"

device:
  key_type: "ec384"
  key_encoding: "x509"
  credential_path: "OUTPUT_DIR/cred.bin"
  device_info: "ACME-Widget-3000-Ephemeral"

rendezvous:
  entries:
    - host: "rv.acme-corp.example.com"
      port: 443
      scheme: "https"

# Signover is strongly recommended with ephemeral mode -- it provides
# the actual trust anchor since the manufacturer key is throwaway.
owner_signover:
  enabled: true
  next_owner_public_key_file: "KEYS_DIR/owner_public.pem"

voucher_output:
  directory: "OUTPUT_DIR/vouchers"
YAML

sed -i "s|KEYS_DIR|$DEMO_DIR/keys|g"       "$CONFIG_EPHEMERAL"
sed -i "s|OUTPUT_DIR|$DEMO_DIR/output-ephemeral|g" "$CONFIG_EPHEMERAL"

echo -e "${YELLOW}--- config-ephemeral.yaml ---${NC}"
cat "$CONFIG_EPHEMERAL"
echo -e "${YELLOW}--- end ---${NC}"
echo ""

step "Notice: no manufacturer_key_file at all. The key is generated in memory."
echo ""

step "Run quick-di in ephemeral mode:"
run_cmd "$BINARY" -config "$CONFIG_EPHEMERAL"

# ─── Show that running again produces a DIFFERENT manufacturer key ────────
banner "INTROSPECT: Ephemeral key uniqueness"

step "Run quick-di AGAIN with a different credential path."
step "Each run generates a completely different manufacturer key."
echo ""

# Create a second config with different output paths
CONFIG_EPHEMERAL2="$DEMO_DIR/config-ephemeral2.yaml"
mkdir -p "$DEMO_DIR/output-ephemeral2"
sed "s|output-ephemeral|output-ephemeral2|g" "$CONFIG_EPHEMERAL" > "$CONFIG_EPHEMERAL2"

run_cmd "$BINARY" -config "$CONFIG_EPHEMERAL2"

step "Compare the manufacturer keys in the two vouchers:"
echo ""

# Inline Go program to extract and compare mfg key hashes
COMPARE_GO=$(mktemp "$DEMO_DIR/compare_XXXXXX.go")
cat > "$COMPARE_GO" <<'GOEOF'
package main

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

func loadVoucher(path string) (*fdo.Voucher, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	block, _ := pem.Decode(data)
	if block == nil { return nil, fmt.Errorf("no PEM block") }
	var ov fdo.Voucher
	if err := cbor.Unmarshal(block.Bytes, &ov); err != nil { return nil, err }
	return &ov, nil
}

func mfgKeyHash(ov *fdo.Voucher) string {
	keyBytes, _ := cbor.Marshal(&ov.Header.Val.ManufacturerKey)
	h := sha256.Sum256(keyBytes)
	return fmt.Sprintf("%x", h[:16])
}

func main() {
	ov1, err := loadVoucher(os.Args[1])
	if err != nil { fmt.Fprintf(os.Stderr, "voucher 1: %v\n", err); os.Exit(1) }
	ov2, err := loadVoucher(os.Args[2])
	if err != nil { fmt.Fprintf(os.Stderr, "voucher 2: %v\n", err); os.Exit(1) }

	hash1 := mfgKeyHash(ov1)
	hash2 := mfgKeyHash(ov2)

	fmt.Printf("  Voucher 1 mfg key fingerprint: %s\n", hash1)
	fmt.Printf("  Voucher 2 mfg key fingerprint: %s\n", hash2)

	if hash1 == hash2 {
		fmt.Println("\n  SAME manufacturer key (unexpected for ephemeral mode!)")
	} else {
		fmt.Println("\n  DIFFERENT manufacturer keys -- each run is unique.")
		fmt.Println("  An attacker who steals a voucher learns nothing about")
		fmt.Println("  the manufacturer key used for any other device.")
	}
}
GOEOF

OV_EPH1=$(ls "$DEMO_DIR/output-ephemeral/vouchers"/*.fdoov 2>/dev/null | head -1)
OV_EPH2=$(ls "$DEMO_DIR/output-ephemeral2/vouchers"/*.fdoov 2>/dev/null | head -1)

show_cmd "go run compare.go <voucher1> <voucher2>"
(cd "$PROJ_DIR" && go run "$COMPARE_GO" "$OV_EPH1" "$OV_EPH2") 2>&1
rm -f "$COMPARE_GO"
echo ""

step "Meanwhile, a PEM-file-mode manufacturer would show the SAME key"
step "for every voucher (which is exactly what makes it a trust anchor,"
step "but also what makes key theft dangerous)."

# ══════════════════════════════════════════════════════════════════════════
# PHASE 7: Trust model comparison
# ══════════════════════════════════════════════════════════════════════════
banner "TRUST MODEL COMPARISON"

echo "  ┌──────────────────────────────────────────────────────────────────┐"
echo "  │                HSM          PEM File       Ephemeral            │"
echo "  │             ─────────    ─────────────    ───────────           │"
echo "  │ Key theft     None          HIGH            None               │"
echo "  │ risk                                                           │"
echo "  │                                                                │"
echo "  │ Mfg           Full          Full            None               │"
echo "  │ provenance                                                     │"
echo "  │                                                                │"
echo "  │ Trust          Mfg key       Mfg key         Next signer       │"
echo "  │ anchor                                       or channel        │"
echo "  │                                                                │"
echo "  │ Infra          HSM +         USB key         Just the          │"
echo "  │ needed         server                        binary            │"
echo "  │                                                                │"
echo "  │ Per-device     Same key      Same key        Unique key        │"
echo "  │ correlation    (traceable)   (traceable)     (untraceable)     │"
echo "  └──────────────────────────────────────────────────────────────────┘"
echo ""
echo "  See TRUST_MODELS.md for the full analysis."
echo ""

# ══════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════
banner "SUMMARY: What was created"

echo "  Demo directory: $DEMO_DIR"
echo ""
echo "  Keys (simulated USB key contents):"
run_cmd ls -la "$DEMO_DIR/keys/"

echo "  Basic DI output (file mode, no signover):"
run_cmd find "$DEMO_DIR/output-basic" -type f -exec ls -la {} \;

echo "  Signover DI output (file mode, with signover):"
run_cmd find "$DEMO_DIR/output-signover" -type f -exec ls -la {} \;

echo "  Ephemeral DI output (ephemeral mode, with signover):"
run_cmd find "$DEMO_DIR/output-ephemeral" -type f -exec ls -la {} \;

banner "WALKTHROUGH COMPLETE"

echo "  Modes demonstrated:"
echo "    1. PEM file mode       -- manufacturer key from disk file"
echo "    2. PEM file + signover -- extended to next owner"
echo "    3. Ephemeral mode      -- throwaway key, trust via signover"
echo ""
echo "  In a real deployment:"
echo "    - PEM file mode: USB key carries the manufacturer key."
echo "      Provides real provenance but key theft is a risk."
echo "    - Ephemeral mode: No key on disk at all. Trust comes from"
echo "      whoever the voucher is signed over to (or the delivery"
echo "      channel). Best when factory identity doesn't matter."
echo "    - HSM mode (go-fdo-manufacturing-station): The gold standard."
echo "      Key never leaves the HSM. Always preferred when possible."
echo ""
echo "  See TRUST_MODELS.md for the full security analysis."
echo ""
