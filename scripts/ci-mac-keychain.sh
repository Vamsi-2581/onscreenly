#!/usr/bin/env bash
# CI only (macOS runner): puts a signing .p12 into a temporary keychain that codesign can use without
# a prompt, and prints the certificate's SHA-1 for ONSCREENLY_MAC_SIGN_IDENTITY.
# Usage: scripts/ci-mac-keychain.sh <p12 file> <p12 password> <keychain path>
set -euo pipefail
P12="$1"
P12_PASSWORD="$2"
KEYCHAIN="$3"
KEYCHAIN_PASSWORD="$(openssl rand -hex 16)"

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN" > /dev/null
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$P12" -k "$KEYCHAIN" -P "$P12_PASSWORD" -T /usr/bin/codesign > /dev/null
# Let codesign use the key without asking (a CI runner has no one to click Allow).
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" > /dev/null
# codesign looks keychains up by the search list as well as by --keychain.
security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')

# Without -v: a self-signed certificate is not "valid" (not trusted), and codesign does not need it to be.
HASH="$(security find-identity -p codesigning "$KEYCHAIN" | awk '/Onscreenly Self-Signed/ { print $2; exit }')"
if [ -z "$HASH" ]; then
  echo "No 'Onscreenly Self-Signed' identity in the keychain." >&2
  security find-identity -p codesigning "$KEYCHAIN" >&2
  exit 1
fi
echo "$HASH"
