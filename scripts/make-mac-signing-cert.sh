#!/usr/bin/env bash
# Makes the self-signed code-signing certificate that the macOS release builds are signed with, once.
#
# Why: an ad-hoc signed app has no signer, so macOS ties its permissions (Microphone, Screen & System
# Audio Recording) to that exact build, and every update has to be allowed again. Signed with the
# same certificate every time, the app keeps one identity ("com.onscreenly.overlay" signed by this
# certificate), so permissions survive updates. Gatekeeper still asks once (Open Anyway): only an
# Apple Developer ID removes that.
#
# Usage (on a Mac):  scripts/make-mac-signing-cert.sh [folder]     default folder: ~/onscreenly-signing
#   --ci  write a throwaway certificate into [folder] without the secret step (the app tests use it)
#
# KEEP THE FOLDER. A new certificate is a new identity: every user would have to allow the
# permissions again. Back it up somewhere safe (a password manager); never commit it.
set -euo pipefail

CI_MODE=0
if [ "${1:-}" = "--ci" ]; then CI_MODE=1; shift; fi
NAME="Onscreenly Self-Signed"
DIR="${1:-$HOME/onscreenly-signing}"
# The system LibreSSL on macOS, and any OpenSSL 1.1/3 elsewhere, both read these options.
OPENSSL="$(command -v /usr/bin/openssl || command -v openssl)"

mkdir -p "$DIR"
chmod 700 "$DIR"
cd "$DIR"
if [ -e onscreenly-signing.p12 ]; then
  echo "A certificate already exists in $DIR. Keep using it: a new one would reset everyone's permissions." >&2
  exit 1
fi

umask 077
cat > cert.cnf <<CNF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $NAME
[ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
CNF

PASSWORD="$("$OPENSSL" rand -hex 24)"
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 3650 -config cert.cnf -keyout key.pem -out cert.pem 2>/dev/null
# 3DES and SHA-1 keep the .p12 importable by macOS `security import`, which rejects OpenSSL 3's defaults.
"$OPENSSL" pkcs12 -export -inkey key.pem -in cert.pem -name "$NAME" -out onscreenly-signing.p12 \
  -passout "pass:$PASSWORD" -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
rm -f key.pem cert.cnf
printf '%s' "$PASSWORD" > password.txt
base64 < onscreenly-signing.p12 | tr -d '\n' > onscreenly-signing.p12.base64

if [ "$CI_MODE" = 1 ]; then
  echo "Throwaway certificate written to $DIR"
  exit 0
fi

echo
echo "Made $DIR/onscreenly-signing.p12 (certificate \"$NAME\", valid 10 years)."
echo "Fingerprint: $("$OPENSSL" x509 -in cert.pem -noout -fingerprint -sha256 | cut -d= -f2)"
echo
if command -v gh > /dev/null 2>&1; then
  echo "Adding the GitHub secrets with gh (you can also do it by hand, below)…"
  gh secret set MAC_SELF_SIGN_P12 --repo paypilotlabs/onscreenly < onscreenly-signing.p12.base64
  gh secret set MAC_SELF_SIGN_PASSWORD --repo paypilotlabs/onscreenly < password.txt
  echo "Done: MAC_SELF_SIGN_P12 and MAC_SELF_SIGN_PASSWORD are set."
else
  echo "Add two repository secrets (GitHub › paypilotlabs/onscreenly › Settings › Secrets and variables › Actions):"
  echo "  MAC_SELF_SIGN_P12       the contents of $DIR/onscreenly-signing.p12.base64"
  echo "  MAC_SELF_SIGN_PASSWORD  the contents of $DIR/password.txt"
fi
echo
echo "Back up $DIR somewhere safe. Never commit it."
