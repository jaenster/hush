#!/usr/bin/env bash
# Sign hushd so it can use the Secure Enclave / biometric keychain (Touch ID).
#
# Requires an Apple Developer signing identity and a Team ID filled into
# hush.entitlements. The default `hushd --keychain` does NOT need signing.
#
#   usage: scripts/sign.sh <signing-identity> [binary]
#   list:  security find-identity -v -p codesigning
set -euo pipefail

IDENTITY="${1:-}"
BIN="${2:-zig-out/bin/hushd}"
ENT="$(cd "$(dirname "$0")/.." && pwd)/hush.entitlements"

if [ -z "$IDENTITY" ]; then
  echo "usage: scripts/sign.sh <signing-identity> [binary]" >&2
  echo "list identities: security find-identity -v -p codesigning" >&2
  exit 2
fi

if grep -q TEAMID "$ENT"; then
  echo "error: edit $ENT and replace TEAMID with your Apple Developer Team ID first" >&2
  exit 1
fi

codesign --force --options runtime --sign "$IDENTITY" --entitlements "$ENT" "$BIN"
echo "signed $BIN with: $IDENTITY"
codesign -d --entitlements - "$BIN"
