#!/bin/sh
# Assemble and sign NeuralkitCLI.app — the wrapper that lets a provisioning profile
# authorize `keychain-access-groups`, which a bare binary structurally cannot carry.
# That entitlement is what allows a PERSISTED Secure Enclave key to have an access
# control (Apple Watch / Touch ID / PIN) — the measured matrix behind all of this is
# the header of phaze-auth/src/enclave.rs.
#
# usage:
#   release/macos/bundle.sh <binary> <profile.provisionprofile> "<signing identity>"
#
# dev (this Mac only — the measured-good chain that made the Watch prompt):
#   cargo build --release
#   release/macos/bundle.sh target/release/neuralkit \
#     ~/Downloads/Neuralkit_CLI_Dev.provisionprofile \
#     "Apple Development: Rohan Rehman (CBQ9TZC7T3)"
#
# release (any Mac; notarize the zip afterwards for quarantined installs):
#   release/macos/bundle.sh target/release/neuralkit \
#     ~/Downloads/Neuralkit_CLI_Developer_ID.provisionprofile \
#     "Developer ID Application: Neuralkit inc. (SBG7YFF24U)"
#
# The identity must be one the PROFILE pairs with (decode with
# `security cms -D -i <profile>` and read DeveloperCertificates) — a valid cert the
# profile doesn't list still dies at launch.
set -eu

BIN=${1:?usage: bundle.sh <binary> <profile.provisionprofile> "<signing identity>"}
PROFILE=${2:?missing <profile.provisionprofile>}
IDENTITY=${3:?missing "<signing identity>"}

HERE=$(cd "$(dirname "$0")" && pwd)
APP="$HERE/../../dist/NeuralkitCLI.app"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"

cp "$HERE/Info.plist" "$APP/Contents/Info.plist"
cp "$BIN" "$APP/Contents/MacOS/neuralkit"
# The bundle's own copy is what AMFI reads — nothing needs installing in Settings,
# which also means a tester's Mac needs nothing pre-installed.
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
# The profile was downloaded by a browser, so its copy inherits com.apple.quarantine
# (and friends) — strip them so the bit never rides inside a distributed bundle.
xattr -c "$APP/Contents/embedded.provisionprofile" 2>/dev/null || true

# Version from Cargo.toml, so the bundle never drifts from the crate.
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$HERE/../../Cargo.toml" | head -1)
if [ -n "$VERSION" ]; then
  plutil -replace CFBundleShortVersionString -string "$VERSION" "$APP/Contents/Info.plist"
  plutil -replace CFBundleVersion -string "$VERSION" "$APP/Contents/Info.plist"
fi

# --options runtime (Hardened Runtime) is mandatory for notarization; harmless for
# dev, and signing both modes identically means the dev test exercises the release
# configuration.
codesign --force --options runtime \
  --entitlements "$HERE/neuralkit.entitlements" \
  --sign "$IDENTITY" \
  "$APP"

codesign --verify --strict "$APP"
echo
echo "  signed: $APP"
echo "  identity: $IDENTITY"
echo
echo "  entitlements carried by the signature:"
codesign -d --entitlements - "$APP" 2>/dev/null | sed 's/^/    /'
echo
echo "  test the Watch/biometric gate (no code changes needed — the env var is the switch):"
echo "    NEURALKIT_ENCLAVE=1 \"$APP/Contents/MacOS/neuralkit\" auth passkey"
