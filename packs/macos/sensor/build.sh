#!/bin/bash
# build.sh: tangent-sensor, compiled, wrapped and signed.
#
#   ./build.sh /path/to/sensor.provisionprofile              # signed "Apple Development"
#   ./build.sh /path/to/sensor.provisionprofile "Developer ID Application"
#   ./build.sh                                               # unsigned: compiles, and says "not entitled" when run
#
# Endpoint Security's entitlement is one Apple grants to a team, and a
# provisioning profile is what says so to macOS. A profile has to sit in a
# bundle, so the binary is built as build/TangentSensor.app/Contents/MacOS/tangent-sensor
# with the profile beside it, and signed with the entitlements the profile
# itself lists: the bundle's identifier and the team are read from the
# profile, and neither is written here. The bundle's version is tangent's,
# from the workspace's Cargo.toml, so a sensor says which release it is of.
set -euo pipefail
cd "$(dirname "$0")"

profile=${1:-}
identity=${2:-Apple Development}
app=build/TangentSensor.app
# a bundle's version is digits and dots: 0.2.0-rc.1 is written 0.2.0
version=$(sed -n 's/^version = "\([0-9.]*\).*"$/\1/p' ../../../Cargo.toml | head -1)
[ -n "$version" ] || { echo "no version in the workspace's Cargo.toml" >&2; exit 1; }
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"

# both kinds of Mac in one binary, for macOS 13 and later (Info.plist says so too)
for arch in arm64 x86_64; do
  swiftc -O -target "$arch-apple-macos13.0" -o "build/tangent-sensor.$arch" main.swift -lEndpointSecurity -lbsm
done
lipo -create build/tangent-sensor.arm64 build/tangent-sensor.x86_64 -output "$app/Contents/MacOS/tangent-sensor"
rm build/tangent-sensor.arm64 build/tangent-sensor.x86_64

if [ -z "$profile" ]; then
  sed -e "s/BUNDLE_ID/dev.tangent.sensor/" -e "s/VERSION/$version/" Info.plist > "$app/Contents/Info.plist"
  echo "built $app $version, unsigned: it cannot open an Endpoint Security client"
  exit 0
fi

# what the profile grants, and to which identifier
security cms -D -i "$profile" > build/profile.plist
plutil -extract Entitlements xml1 -o build/entitlements.plist build/profile.plist
app_id=$(plutil -extract Entitlements.com\\.apple\\.application-identifier raw build/profile.plist)
bundle_id=${app_id#*.}
if ! plutil -extract Entitlements.com\\.apple\\.developer\\.endpoint-security\\.client raw build/profile.plist >/dev/null 2>&1; then
  echo "$profile does not grant com.apple.developer.endpoint-security.client: add the Endpoint Security capability to the App ID and make the profile again" >&2
  exit 1
fi

sed -e "s/BUNDLE_ID/$bundle_id/" -e "s/VERSION/$version/" Info.plist > "$app/Contents/Info.plist"
cp "$profile" "$app/Contents/embedded.provisionprofile"
# a build to hand out is notarized, and Apple's notary wants its time of signing
stamp=--timestamp=none
case "$identity" in "Developer ID"*) stamp=--timestamp ;; esac
codesign --force --options runtime "$stamp" --sign "$identity" --entitlements build/entitlements.plist "$app"
codesign --verify --strict "$app"
echo "built and signed $app $version ($bundle_id)"
echo "run: sudo $(pwd)/$app/Contents/MacOS/tangent-sensor | nc -U es.sock"
