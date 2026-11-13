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
# profile, and neither is written here.
set -euo pipefail
cd "$(dirname "$0")"

profile=${1:-}
identity=${2:-Apple Development}
app=build/TangentSensor.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"

swiftc -O -o "$app/Contents/MacOS/tangent-sensor" main.swift -lEndpointSecurity -lbsm

if [ -z "$profile" ]; then
  sed "s/BUNDLE_ID/dev.tangent.sensor/" Info.plist > "$app/Contents/Info.plist"
  echo "built $app, unsigned: it cannot open an Endpoint Security client"
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

sed "s/BUNDLE_ID/$bundle_id/" Info.plist > "$app/Contents/Info.plist"
cp "$profile" "$app/Contents/embedded.provisionprofile"
codesign --force --options runtime --sign "$identity" --entitlements build/entitlements.plist "$app"
codesign --verify --strict "$app"
echo "built and signed $app ($bundle_id)"
echo "run: sudo $(pwd)/$app/Contents/MacOS/tangent-sensor | nc -U es.sock"
