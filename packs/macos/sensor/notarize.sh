#!/bin/bash
# notarize.sh: build/TangentSensor.app, as build.sh signed it with a Developer
# ID, sent to Apple's notary, its ticket stapled on, and zipped to hand out:
# build/tangent-sensor-macos.zip. A Mac that downloads it runs it without
# being asked, and with no profile or grant of its own.
#
#   ./build.sh developer-id.provisionprofile "Developer ID Application"
#   ./notarize.sh --keychain-profile NAME                      # xcrun notarytool store-credentials NAME
#   ./notarize.sh --key AuthKey.p8 --key-id ID --issuer UUID   # an App Store Connect API key
#
# The arguments are notarytool's own, passed on as given.
set -euo pipefail
cd "$(dirname "$0")"

app=build/TangentSensor.app
[ -d "$app" ] || { echo "no $app: ./build.sh PROFILE \"Developer ID Application\" first" >&2; exit 1; }
[ $# -gt 0 ] || { echo "say how to sign in to the notary: --keychain-profile NAME, or --key FILE --key-id ID --issuer UUID" >&2; exit 1; }

rm -f build/notarize.zip build/tangent-sensor-macos.zip
ditto -c -k --keepParent "$app" build/notarize.zip
xcrun notarytool submit build/notarize.zip --wait --output-format json "$@" > build/notary.json
status=$(plutil -extract status raw build/notary.json)
if [ "$status" != Accepted ]; then
  echo "the notary said $status: xcrun notarytool log $(plutil -extract id raw build/notary.json) says why" >&2
  exit 1
fi
rm build/notarize.zip

xcrun stapler staple "$app"
spctl --assess --type execute "$app"
ditto -c -k --keepParent "$app" build/tangent-sensor-macos.zip
echo "notarized: $(pwd)/build/tangent-sensor-macos.zip"
