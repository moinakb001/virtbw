#!/bin/sh
# Builds build/virtbw.app, signed with the com.apple.developer.hid.virtual.device entitlement
# that macOS requires for creating the virtual security key.
#
#   PROFILE=virtbw.provisionprofile IDENTITY="Apple Development: Jane Doe (ABCDE12345)" \
#       scripts/macos-bundle.sh
#
# PROFILE is a macOS provisioning profile for an App ID with the "HID Virtual Device"
# capability. The bundle ID and team ID are read from it. IDENTITY is the signing
# certificate the profile was created for (see `security find-identity -v -p codesigning`).
#
# Without PROFILE the app is ad-hoc signed with the entitlement. macOS refuses to run such a
# binary unless AMFI enforcement is disabled on the machine.
#
# Run the result from a terminal: build/virtbw.app/Contents/MacOS/virtbw start
set -eu

OUT=${OUT:-build/virtbw.app}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [ -n "${PROFILE:-}" ]; then
    : "${IDENTITY:?set IDENTITY to the signing certificate for the profile}"
    security cms -D -i "$PROFILE" > "$WORK/profile.plist"
    APP_IDENTIFIER=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$WORK/profile.plist")
    TEAM_ID=$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$WORK/profile.plist")
    if ! /usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.developer.hid.virtual.device' "$WORK/profile.plist" >/dev/null 2>&1; then
        echo "error: $PROFILE does not grant com.apple.developer.hid.virtual.device" >&2
        exit 1
    fi
    BUNDLE_ID=${APP_IDENTIFIER#"$TEAM_ID."}
else
    IDENTITY=-
    BUNDLE_ID=${BUNDLE_ID:-com.github.moinakb001.virtbw}
    echo "warning: no PROFILE given, ad-hoc signing (only runs with AMFI disabled)" >&2
fi

rm -rf "$OUT"
mkdir -p "$OUT/Contents/MacOS"
CGO_ENABLED=1 go build -o "$OUT/Contents/MacOS/virtbw" ./cmd/virtbw

cat > "$OUT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_ID</string>
    <key>CFBundleName</key>
    <string>virtbw</string>
    <key>CFBundleExecutable</key>
    <string>virtbw</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
PLIST

{
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><dict>'
    echo '<key>com.apple.developer.hid.virtual.device</key><true/>'
    if [ -n "${PROFILE:-}" ]; then
        echo "<key>com.apple.application-identifier</key><string>$APP_IDENTIFIER</string>"
        echo "<key>com.apple.developer.team-identifier</key><string>$TEAM_ID</string>"
    fi
    echo '</dict></plist>'
} > "$WORK/entitlements.plist"

if [ -n "${PROFILE:-}" ]; then
    cp "$PROFILE" "$OUT/Contents/embedded.provisionprofile"
fi
codesign --force --options runtime --entitlements "$WORK/entitlements.plist" --sign "$IDENTITY" "$OUT"
codesign --display --entitlements - "$OUT"
echo "Built $OUT"
