#!/bin/bash
# Builds JamfSecurityAudit.app (AppleScript applet + bundled audit script):
# osacompile, copy resources, ad-hoc sign.
# Usage: build_jamf_security_audit_app.sh [DEST_DIR]   (default: ~/Desktop)
set -euo pipefail
# System tools only: a PATH entry earlier in the inherited PATH cannot swap in its own install or sed.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-$HOME/Desktop}"
APP="$DEST/JamfSecurityAudit.app"
VERSION="$(sed -n "s/^const VERSION = '\(.*\)';/\1/p" "$SRC/jamf_host_audit.js")"
if [ -z "$VERSION" ]; then
    echo "no VERSION found in $SRC/jamf_host_audit.js" >&2
    exit 1
fi

# Build and sign outside the Desktop: iCloud Desktop sync stamps FinderInfo on new bundles there, which
# codesign refuses. The signed app is copied into DEST at the end.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/jamfsecurityaudit-build.XXXXXX")"
FINAL="$APP"
APP="$STAGE/JamfSecurityAudit.app"

/usr/bin/osacompile -o "$APP" "$SRC/jamf_security_audit.applescript"
RES="$APP/Contents/Resources"
install -m 755 "$SRC/run-jamfsecurityaudit.command" "$RES/run-jamfsecurityaudit.command"
install -m 644 "$SRC/jamf_host_audit.js" "$RES/jamf_host_audit.js"
# Report stylesheet and source-link titles.
install -m 644 "$SRC/report_assets.json" "$RES/report_assets.json"

PLIST="$APP/Contents/Info.plist"
/usr/bin/plutil -replace CFBundleIdentifier -string com.dferri.jamfsecurityaudit "$PLIST"
/usr/bin/plutil -replace CFBundleName -string JamfSecurityAudit "$PLIST"
/usr/bin/plutil -replace CFBundleShortVersionString -string "$VERSION" "$PLIST"
/usr/bin/plutil -replace CFBundleVersion -string "$VERSION" "$PLIST"
/usr/bin/plutil -replace OSAAppletShowStartupScreen -bool false "$PLIST"

/usr/bin/codesign --force --deep --sign - "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"

if [ -e "$FINAL" ]; then
    BAK="$FINAL.bak.$(date +%Y%m%d-%H%M%S)"
    mv "$FINAL" "$BAK"
    echo "previous app moved to $BAK"
fi
/usr/bin/ditto "$APP" "$FINAL"
# On the Desktop the file provider may add FinderInfo again, so --strict can fail there; the signature must not.
/usr/bin/codesign --verify --deep "$FINAL"
echo "built $FINAL ($VERSION); staged copy left in $STAGE"
