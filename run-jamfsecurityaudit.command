#!/bin/bash
# Runs the bundled host audit (jamf_host_audit.js) on THIS Mac and opens the HTML report. Works on any Mac:
# it uses only osascript (JavaScript for Automation) and built-in macOS commands, so no Python, Homebrew or
# Jamf credentials are needed. Opened by JamfSecurityAudit.app (via `open -a Terminal`), so no
# Automation/AppleEvents permission is involved. Read-only: nothing on the Mac is changed. The admin password
# adds computer-level profiles, the bootstrap token and the FileVault recovery key; Ctrl-C runs it without.
umask 077
clear
DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$DIR/../.."
# Reports name the Mac and its accounts: keep them private and out of iCloud-synced Desktop/Documents.
REPORTS="$HOME/Library/Logs/JamfSecurityAudit"
mkdir -p "$REPORTS" && chmod 700 "$REPORTS"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$REPORTS/JamfSecurityAudit-$(scutil --get LocalHostName 2>/dev/null || hostname -s)-$STAMP.html"
RUN=(/usr/bin/osascript -l JavaScript "$DIR/jamf_host_audit.js" --assets "$DIR/report_assets.json")

echo 'JamfSecurityAudit: read-only security check of this Mac'
LOG="$REPORTS/last-run.txt"
ROOTDIR=""
# A strict signature catches changed bundle resources. Developer ID builds must also pass Gatekeeper assessment;
# an ad-hoc local build has integrity only and does not authenticate its publisher.
TEAM_ID=""
if /usr/bin/codesign --verify --deep --strict "$APP" 2>/dev/null; then
    TEAM_ID="$(/usr/bin/codesign -d --verbose=2 "$APP" 2>&1 | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
fi
if [ "$TEAM_ID" = "not set" ]; then
    echo 'Local ad-hoc build: signature integrity verified; publisher identity is not authenticated.'
    SIGNATURE_OK=1
elif [ -n "$TEAM_ID" ] && /usr/sbin/spctl --assess --type execute "$APP" 2>/dev/null; then
    SIGNATURE_OK=1
else
    SIGNATURE_OK=""
fi
if [ -n "$SIGNATURE_OK" ]; then
    echo 'Enter your admin password for full coverage, or press Ctrl-C for reduced coverage.'
    # Ctrl-C at the password prompt ends sudo only, so the reduced-coverage run below still happens.
    trap ':' INT
    /usr/bin/sudo -v && ROOTDIR="$(/usr/bin/sudo /usr/bin/mktemp -d /private/tmp/JamfSecurityAudit.XXXXXXXX)"
    trap - INT
else
    echo 'The app signature or Gatekeeper assessment does not verify, so the audit will not ask for the admin password.'
fi
echo
if [ -n "$ROOTDIR" ]; then
    # Root writes only inside its own mode-700 folder. The user shell copies the report out into a file it owns.
    /usr/bin/sudo "${RUN[@]}" --html "$ROOTDIR/report.html" | tee "$LOG"
    if /usr/bin/sudo /bin/test -f "$ROOTDIR/report.html"; then
        # The user-owned redirect is the security boundary described above.
        # shellcheck disable=SC2024
        /usr/bin/sudo /bin/cat "$ROOTDIR/report.html" > "$OUT"
    fi
    /usr/bin/sudo /bin/rm -f "$ROOTDIR/report.html"
    /usr/bin/sudo /bin/rmdir "$ROOTDIR"
else
    echo 'No admin password: checks that need it will be listed as not evaluated.'
    "${RUN[@]}" --html "$OUT" | tee "$LOG"
fi
/usr/bin/sudo -k
INCOMPLETE=""
/usr/bin/grep -q '^INCOMPLETE AUDIT' "$LOG" 2>/dev/null && INCOMPLETE=1

echo
if [ -f "$OUT" ]; then
    /usr/bin/open "$OUT"
    [ -n "$INCOMPLETE" ] && echo '✗ Audit incomplete. A missing finding is not a pass; see the top of the report.'
    echo "Report (private, mode 600): $OUT"
else
    echo '✗ No report was written.'
fi
echo 'Press Return to close this window.'
read -r _
