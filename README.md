# JamfSecurityAudit

JamfSecurityAudit checks one Mac for common security gaps in Jamf-managed Macs. It reads the Mac's state and writes a private HTML report. It changes nothing on the Mac.

The audit is a single JavaScript for Automation (JXA) script. It runs on stock macOS with no Python, Homebrew or Jamf credentials.

## What it checks

Rule IDs are stable across releases. Gaps in the numbering are expected.

| Area | Rule | Finding |
| --- | --- | --- |
| FileVault | FV-01 | FileVault is off |
| FileVault | FV-03 | FileVault is on but no personal recovery key exists |
| FileVault | FV-04 | No recovery-key escrow profile is installed |
| MDM health | MDM-02 | The Mac lacks user-approved MDM |
| MDM health | MDM-03 | No bootstrap token is escrowed |
| Accounts | ACC-01 | The signed-in user is a local administrator |
| Accounts | ACC-02 | Local account records are broken (no UID) |
| Accounts | ACC-03 | No working admin account for IT |
| Accounts | ACC-06 | The Guest account is on |
| Accounts | ACC-07 | Automatic login is on |
| Accounts | ACC-08 | A Platform SSO profile makes users administrators |
| Accounts | DIR-01 | The Mac is bound to Active Directory |
| Accounts | DIR-02 | The AD binding makes directory groups local administrators |
| Remote access | NET-01 | The macOS firewall is off |
| Remote access | NET-02 | SSH (Remote Login) is on |
| Remote access | NET-03 | Screen Sharing or Remote Management is on |
| Remote access | NET-04 | Third-party remote-control software is installed |
| Remote access | NET-05 | A Wi-Fi profile defines an open network |
| Remote access | NET-06 | A Wi-Fi profile turns off Private Wi-Fi Address |
| Remote access | NET-07 | Enterprise Wi-Fi does not pin its RADIUS server certificate |
| Updates | OS-01 | The Mac misses fixes for actively exploited vulnerabilities |
| Updates | OS-02 | The Mac is behind the latest security release for its macOS version |
| Updates | OS-03 | The Mac runs a macOS version that no longer gets security updates |
| Platform security | SEC-01 | SIP or Gatekeeper is off |
| Platform security | SEC-02 | Activation Lock is on |
| Platform security | SEC-04 | No profile requires a password soon after the screen saver starts |
| Platform security | SEC-05 | No password policy applies |
| Profiles | PRF-01 | Installed profiles set the same key to different values |
| Profiles | PRF-04 | A privacy profile gives Full Disk Access to Terminal or a script interpreter |
| Profiles | PRF-06 | A privacy profile gives remote-control apps full disk, screen and accessibility access |

Each check ends as PASS, FAIL, SKIP or ERROR. A check that cannot get reliable evidence is skipped. A skipped check is never counted as a pass.

[RULE_SOURCES.md](RULE_SOURCES.md) quotes the Apple, Jamf and Microsoft sources behind the rule text.

## Run the app

1. Double-click `JamfSecurityAudit.app`. A Terminal window opens.
2. Enter your admin password for full coverage.
3. Or press Ctrl-C at the password prompt. The audit then runs without admin rights.

Some checks need root. These are computer-level profiles, the bootstrap token and the FileVault recovery key. Without the admin password, those checks are skipped and the report is marked incomplete.

The launcher verifies the app's code signature before it asks for the password. If the signature does not verify, the audit runs without admin rights.

## Where the report goes

The report is saved in `~/Library/Logs/JamfSecurityAudit`. The folder has mode 700 and each report has mode 600. The launcher opens the report when the run ends.

The report names the Mac, its accounts and its weaknesses. It therefore stays out of the Desktop and Documents folders, which iCloud can sync.

Under sudo, the audit writes into a temporary folder that only root can read. Your own shell then copies the report into the log folder. Root never writes into a folder you can change.

## Run from the command line

```sh
osascript -l JavaScript jamf_host_audit.js --html out.html [--json out.json] [--offline]
```

- `--html FILE` writes the HTML report.
- `--json FILE` writes the same results as JSON.
- `--assets FILE` adds the report stylesheet and source titles from `report_assets.json`.
- `--offline` skips the SOFA download. The update checks are then skipped.

Run it with `sudo` for full coverage. The command prints one line per finding and a summary. It exits 0 when the audit completes, even with findings. It exits non-zero only when the audit itself fails.

## Build the app

```sh
./build_jamf_security_audit_app.sh [DEST_DIR]
```

The script compiles the AppleScript launcher and copies in the audit script, the launcher and `report_assets.json`. It then ad-hoc signs the bundle. The default destination is `~/Desktop`. An existing app at the destination is renamed with a `.bak` timestamp, not overwritten.

## Run the tests

```sh
/usr/bin/python3 -I test_jamf_host_audit.py
```

The tests replay recorded command output through the `--fixture` option. They need no admin rights and do not read the Mac's real state. The audit accepts `--fixture` only when `JAMF_HOST_AUDIT_FIXTURE=1` is set. The tests set it for you.

## The SOFA feed

SOFA is a public macOS update feed run by the Mac Admins community. It lists each macOS security release and the CVEs that Apple says may have been exploited. The update checks compare this Mac's version with that list.

The audit downloads the feed from `https://sofafeed.macadmins.io/v1/macos_data_feed.json` over HTTPS. This is the only network call. The audit sends no data about the Mac.

## Limitations

- The audit sees only this Mac. It cannot read Jamf server settings such as SSO, API clients, scopes, Recovery Lock or LAPS state.
- Without the admin password, several checks are skipped.
- NET-04 matches known product names in application, launchd and `/opt` folders. It does not find renamed or unlisted tools.
- Wi-Fi checks read installed profiles. Networks a user added by hand are not checked.
- OS checks depend on the SOFA feed. A macOS version newer than the feed is skipped.
- Slow commands stop after 60 seconds. A check that times out is skipped.

## Signing and quarantine

The app is ad-hoc signed. It has no Developer ID and is not notarized. A copy you build yourself carries no quarantine flag and opens normally.

A copy downloaded from elsewhere is quarantined, so Gatekeeper blocks it. To open it once, go to System Settings > Privacy & Security and click Open Anyway. Building from source avoids this step.
