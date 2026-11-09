# Changelog

## 2.1.1 (2026-11-08)

This release makes missing evidence explicit and closes the remaining report-redaction and screen-lock validation gaps.

### Correctness

- Command failures for FileVault status, bootstrap-token status, automatic login, Active Directory binding, SIP and Gatekeeper no longer become findings or passes.
- SKIP now distinguishes a check that does not apply from missing evidence. Missing evidence marks the report incomplete, including partial checks that still found a problem.
- SEC-04 requires a present, finite `askForPasswordDelay` from 0 through 300 seconds before it counts a screen-saver profile as enforcement.
- The AppleScript launcher builds on macOS 27.2 even when `osacompile` does not load Standard Additions terminology.

### Security

- Profile-conflict evidence reports value types instead of copying arbitrary primitive profile values.
- Developer ID builds can set `CODESIGN_IDENTITY` for hardened-runtime, timestamped signing. The launcher requires Developer ID builds to pass Gatekeeper assessment before it requests administrator access and labels ad-hoc verification as integrity-only.

### Documentation

- The README has a new layout: a banner, an example report, a check table grouped by area with severities, and collapsible reference sections.
- RULE_SOURCES.md uses shorter sentences and labels each claim under review as an earlier draft. Its quotes did not change.
- The repository moved to github.com/dominicferri/JamfSecurityAudit. The clone command in the README uses the new address.

## 2.1.0 (2026-10-21)

This release hardens security and handles missing evidence more reliably.

### Security

- Under sudo, the audit now writes its report into a new root-owned folder with mode 700. The launcher copies the report into the user's log folder from the user's own shell. Root no longer writes, renames or changes ownership inside a user-writable folder.
- Report writes use a random temporary name and refuse a destination or temporary path that is a symbolic link. Reports keep mode 600.
- The launcher sets `umask 077` and clears the cached sudo credential when it finishes. It verifies the app's code signature before it asks for the admin password. If the signature does not verify, the audit runs without admin rights.
- The SOFA download no longer follows redirects.
- The audit strips `<` characters from the embedded report stylesheet.
- The audit accepts `--fixture` only when the environment sets `JAMF_HOST_AUDIT_FIXTURE=1`.

### Fixes

- Pressing Ctrl-C at the password prompt now runs the reduced-coverage audit instead of closing the launcher.
- A failed or unreadable `profiles` listing now skips the profile-based checks. Before, the audit reported that no profiles were present. This affects ACC-06, FV-04, SEC-04 and the other profile checks. FV-01 still reports FileVault off, with a note that the profile state is unknown.
- ACC-01 and ACC-03 now use `dsmemberutil` for effective admin membership, which includes nested groups. A failed lookup or a failed user listing skips the check.
- NET-04 also scans `/Library/LaunchDaemons`, `/Library/LaunchAgents` (file names and job labels) and `/opt`. NET-04 does not count a folder that it cannot list. NET-04 skips when it can list no folder.
- NET-07 treats an empty `PayloadCertificateAnchorUUID` list as no certificate pin.
- OS-01, OS-02 and OS-03 skip a macOS version newer than any in the SOFA feed.
- OS-01 and OS-02 compare the Background Security Improvement suffix from `sw_vers -productVersionExtra` and note it in the evidence.
- SEC-04 counts a screen-saver password requirement only when `askForPasswordDelay` is 300 seconds or less.
- FV-03, SEC-05 and MDM-02 skip when their command fails. FV-03 accepts only a "true" or "false" answer.
- `profiles`, `system_profiler` and `curl` stop after 60 seconds. A timeout skips the affected checks.
- The About section of the report states whether the audit fetched the SOFA feed.

### Build

- The build script copies the committed `report_assets.json` instead of generating it.
- The build stops when it cannot read the version. The default destination is `~/Desktop`.
