# Changelog

## 2.1.0 (2026-10-21)

Security hardening and more reliable evidence handling.

### Security

- Under sudo, the audit now writes its report into a new root-owned folder with mode 700. The launcher copies the report into the user's log folder from the user's own shell. Root no longer writes, renames or changes ownership inside a user-writable folder.
- Report writes use a random temporary name and refuse a destination or temporary path that is a symbolic link. Reports keep mode 600.
- The launcher sets `umask 077` and clears the cached sudo credential when it finishes. It verifies the app's code signature before it asks for the admin password. If the signature does not verify, the audit runs without admin rights.
- The SOFA download no longer follows redirects.
- The embedded report stylesheet is stripped of `<` characters.
- `--fixture` is accepted only when `JAMF_HOST_AUDIT_FIXTURE=1` is set.

### Fixes

- Pressing Ctrl-C at the password prompt now runs the reduced-coverage audit instead of closing the launcher.
- A failed or unreadable `profiles` listing now skips the profile-based checks instead of reporting that no profiles are installed. This affects ACC-06, FV-04, SEC-04 and the other profile checks. FV-01 still reports FileVault off, with a note that profile state is unknown.
- ACC-01 and ACC-03 now use `dsmemberutil` for effective admin membership, which includes nested groups. A failed lookup or a failed user listing skips the check.
- NET-04 also scans `/Library/LaunchDaemons`, `/Library/LaunchAgents` (file names and job labels) and `/opt`. Folders that cannot be listed are not counted. The check is skipped when no folder can be listed.
- NET-07 treats an empty `PayloadCertificateAnchorUUID` list as no certificate pin.
- OS-01, OS-02 and OS-03 skip a macOS version newer than any in the SOFA feed.
- OS-01 and OS-02 compare the Background Security Improvement suffix from `sw_vers -productVersionExtra` and note it in the evidence.
- SEC-04 counts a screen-saver password requirement only when `askForPasswordDelay` is 300 seconds or less.
- FV-03, SEC-05 and MDM-02 skip when their command fails. FV-03 accepts only a "true" or "false" answer.
- `profiles`, `system_profiler` and `curl` stop after 60 seconds. A timeout skips the affected checks.
- The About section of the report states whether the SOFA feed was fetched.

### Build

- The build script copies the committed `report_assets.json` instead of generating it.
- The build stops when it cannot read the version. The default destination is `~/Desktop`.
