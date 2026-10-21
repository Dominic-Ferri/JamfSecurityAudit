"""Known-bad / known-good controls for jamf_host_audit.js, driven through osascript with --fixture replay."""
import json
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'jamf_host_audit.js'
SOFA_URL = 'https://sofafeed.macadmins.io/v1/macos_data_feed.json'
CURL = (f"/usr/bin/curl -fsSL --proto '=https' --proto-redir '=https' --max-redirs 0 --max-time 20 "
        f"--max-filesize 20971520 '{SOFA_URL}'")
PROFILES = '/usr/bin/profiles show -type configuration -output stdout-xml'
ENV = dict(os.environ, JAMF_HOST_AUDIT_FIXTURE='1')
FAKE_WIFI_PASSWORD = 'WifiSecret99'
SOFA = {'OSVersions': [
    {'OSVersion': 'Golden Gate 27', 'SecurityReleases': [
        {'ProductVersion': '27.0.1', 'ReleaseDate': '2026-09-28T00:00:00Z', 'ActivelyExploitedCVEs': ['CVE-2026-0001']},
        {'ProductVersion': '27.0', 'ReleaseDate': '2026-09-14T00:00:00Z', 'ActivelyExploitedCVEs': []},
        {'ProductVersion': '27.9', 'ReleaseDate': '2099-01-01T00:00:00Z', 'ActivelyExploitedCVEs': ['CVE-2099-9']}]},
    {'OSVersion': 'Tahoe 26', 'SecurityReleases': [
        {'ProductVersion': '26.7', 'ReleaseDate': '2026-09-14T00:00:00Z', 'ActivelyExploitedCVEs': []}]},
    {'OSVersion': 'Sequoia 15', 'SecurityReleases': [
        {'ProductVersion': '15.7.2', 'ReleaseDate': '2026-09-14T00:00:00Z', 'ActivelyExploitedCVEs': []}]},
    {'OSVersion': 'Sonoma 14', 'SecurityReleases': [
        {'ProductVersion': '14.8', 'ReleaseDate': '2025-09-14T00:00:00Z', 'ActivelyExploitedCVEs': []}]},
]}


def ok(out='', rc=0):
    return {'out': out, 'rc': rc}


def profile(name, *payloads):
    return {'ProfileDisplayName': name, 'ProfileIdentifier': f'com.test.{name}',
            'ProfileItems': [{'PayloadType': t, 'PayloadContent': c} for t, c in payloads]}


def profiles_xml(computer):
    return plistlib.dumps({'_computerlevel': computer}).decode()


BAD_PROFILES = [
    profile('LoginA', ('com.apple.loginwindow', {'SHOWFULLNAME': True, 'EnableGuestAccount': True})),
    profile('LoginB', ('com.apple.loginwindow', {'SHOWFULLNAME': False})),
    profile('PSSO', ('com.apple.extensiblesso', {'PlatformSSO': {'UserAuthorizationMode': 'Admin'}})),
    profile('WiFi', ('com.apple.wifi.managed', {'SSID_STR': 'Example', 'EncryptionType': 'None',
                                                'DisableAssociationMACRandomization': True}),
            ('com.apple.wifi.managed', {'SSID_STR': 'Secure', 'EncryptionType': 'WPA2', 'Password': FAKE_WIFI_PASSWORD,
                                        'EAPClientConfiguration': {'AcceptEAPTypes': [25]}})),
    profile('PPPC', ('com.apple.TCC.configuration-profile-policy', {'Services': {
        'SystemPolicyAllFiles': [{'Identifier': 'com.apple.Terminal', 'Allowed': True}],
        'ScreenCapture': [{'Identifier': 'com.teamviewer.TeamViewer', 'Authorization': 'Allow'}]}})),
    profile('Saver', ('com.apple.screensaver', {'idleTime': 900})),
]
GOOD_PROFILES = [
    profile('FileVault', ('com.apple.MCX.FileVault2', {'Enable': 'On'}),
            ('com.apple.security.FDERecoveryKeyEscrow', {'Location': 'Jamf'})),
    profile('Login', ('com.apple.loginwindow', {'SHOWFULLNAME': True, 'DisableGuestAccount': True})),
    profile('PSSO', ('com.apple.extensiblesso', {'PlatformSSO': {'UserAuthorizationMode': 'Standard'}})),
    profile('WiFi', ('com.apple.wifi.managed', {'SSID_STR': 'Secure', 'EncryptionType': 'WPA2', 'EAPClientConfiguration': {
        'AcceptEAPTypes': [13], 'TLSTrustedServerNames': ['radius.test.invalid']}})),
    profile('PPPC', ('com.apple.TCC.configuration-profile-policy', {'Services': {
        'SystemPolicyAllFiles': [{'Identifier': 'com.vendor.backup', 'Allowed': True}]}})),
    profile('Saver', ('com.apple.screensaver', {'idleTime': 900, 'askForPassword': True, 'askForPasswordDelay': 0})),
]
PWPOLICY_DEFAULT = plistlib.dumps({'policyCategoryPasswordContent': [
    {'policyIdentifier': 'com.apple.defaultpasswordpolicy.fde'}]}).decode()
PWPOLICY_MANAGED = plistlib.dumps({'policyCategoryPasswordContent': [
    {'policyIdentifier': 'com.apple.defaultpasswordpolicy.fde'}, {'policyIdentifier': 'com.apple.policy.legacy.minChars'}]}).decode()


def bad():
    return {'commands': {
        '/usr/bin/id -u': ok('0'),
        '/usr/bin/stat -f%Su /dev/console': ok('student'),
        '/usr/sbin/scutil --get ComputerName': ok('lab-01'),
        '/usr/bin/fdesetup status': ok('FileVault is On.'),
        '/usr/bin/fdesetup haspersonalrecoverykey': ok('false'),
        '/bin/test -f /var/db/FileVaultPRK.dat': ok('', 1),
        '/usr/bin/profiles status -type enrollment': ok('Enrolled via DEP: No\nMDM enrollment: Yes\nMDM server: https://jamf.test.invalid:8443/mdm/ServerURL'),
        '/usr/bin/profiles status -type bootstraptoken': ok('profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: NO'),
        '/usr/sbin/system_profiler SPHardwareDataType -json': ok(json.dumps({'SPHardwareDataType': [
            {'activation_lock_status': 'activation_lock_enabled', 'machine_name': 'MacBook Air', 'chip_type': 'Apple M5'}]})),
        '/usr/sbin/system_profiler SPAirPortDataType -json': ok(json.dumps({'SPAirPortDataType': [{'spairport_airport_interfaces': [
            {'spairport_current_network_information': {'spairport_security_mode': 'spairport_security_mode_wpa2_enterprise'}}]}]})),
        '/usr/bin/sw_vers -productVersion': ok('27.0'),
        '/usr/bin/dscl . -list /Users': ok('_spotlight\nadmin\njamf\nroot\nstudent'),
        '/usr/bin/dscl . -list /Users UniqueID': ok('_spotlight 89\njamf 502\nroot 0\nstudent 501'),
        '/usr/bin/dscl . -read /Groups/admin GroupMembership': ok('GroupMembership: root admin student'),
        "/usr/bin/dsmemberutil checkmembership -U 'student' -G admin": ok('user is a member of the group'),
        "/usr/bin/dsmemberutil checkmembership -U 'jamf' -G admin": ok('user is not a member of the group'),
        "/usr/bin/dscl . -read '/Users/admin' IsHidden": ok('dsAttrTypeNative:IsHidden: 1'),   # as a dscl-created stub shows it
        PROFILES: ok(profiles_xml(BAD_PROFILES)),
        '/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled': ok('1'),
        '/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser': ok('student'),
        '/usr/sbin/dsconfigad -show': ok('Active Directory Forest = ad.test.invalid\nActive Directory Domain = ad.test.invalid\n'
                                         'Allowed admin groups = TEST\\Domain Admins'),
        '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate': ok('Firewall is disabled. (State = 0)'),
        '/bin/launchctl print system/com.openssh.sshd >/dev/null': ok(),
        '/bin/launchctl print system/com.apple.screensharing >/dev/null': ok(),
        "/bin/ls -1 '/Applications'": ok('Safari.app\nTeamViewer.app\nAnyDesk.app'),
        "/bin/ls -1 '/Applications/Utilities'": ok('Terminal.app'),
        "/bin/ls -1 '/Users/student/Applications'": ok('', 1),
        "/bin/ls -1 '/Library/LaunchDaemons'": ok('com.vendor.helper.plist'),
        "/bin/ls -1 '/Library/LaunchAgents'": ok(''),
        "/bin/ls -1 '/opt'": ok('homebrew'),
        '/usr/bin/csrutil status': ok('System Integrity Protection status: disabled.'),
        '/usr/sbin/spctl --status': ok('assessments disabled'),
        "/usr/bin/sudo -n -u 'student' /usr/sbin/sysadminctl -screenLock status": ok('2026-10-07 sysadminctl[1:2] screenLock is off'),
        '/usr/bin/pwpolicy getaccountpolicies': ok('Getting global account policies\n' + PWPOLICY_DEFAULT),
        CURL: ok(json.dumps(SOFA)),
    }, 'files': {'/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd': 'enabled',
                 '/Library/LaunchDaemons/com.vendor.helper.plist': plistlib.dumps({'Label': 'com.teamviewer.helper'}).decode()}}


def good():
    f = bad()
    c = f['commands']
    c.update({
        '/usr/bin/fdesetup haspersonalrecoverykey': ok('true'),
        '/bin/test -f /var/db/FileVaultPRK.dat': ok(),
        '/usr/bin/profiles status -type enrollment': ok('Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\nMDM server: https://jamf.test.invalid:8443/mdm/ServerURL'),
        '/usr/bin/profiles status -type bootstraptoken': ok('profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: YES'),
        '/usr/sbin/system_profiler SPHardwareDataType -json': ok(json.dumps({'SPHardwareDataType': [
            {'activation_lock_status': 'activation_lock_disabled', 'machine_name': 'MacBook Air', 'chip_type': 'Apple M5'}]})),
        '/usr/bin/sw_vers -productVersion': ok('27.0.1'),
        '/usr/bin/dscl . -list /Users': ok('_spotlight\nadmin\njamf\nroot\nstudent'),
        '/usr/bin/dscl . -list /Users UniqueID': ok('_spotlight 89\nadmin 503\njamf 502\nroot 0\nstudent 501'),
        '/usr/bin/dscl . -read /Groups/admin GroupMembership': ok('GroupMembership: root jamf admin'),
        "/usr/bin/dsmemberutil checkmembership -U 'student' -G admin": ok('user is not a member of the group'),
        "/usr/bin/dsmemberutil checkmembership -U 'jamf' -G admin": ok('user is a member of the group'),
        "/usr/bin/dsmemberutil checkmembership -U 'admin' -G admin": ok('user is a member of the group'),
        PROFILES: ok(profiles_xml(GOOD_PROFILES)),
        '/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled': ok('0'),
        '/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser':
            ok("The domain/default pair of (/Library/Preferences/com.apple.loginwindow, autoLoginUser) does not exist", 1),
        '/usr/sbin/dsconfigad -show': ok(''),
        '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate': ok('Firewall is enabled. (State = 1)'),
        '/bin/launchctl print system/com.openssh.sshd >/dev/null': ok('', 113),
        '/bin/launchctl print system/com.apple.screensharing >/dev/null': ok('', 113),
        "/bin/ls -1 '/Applications'": ok('Safari.app'),
        '/usr/bin/csrutil status': ok('System Integrity Protection status: enabled.'),
        '/usr/sbin/spctl --status': ok('assessments enabled'),
        '/usr/bin/pwpolicy getaccountpolicies': ok('Getting global account policies\n' + PWPOLICY_MANAGED),
    })
    f['files'] = {}
    return f


class HostAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_audit(self, fixture, *extra, env=ENV):
        fx = self.dir / 'fixture.json'
        fx.write_text(json.dumps(fixture))
        html, js = self.dir / 'r.html', self.dir / 'r.json'
        return subprocess.run(['/usr/bin/osascript', '-l', 'JavaScript', str(SCRIPT), '--fixture', str(fx), '--html', str(html),
                               '--json', str(js), *extra], capture_output=True, text=True, timeout=60, env=env)

    def audit(self, fixture, *extra):
        p = self.run_audit(fixture, *extra)
        self.assertEqual(p.returncode, 0, p.stderr)
        html, js = self.dir / 'r.html', self.dir / 'r.json'
        data = json.loads(js.read_text())
        return {r['id']: r for r in data['results']}, data, html.read_text(), p.stdout + p.stderr

    def test_known_bad_fires(self):
        r, data, _, _ = self.audit(bad())
        expected = {'FV-03': 1, 'FV-04': 1, 'MDM-02': 1, 'MDM-03': 1, 'ACC-01': 1, 'ACC-02': 1, 'ACC-03': 1,
                    'ACC-06': 2, 'ACC-07': 1, 'ACC-08': 1, 'DIR-01': 1, 'DIR-02': 1, 'NET-01': 1, 'NET-02': 1, 'NET-03': 2,
                    'NET-04': 2, 'NET-05': 1, 'NET-06': 1, 'NET-07': 1, 'OS-01': 1, 'OS-02': 1, 'SEC-01': 2, 'SEC-02': 1,
                    'SEC-04': 1, 'SEC-05': 1, 'PRF-01': 1, 'PRF-04': 1, 'PRF-06': 1}
        for rid, n in expected.items():
            self.assertEqual((r[rid]['status'], len(r[rid]['items'])), ('FAIL', n), (rid, r[rid]))
        self.assertEqual(r['FV-01']['status'], 'PASS')
        self.assertEqual(r['OS-03']['status'], 'PASS')
        self.assertEqual(r['NET-05']['severity'], 'Medium')     # AutoJoin defaults on
        self.assertEqual(r['PRF-04']['severity'], 'High')
        self.assertIn('IsHidden=1', r['ACC-02']['items'][0]['detail'])
        teamviewer = next(i['detail'] for i in r['NET-04']['items'] if i['name'] == 'TeamViewer')
        self.assertIn('/Library/LaunchDaemons/com.vendor.helper.plist', teamviewer)   # matched by its Label
        self.assertIn('CVE-2026-0001', r['OS-01']['items'][0]['detail'])
        self.assertNotIn('CVE-2099-9', r['OS-01']['items'][0]['detail'])   # releases after today are ignored
        self.assertEqual(data['incomplete'], [])

    def test_known_good_passes(self):
        r, data, _, _ = self.audit(good())
        bad_status = {k: (v['status'], v['items'], v['note']) for k, v in r.items()
                      if v['status'] not in ('PASS',) and k not in ('DIR-02',)}
        self.assertEqual(bad_status, {})
        self.assertEqual(r['DIR-02']['status'], 'SKIP')         # not bound
        self.assertIn('com.apple.policy.legacy.minChars', r['SEC-05']['note'])
        self.assertEqual(data['incomplete'], [])

    def test_filevault_off_and_old_macos(self):
        f = bad()
        f['commands']['/usr/bin/fdesetup status'] = ok('FileVault is Off.')
        f['commands']['/usr/bin/sw_vers -productVersion'] = ok('14.8')
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['FV-01']['status'], 'FAIL')
        self.assertIn('No installed profile enforces FileVault', r['FV-01']['note'])
        self.assertEqual(r['FV-03']['status'], 'SKIP')
        self.assertIn('FileVault off', r['ACC-07']['items'][0]['detail'])
        self.assertEqual(r['OS-03']['status'], 'FAIL')
        self.assertEqual(r['OS-02']['status'], 'SKIP')

    def test_without_admin_password_root_checks_skip_and_audit_is_incomplete(self):
        f = bad()
        f['commands']['/usr/bin/id -u'] = ok('501')
        r, data, html, out = self.audit(f)
        for rid in ('FV-03', 'FV-04', 'MDM-03', 'ACC-08', 'NET-05', 'NET-06', 'PRF-01', 'PRF-04', 'PRF-06', 'SEC-04'):
            self.assertEqual(r[rid]['status'], 'SKIP', rid)
        self.assertEqual(r['NET-01']['status'], 'FAIL')
        self.assertTrue(data['incomplete'])
        self.assertIn('Incomplete audit', html)
        self.assertIn('INCOMPLETE AUDIT', out)

    def test_no_sofa_feed_skips_os_checks(self):
        r, _, _, _ = self.audit(bad(), '--offline')
        for rid in ('OS-01', 'OS-02', 'OS-03'):
            self.assertEqual(r[rid]['status'], 'SKIP', rid)

    def test_unknown_commands_never_pass_silently(self):
        r, _, _, _ = self.audit({"commands": {"/usr/bin/id -u": ok("0")}})
        self.assertFalse([k for k, v in r.items() if v['status'] == 'ERROR'], 'a check crashed on empty input')
        # With no evidence at all, a check may pass only where an empty answer really means "off".
        self.assertLessEqual({k for k, v in r.items() if v['status'] == 'PASS'},
                             {'NET-02', 'NET-03', 'NET-04', 'ACC-06', 'ACC-07', 'DIR-01', 'ACC-02', 'SEC-05', 'SEC-01', 'MDM-02'})

    def test_report_is_private_and_keeps_secrets_out(self):
        _, _, html, _ = self.audit(bad())
        self.assertNotIn(FAKE_WIFI_PASSWORD, html)
        self.assertEqual(os.stat(self.dir / 'r.html').st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.dir / 'r.json').st_mode & 0o777, 0o600)
        self.assertIn("default-src 'none'", html)
        self.assertNotIn('<script', html)

    def test_failed_membership_lookup_skips_instead_of_passing(self):
        f = good()
        f['commands']["/usr/bin/dsmemberutil checkmembership -U 'student' -G admin"] = ok('There was an unknown error.', 7)
        f['commands']["/usr/bin/dsmemberutil checkmembership -U 'jamf' -G admin"] = ok('', 7)
        f['commands']["/usr/bin/dsmemberutil checkmembership -U 'admin' -G admin"] = ok('', 7)
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['ACC-01']['status'], 'SKIP')
        self.assertEqual(r['ACC-03']['status'], 'SKIP')

    def test_failed_dscl_skips_account_checks(self):
        f = good()
        f['commands']['/usr/bin/dscl . -list /Users'] = ok('', 1)
        f['commands']['/usr/bin/dscl . -read /Groups/admin GroupMembership'] = ok('', 1)
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['ACC-02']['status'], 'SKIP')
        self.assertEqual(r['ACC-03']['status'], 'SKIP')
        self.assertEqual(r['ACC-01']['status'], 'PASS')        # decided by dsmemberutil, not by dscl

    def test_unlistable_folders_skip_remote_control_check(self):
        f = bad()
        for d in ('/Applications', '/Applications/Utilities', '/Library/LaunchDaemons', '/Library/LaunchAgents', '/opt'):
            f['commands'][f"/bin/ls -1 '{d}'"] = ok('ls: Operation not permitted', 1)
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['NET-04']['status'], 'SKIP')

    def test_failed_profiles_listing_skips_profile_checks(self):
        f = good()
        f['commands'][PROFILES] = ok('profiles: error', 1)
        r, _, _, _ = self.audit(f)
        for rid in ('ACC-06', 'FV-04', 'SEC-04', 'PRF-01'):
            self.assertEqual(r[rid]['status'], 'SKIP', rid)
        self.assertEqual(r['FV-01']['status'], 'PASS')          # FileVault on: fdesetup decides
        f['commands']['/usr/bin/fdesetup status'] = ok('FileVault is Off.')
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['FV-01']['status'], 'FAIL')
        self.assertIn('is unknown', r['FV-01']['note'])
        self.assertNotIn('No installed profile', r['FV-01']['note'])

    def test_unparseable_profiles_output_skips(self):
        f = good()
        f['commands'][PROFILES] = ok('<?xml version="1.0"?><plist><dict><key>broken')
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['SEC-04']['status'], 'SKIP')

    def test_empty_certificate_anchor_list_is_not_a_pin(self):
        f = good()
        anchored = [profile('WiFi', ('com.apple.wifi.managed', {'SSID_STR': 'Secure', 'EncryptionType': 'WPA2',
                    'EAPClientConfiguration': {'AcceptEAPTypes': [25], 'PayloadCertificateAnchorUUID': []}}))]
        f['commands'][PROFILES] = ok(profiles_xml(GOOD_PROFILES[:3] + anchored + GOOD_PROFILES[4:]))
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['NET-07']['status'], 'FAIL')

    def test_macos_newer_than_sofa_skips(self):
        f = good()
        f['commands']['/usr/bin/sw_vers -productVersion'] = ok('28.0')
        r, _, _, _ = self.audit(f)
        for rid in ('OS-01', 'OS-02', 'OS-03'):
            self.assertEqual(r[rid]['status'], 'SKIP', rid)
            self.assertIn('does not list macOS 28.0', r[rid]['note'])

    def test_background_security_improvement_suffix_counts(self):
        f = good()
        f['commands']['/usr/bin/sw_vers -productVersionExtra'] = ok('(a)')
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['OS-02']['status'], 'PASS')
        self.assertIn('Background Security Improvement', r['OS-02']['note'])
        f['commands'][CURL] = ok(json.dumps({'OSVersions': [dict(SOFA['OSVersions'][0], SecurityReleases=[
            {'ProductVersion': '27.0.1 (b)', 'ReleaseDate': '2026-10-01T00:00:00Z', 'ActivelyExploitedCVEs': ['CVE-2026-0002']}]
            + SOFA['OSVersions'][0]['SecurityReleases'])] + SOFA['OSVersions'][1:]}))
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['OS-02']['status'], 'FAIL')
        self.assertIn('CVE-2026-0002', r['OS-01']['items'][0]['detail'])

    def test_long_screen_saver_grace_period_is_not_enforcement(self):
        f = good()
        saver = [profile('Saver', ('com.apple.screensaver', {'askForPassword': True, 'askForPasswordDelay': 2147483647}))]
        f['commands'][PROFILES] = ok(profiles_xml(GOOD_PROFILES[:5] + saver))
        r, _, _, _ = self.audit(f)
        self.assertEqual(r['SEC-04']['status'], 'FAIL')
        self.assertIn('over 300 seconds', r['SEC-04']['items'][0]['detail'])

    def test_fixture_refused_without_env_var(self):
        env = {k: v for k, v in os.environ.items() if k != 'JAMF_HOST_AUDIT_FIXTURE'}
        p = self.run_audit(bad(), env=env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('--fixture is for the test suite only', p.stderr)
        self.assertFalse((self.dir / 'r.html').exists())

    def test_symlinked_report_destination_is_refused(self):
        target = self.dir / 'elsewhere.txt'
        target.write_text('keep')
        (self.dir / 'r.html').symlink_to(target)
        p = self.run_audit(bad())
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('refusing to write through a symlink', p.stderr)
        self.assertEqual(target.read_text(), 'keep')
        self.assertTrue((self.dir / 'r.html').is_symlink())


if __name__ == '__main__':
    unittest.main()
