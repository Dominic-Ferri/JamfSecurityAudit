// JamfSecurityAudit host audit: checks THIS Mac for common security gaps in Jamf-managed Macs (FileVault, MDM,
// accounts, remote access, updates, platform security and configuration profiles).
//
// Runs on any Mac with nothing installed: `osascript -l JavaScript jamf_host_audit.js --html OUT [--json OUT]
// [--assets report_assets.json] [--offline]`. Read-only: it only runs macOS status commands (fdesetup, profiles,
// dscl, launchctl, ...) and fetches the public SOFA macOS feed. Run as root (sudo) for full coverage:
// computer-level profiles, the bootstrap token and the FileVault recovery key are readable only by root.
// Sources for each rule's wording are quoted in RULE_SOURCES.md.
// Secret rule: reports carry names, states and counts only. Profile-conflict values are reduced to their types.

ObjC.import('Foundation');
ObjC.import('stdio');

const VERSION = '2.1.1';
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];
const SOFA_URL = 'https://sofafeed.macadmins.io/v1/macos_data_feed.json';
const SECRET_KEY = /password|passwd|passphrase|secret|token|credential|private_?key|\bpsk\b|api_?key/i;
const REMOTE_CONTROL_BUNDLE = /teamviewer|anydesk|splashtop|logmein|screenconnect|rustdesk|bomgar|beyondtrust/i;
const REMOTE_CONTROL_APPS = {
  'TeamViewer': /^teamviewer/i, 'AnyDesk': /^anydesk/i, 'Splashtop': /^splashtop/i, 'LogMeIn': /^logmein/i,
  'ScreenConnect': /screenconnect|connectwise control/i, 'RustDesk': /^rustdesk/i,
  'Chrome Remote Desktop': /chrome remote desktop/i,
};
const SHELL_IDENTIFIERS = new Set(['com.apple.Terminal', 'com.googlecode.iterm2', 'dev.warp.Warp-Stable', '/bin/bash',
  '/bin/zsh', '/bin/sh', '/usr/bin/python3', '/usr/bin/osascript', '/usr/bin/perl', '/usr/bin/ruby']);
// Payload types macOS treats as one setting per key.
const SINGLE_INSTANCE_PAYLOADS = new Set(['com.apple.applicationaccess', 'com.apple.loginwindow', 'com.apple.screensaver',
  'com.apple.MCX', 'com.apple.security.firewall', 'com.apple.systempolicy.control', 'com.apple.preference.security',
  'com.apple.SoftwareUpdate', 'com.apple.mobiledevice.passwordpolicy', 'com.apple.screensaver.user']);

const DOC = {
  FV: 'https://learn.jamf.com/r/en-US/jamf-pro-documentation-current/FileVault',
  FV_PREP: 'https://learn.jamf.com/r/en-US/jamf-pro-documentation-current/Preparing_for_FileVault_Deployment',
  ESCROW: 'https://developer.apple.com/documentation/devicemanagement/fderecoverykeyescrow',
  RESTRICTIONS: 'https://developer.apple.com/documentation/devicemanagement/restrictions',
  FIREWALL: 'https://developer.apple.com/documentation/devicemanagement/firewall',
  FIREWALL_SETTINGS: 'https://support.apple.com/guide/mac-help/change-firewall-settings-on-mac-mh11783/mac',
  AUTOLOGIN: 'https://support.apple.com/guide/mac-help/a-login-window-start-mac-mchlp1158/mac',
  SW_UPDATES: 'https://support.apple.com/guide/deployment/about-software-updates-depc4c80847a/web',
  AD_MOBILITY: 'https://support.apple.com/guide/directory-utility/active-directory-and-mobility-ior6d33c187e/mac',
  PASSCODE_DDM: 'https://developer.apple.com/documentation/devicemanagement/passcodesettings',
  SOFA: 'https://sofa.macadmins.io/', APPLE_SEC: 'https://support.apple.com/en-us/100100',
  BOOTSTRAP: 'https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web',
  ACTLOCK: 'https://support.apple.com/guide/deployment/activation-lock-depf4ab94ef1/web',
  WIFI: 'https://developer.apple.com/documentation/devicemanagement/wifi',
  EAP: 'https://developer.apple.com/documentation/devicemanagement/wifi/eapclientconfiguration-data.dictionary',
  MSCHAP: 'https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2743314',
  PRIVATE_MAC: 'https://support.apple.com/en-us/102509',
  PPPC: 'https://developer.apple.com/documentation/devicemanagement/privacypreferencespolicycontrol',
  LAPS: 'https://learn.jamf.com/r/en-US/technical-paper-laps-current/Local_Administrator_Password_Solution',
  PRESTAGE: 'https://learn.jamf.com/r/en-US/jamf-pro-documentation-current/Computer_PreStage_Enrollments',
  SCREENSAVER: 'https://developer.apple.com/documentation/devicemanagement/screensaver',
  PASSCODE: 'https://developer.apple.com/documentation/devicemanagement/passcode',
  PSSO: 'https://support.apple.com/guide/deployment/platform-sso-for-mac-dep7bbb05313/web',
};

// ---- plumbing ---------------------------------------------------------------------------------

const app = Application.currentApplication();
app.includeStandardAdditions = true;

class MissingData extends Error {}
class NotApplicable extends Error {}

function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

// Run a command through /bin/sh; stdout (plus stderr unless stderr is false) and the exit status. Never throws.
// limit (seconds) kills a slow command: perl's alarm survives exec, so SIGALRM ends it with exit 142.
// --fixture FILE replays recorded {command: {out, rc}} answers instead (tests); unknown commands give rc 127.
let FIXTURE = null;
const LIMIT = 60;
const TIMED_OUT = 142;
function sh(cmd, {limit = 0, stderr = true} = {}) {
  if (FIXTURE) return FIXTURE.commands[cmd] || {out: '', rc: 127};
  const run = limit ? `/usr/bin/perl -e 'alarm shift; exec @ARGV' ${limit} ${cmd}` : cmd;
  try {
    const out = app.doShellScript(`{ ${run} ; } ${stderr ? '2>&1' : '2>/dev/null'}; printf '\\n__RC=%s' $?`, {alteringLineEndings: false});
    const at = out.lastIndexOf('\n__RC=');
    return {out: out.slice(0, at).trim(), rc: parseInt(out.slice(at + 6), 10)};
  } catch (e) {
    return {out: String(e.message || e), rc: -1};
  }
}
// A command that failed or timed out is missing evidence, never a pass.
function failure(cmd, r) {
  return `${cmd.split(' ').slice(0, 2).join(' ')} ${r.rc === TIMED_OUT ? 'timed out' : `failed (exit ${r.rc})`}`;
}
function must(cmd, opts) {
  const r = sh(cmd, opts);
  if (r.rc !== 0) throw new MissingData(failure(cmd, r));
  return r.out;
}

// `defaults read` uses exit 1 when a key is absent. Other failures are missing evidence.
function readDefault(cmd) {
  const r = sh(cmd);
  if (r.rc === 0) return r.out.trim();
  if (r.rc === 1 && /domain\/default pair[\s\S]*does not exist/i.test(r.out)) return null;
  throw new MissingData(failure(cmd, r));
}

function plist(text) {
  const start = text.indexOf('<?xml');
  if (start < 0) return null;
  const data = $(text.slice(start)).dataUsingEncoding($.NSUTF8StringEncoding);
  const obj = $.NSPropertyListSerialization.propertyListWithDataOptionsFormatError(data, 0, null, null);
  return obj.isNil() ? null : ObjC.deepUnwrap(obj);
}

function readFile(path) {
  if (FIXTURE && path !== FIXTURE.allowRead) return (FIXTURE.files || {})[path] || null;
  const s = $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, null);
  return s.isNil() ? null : s.js;
}

// Atomic, mode-600 write: a randomly named temp file next to the target, then rename(2), which replaces the
// target without following it. A symlink at either path is refused.
function writePrivate(path, text) {
  const fm = $.NSFileManager.defaultManager;
  const tmp = `${path}.${$.NSUUID.UUID.UUIDString.js}.tmp`;
  for (const p of [path, tmp])
    if (!fm.destinationOfSymbolicLinkAtPathError(p, null).isNil()) throw new Error(`refusing to write through a symlink: ${p}`);
  if (!$(text).writeToFileAtomicallyEncodingError(tmp, true, $.NSUTF8StringEncoding, null)) throw new Error('write failed');
  fm.setAttributesOfItemAtPathError($({NSFilePosixPermissions: 384}), tmp, null);
  if ($.rename(tmp, path) !== 0) throw new Error('rename failed');
}

// [major, minor, patch, suffix]: the suffix is the Background Security Improvement letter, as in "26.3.1 (a)".
function verTuple(text) {
  const s = String(text || '');
  const p = (s.match(/\d+/g) || []).slice(0, 3).map(Number);
  while (p.length < 3) p.push(0);
  p.push((s.match(/\(([a-z])\)/) || [])[1] || '');
  return p;
}
function verCmp(a, b) { for (let i = 0; i < 4; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; return 0; }

function safeValue(key, value) {
  if (SECRET_KEY.test(key)) return '<set>';
  if (typeof value === 'boolean') return '<boolean>';
  if (typeof value === 'number') return '<number>';
  if (typeof value === 'string') return '<string>';
  return `<${Array.isArray(value) ? 'array' : typeof value}>`;
}

const cache = {};
// Caches a thrown error too, so a failed or timed-out command is not re-run by every rule.
function once(name, fn) {
  if (!(name in cache)) { try { cache[name] = {value: fn()}; } catch (e) { cache[name] = {error: e}; } }
  if (cache[name].error) throw cache[name].error;
  return cache[name].value;
}

// ---- host facts ----------------------------------------------------------------------------------

const isRoot = () => once('root', () => sh('/usr/bin/id -u').out === '0');
const consoleUser = () => once('console', () => {
  const u = sh('/usr/bin/stat -f%Su /dev/console').out;
  return ['root', 'loginwindow', '_mbsetupuser', ''].includes(u) ? '' : u;
});
const fvStatus = () => once('fv', () => must('/usr/bin/fdesetup status'));
const fvOn = () => /FileVault is On/.test(fvStatus()) && !/Decryption in progress/.test(fvStatus());
// rc is non-zero when profiles failed or timed out; then nothing below it is evidence.
const enrollment = () => once('enroll', () => {
  const {out, rc} = sh('/usr/bin/profiles status -type enrollment', {limit: LIMIT});
  const mdm = (out.match(/MDM enrollment:\s*(.*)/) || [])[1] || '';
  return {rc, enrolled: /^Yes/.test(mdm), approved: /User Approved/i.test(mdm), dep: /Enrolled via DEP:\s*Yes/.test(out),
          server: ((out.match(/MDM server:\s*(\S+)/) || [])[1] || '').replace(/^https?:\/\//, '').split('/')[0]};
});
function enrolled() {
  const e = enrollment();
  if (e.rc !== 0) throw new MissingData(`profiles status -type enrollment ${e.rc === TIMED_OUT ? 'timed out' : `failed (exit ${e.rc})`}`);
  return e;
}
const hardware = () => once('hw', () => {
  try {
    return JSON.parse(sh('/usr/sbin/system_profiler SPHardwareDataType -json', {limit: LIMIT}).out).SPHardwareDataType[0];
  } catch (e) { return {}; }
});
// The version plus its Background Security Improvement suffix, if any (for example "26.3.1 (a)").
const osVersion = () => once('os', () => {
  const extra = sh('/usr/bin/sw_vers -productVersionExtra');
  return [sh('/usr/bin/sw_vers -productVersion').out, extra.rc === 0 ? extra.out : ''].filter(Boolean).join(' ');
});
const osNote = () => SOFA.note + (/\(/.test(osVersion()) ? `; compared including the Background Security Improvement suffix of ${osVersion()}` : '');

// Local user records and their UIDs. listed = names in the admin group's own GroupMembership (for notes only).
const users = () => once('users', () => {
  const names = must('/usr/bin/dscl . -list /Users').split('\n').map(s => s.trim()).filter(Boolean);
  const uids = {};
  for (const line of must('/usr/bin/dscl . -list /Users UniqueID').split('\n')) {
    const m = line.trim().match(/^(\S+)\s+(-?\d+)$/);
    if (m) uids[m[1]] = Number(m[2]);
  }
  const listed = (sh('/usr/bin/dscl . -read /Groups/admin GroupMembership').out.split(':')[1] || '').trim().split(/\s+/)
    .filter(Boolean);
  return {names: names.filter(n => !n.startsWith('_')), uids, listed};
});
const adStatus = () => once('ad', () => must('/usr/sbin/dsconfigad -show'));
// Effective admin membership, nested groups included. A failed lookup is missing evidence.
function isAdmin(name) {
  return once(`admin:${name}`, () => {
    const r = sh(`/usr/bin/dsmemberutil checkmembership -U ${shq(name)} -G admin`);
    return {rc: r.rc, member: /is a member/.test(r.out)};
  });
}
function mustBeAdmin(name) {
  const r = isAdmin(name);
  if (r.rc !== 0) throw new MissingData(`dsmemberutil could not check ${name} (exit ${r.rc})`);
  return r.member;
}

// Installed configuration profiles, each payload flattened to {PayloadType, ...PayloadContent}.
// Computer-level profiles are listed only for root. A failed or unreadable listing is missing evidence.
const profiles = () => once('profiles', () => {
  const text = must('/usr/bin/profiles show -type configuration -output stdout-xml', {limit: LIMIT, stderr: false});
  const data = plist(text);
  if (!data && text.trim()) throw new MissingData('profiles gave output that is not a readable property list');
  const out = [];
  for (const [level, list] of Object.entries(data || {})) {
    for (const p of (Array.isArray(list) ? list : [])) {
      const payloads = (p.ProfileItems || []).map(i => Object.assign({PayloadType: i.PayloadType},
        i.PayloadContent && typeof i.PayloadContent === 'object' && !Array.isArray(i.PayloadContent) ? i.PayloadContent : {}));
      out.push({level: level.toLowerCase() === '_computerlevel' ? 'computer' : `user ${level}`,
                name: p.ProfileDisplayName || p.ProfileIdentifier || '?', id: p.ProfileIdentifier || '', payloads});
    }
  }
  return out;
});
function computerProfiles() {
  if (!isRoot()) throw new MissingData('computer-level profiles are readable only with the admin password');
  return profiles();
}
function payloadsOf(type) {
  const out = [];
  for (const p of computerProfiles()) for (const c of p.payloads) if (c.PayloadType === type) out.push([p, c]);
  return out;
}
const hasPayload = type => payloadsOf(type).length > 0;
const label = p => `${p.name} (${p.level})`;

// SOFA: per major, every security release up to now, the newest one, and the three newest majors.
let SOFA = {feed: null, note: 'SOFA feed not loaded'};
function loadSofa(offline) {
  if (offline) { SOFA = {feed: null, note: 'SOFA feed not fetched (--offline)'}; return; }
  const r = sh(`/usr/bin/curl -fsSL --proto '=https' --proto-redir '=https' --max-redirs 0 --max-time 20 --max-filesize 20971520 ${shq(SOFA_URL)}`,
    {limit: LIMIT});
  try {
    const feed = JSON.parse(r.out);
    if (!Array.isArray(feed.OSVersions) || !feed.OSVersions.every(o => Array.isArray(o.SecurityReleases))) throw new Error();
    SOFA = {feed, note: `SOFA feed fetched ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`};
  } catch (e) {
    SOFA = {feed: null, note: 'SOFA feed unavailable (offline or unexpected response)'};
  }
}
function osBaseline() {
  if (!SOFA.feed) throw new MissingData(SOFA.note);
  const now = Date.now(), majors = {};
  for (const o of SOFA.feed.OSVersions) {
    const rel = o.SecurityReleases.filter(r => !(Date.parse(r.ReleaseDate) > now));
    if (!rel.length) continue;
    const latest = rel.reduce((a, b) => (verCmp(verTuple(b.ProductVersion), verTuple(a.ProductVersion)) > 0 ? b : a));
    majors[verTuple(rel[0].ProductVersion)[0]] = {name: o.OSVersion, releases: rel, latest};
  }
  const supported = Object.keys(majors).map(Number).sort((a, b) => b - a).slice(0, 3);
  if (verTuple(osVersion())[0] > supported[0]) throw new MissingData(`SOFA does not list macOS ${osVersion()} yet`);
  return {majors, supported};
}

// ---- rules ---------------------------------------------------------------------------------------

const RULES = [];
function rule(id, title, severity, category, why, fix, docs, fn) { RULES.push({id, title, severity, category, why, fix, docs, fn}); }
const item = (name, detail) => ({name, detail});
const res = (items, checked, unit, note, severity, missing) =>
  ({items, checked, unit, note: note || '', severity: severity || '', missing: missing || []});

// FileVault
rule('FV-01', 'FileVault is off', 'Critical', 'FileVault',
  'The startup disk is not encrypted, so its data can be read if the Mac is lost or stolen.',
  'Scope a FileVault profile (with the recovery-key escrow payload) to this Mac in Jamf, or turn FileVault on in Privacy & Security settings.',
  [DOC.FV], () => {
    if (fvOn()) return res([], 1, 'startup disk', fvStatus().split('\n')[0]);
    let note;
    try { note = hasPayload('com.apple.MCX.FileVault2') ? 'A FileVault enforcement payload IS installed but has not worked: check deferrals and the secure-token user.' : 'No installed profile enforces FileVault.'; }
    catch (e) { note = `Whether a FileVault profile is installed is unknown: ${e.message}.`; }
    return res([item('Startup disk', fvStatus().replace(/\s+/g, ' '))], 1, 'startup disk', note);
  });
rule('FV-03', 'FileVault is on but no personal recovery key exists', 'Critical', 'FileVault',
  'Without a valid personal recovery key in Jamf, IT cannot unlock the disk if the user forgets the password. This Mac has no personal recovery key at all, so Jamf cannot hold a valid one.',
  'Scope a FileVault recovery-key escrow profile plus a key-reissue tool (Escrow Buddy) to this Mac.',
  [DOC.ESCROW, DOC.FV], () => {
    if (!isRoot()) throw new MissingData('fdesetup haspersonalrecoverykey needs the admin password');
    if (!fvOn()) throw new NotApplicable('FileVault is off (FV-01)');
    const r = sh('/usr/bin/fdesetup haspersonalrecoverykey'), has = r.out.trim();
    // The exit status that goes with "false" is undocumented, so the answer decides; any other output is no evidence.
    if (has !== 'true' && has !== 'false') throw new MissingData(`fdesetup haspersonalrecoverykey gave no answer (exit ${r.rc})`);
    return res(has === 'true' ? [] : [item('Personal recovery key', `fdesetup haspersonalrecoverykey: ${has}`)], 1, 'startup disk');
  });
rule('FV-04', 'No recovery-key escrow profile is installed', 'Medium', 'FileVault',
  'Without an escrow profile, a recovery key that changes later reaches Jamf only if a Jamf policy issues a new one.',
  'Scope a profile with the FileVault recovery key escrow payload to all Macs. On macOS 26 and later, installing it while a bootstrap token is present rotates the key and escrows the new one.',
  [DOC.FV_PREP, DOC.ESCROW], () => {
    if (!fvOn()) throw new NotApplicable('FileVault is off (FV-01)');
    const ok = hasPayload('com.apple.security.FDERecoveryKeyEscrow');
    const prk = sh('/bin/test -f /var/db/FileVaultPRK.dat').rc === 0;
    return res(ok ? [] : [item('FDERecoveryKeyEscrow payload', 'not installed')], 1, 'startup disk',
      `/var/db/FileVaultPRK.dat (key encrypted for escrow) ${prk ? 'present' : 'absent'}.`);
  });

// MDM health
rule('MDM-02', 'This Mac lacks user-approved MDM', 'Medium', 'MDM health',
  'Without user-approved MDM, macOS does not apply Privacy Preferences (PPPC), Kernel Extension Policy or System Extensions payloads from Jamf.',
  'Re-enroll through ADE, or have the user approve the MDM profile in System Settings.',
  [DOC.PPPC], () => {
    const e = enrolled();
    const items = !e.enrolled ? [item('MDM enrollment', 'not enrolled in MDM')]
      : e.approved ? [] : [item('MDM enrollment', 'enrolled, not user approved')];
    return res(items, 1, 'MDM enrollment', e.enrolled ? `MDM server ${e.server}; enrolled via ADE: ${e.dep ? 'yes' : 'no'}.` : '');
  });
rule('MDM-03', 'No bootstrap token is escrowed', 'Medium', 'MDM health',
  'Without an escrowed bootstrap token, new mobile and Platform SSO accounts get a secure token only when an administrator authenticates, and on Apple silicon MDM cannot authorize software updates, Erase All Content and Settings or kernel-extension enablement without a user authenticating.',
  'Have a secure-token user log in after MDM enrollment (or run `profiles install -type bootstraptoken`).',
  [DOC.BOOTSTRAP], () => {
    if (!enrolled().enrolled) throw new NotApplicable('not enrolled in MDM (MDM-02)');
    if (!isRoot()) throw new MissingData('profiles status -type bootstraptoken needs the admin password');
    const out = must('/usr/bin/profiles status -type bootstraptoken', {limit: LIMIT});
    const escrowed = /escrowed to server:\s*YES/i.test(out);
    return res(escrowed ? [] : [item('Bootstrap token', out.replace(/profiles:\s*/g, '').replace(/\s*\n\s*/g, '; '))], 1, 'MDM enrollment');
  });

// Accounts
rule('ACC-01', 'The signed-in user is a local administrator', 'High', 'Accounts',
  'Admin users can switch off security settings, remove management software and install anything.',
  'Create Standard users in PreStage, and give a managed (LAPS) admin account to IT instead.',
  [DOC.PRESTAGE], () => {
    const u = consoleUser();
    if (!u) throw new NotApplicable('no user is signed in at the console');
    return res(mustBeAdmin(u) ? [item(u, 'member of the admin group')] : [], 1, 'signed-in user');
  });
rule('ACC-02', 'Local account records are broken (no UID)', 'High', 'Accounts',
  'Jamf policies and LAPS depend on the management account. A record with no UID cannot log in or be rotated.',
  'Find what creates the stub (for example a Jamf script that runs `dscl . create /Users/<name>`) and re-create the account.',
  [DOC.LAPS], () => {
    const u = users();
    const broken = u.names.filter(n => !(n in u.uids));
    const items = broken.map(n => {
      const hidden = (sh(`/usr/bin/dscl . -read ${shq('/Users/' + n)} IsHidden`).out.match(/(?:^|:)IsHidden:\s*(\S+)/m) || [])[1];   // also dsAttrTypeNative:IsHidden (set by `dscl . create`)
      return item(n, `user record has no UniqueID${hidden ? `; IsHidden=${hidden}` : ''}${u.listed.includes(n) ? '; listed in the admin group' : ''}`);
    });
    return res(items, u.names.length, 'local user records');
  });
rule('ACC-03', 'No working admin account for IT', 'High', 'Accounts',
  'If the signed-in user forgets the password or leaves, nobody else can administer this Mac. A Jamf Delete Accounts action with no guard can remove the only other admin.',
  'Re-create the managed admin or management account from Jamf (LAPS), and check that it works before removing any other admin.',
  [DOC.LAPS], () => {
    const u = users(), me = consoleUser();
    const candidates = u.names.filter(n => n !== 'root' && n !== me && u.uids[n] >= 500);
    const working = candidates.filter(n => isAdmin(n).member);
    if (!working.length) candidates.forEach(mustBeAdmin);   // a failed lookup leaves "no IT admin" unproven
    const rest = u.listed.filter(n => n !== 'root' && n !== me);
    return res(working.length ? [] : [item('admin group', `no admin with a working record besides ${me || 'the signed-in user'}`
      + (rest.length ? `; also listed: ${rest.join(', ')} (no UID or a system UID)` : ''))], 1, 'admin group',
      working.length ? `IT admin accounts: ${working.join(', ')}.` : '');
  });
rule('ACC-06', 'The Guest account is on', 'Medium', 'Accounts',
  'A guest login gives anyone at the keyboard a session on the Mac.',
  'Remove the guest keys from the profile, and keep guest off in one login-window profile only.',
  [], () => {
    const items = [];
    if (readDefault('/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled') === '1')
      items.push(item('Login window', 'GuestEnabled=1'));
    let note = '', missing = [];
    try {
      for (const p of computerProfiles()) for (const c of p.payloads)
        if (c.EnableGuestAccount === true || c.DisableGuestAccount === false) items.push(item(label(p), `${c.PayloadType} enables Guest`));
    } catch (e) {
      if (!items.length) throw e;   // a profile could still enable Guest
      note = 'Profiles not checked: ' + e.message + '.';
      missing.push(e.message);
    }
    return res(items, 1, 'login window', note, '', missing);
  });
rule('ACC-07', 'Automatic login is on', 'High', 'Accounts',
  'Anyone who restarts this Mac reaches the chosen account\'s desktop without a password. macOS turns automatic login off when FileVault is on, so automatic login also means the disk is not encrypted.',
  'Turn on FileVault (FV-01), which turns automatic login off, and turn automatic login off in Users & Groups settings.',
  [DOC.AUTOLOGIN], () => {
    const user = readDefault('/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser');
    return res(user ? [item(user, `automatic login; FileVault ${fvOn() ? 'on' : 'off'}`)] : [], 1, 'login window');
  });
rule('ACC-08', 'A Platform SSO profile makes users administrators', 'High', 'Accounts',
  'With UserAuthorizationMode set to Admin, macOS adds each user who authenticates with Platform SSO to the local administrators group. NewUserAuthorizationMode Admin does the same for accounts created at sign-in.',
  'Set UserAuthorizationMode and NewUserAuthorizationMode to Standard (or Groups with an admin group).',
  [DOC.PSSO], () => {
    const found = payloadsOf('com.apple.extensiblesso');
    const items = [];
    for (const [p, c] of found) {
      const ps = c.PlatformSSO || {};
      const modes = ['UserAuthorizationMode', 'NewUserAuthorizationMode'].filter(k => ps[k] === 'Admin');
      if (modes.length) items.push(item(label(p), modes.map(k => `${k}=Admin`).join(', ')));
    }
    return res(items, found.length, 'SSO extension payloads');
  });
rule('DIR-01', 'This Mac is bound to Active Directory', 'Low', 'Accounts',
  'Bound Macs keep a computer-account password and cache mobile-account passwords. Away from the organisation\'s network, mobile accounts can still sign in, but password changes made off the network fall out of sync with AD and the login keychain, and accounts that are not mobile accounts cannot sign in.',
  'Plan the unbind and move to Platform SSO or local accounts.',
  [DOC.AD_MOBILITY], () => {
    const out = adStatus();
    const domain = (out.match(/Active Directory Domain\s*=\s*(.+)/) || [])[1];
    return res(domain ? [item('Active Directory', `bound to ${domain.trim()}`)] : [], 1, 'directory binding');
  });
rule('DIR-02', 'The AD binding makes directory groups local administrators', 'Medium', 'Accounts',
  'Every member of these AD groups becomes an admin on each bound Mac, so one compromised AD account controls them all.',
  'Remove broad groups (for example Domain Admins) from the binding\'s admin groups.',
  [], () => {
    const out = adStatus();
    if (!/Active Directory Domain/.test(out)) throw new NotApplicable('not bound to Active Directory');
    const groups = ((out.match(/Allowed admin groups\s*=\s*(.+)/) || [])[1] || '').trim();
    return res(groups && groups !== 'not set' ? [item('Allowed admin groups', groups)] : [], 1, 'directory binding');
  });

// Remote access
rule('NET-01', 'The macOS firewall is off', 'High', 'Remote access',
  'The application firewall blocks incoming connections to apps and services that are not allowed. It does not filter services turned on in Sharing settings (Apple: they "can connect through the firewall"), so SSH and Screen Sharing (NET-02, NET-03) stay reachable either way.',
  'Deploy a Firewall profile (EnableFirewall=true) to all Macs, and turn off sharing services that are not needed.',
  [DOC.FIREWALL_SETTINGS, DOC.FIREWALL], () => {
    const out = sh('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate').out;
    if (!/enabled|disabled/i.test(out)) throw new MissingData('socketfilterfw gave no state');
    return res(/disabled|State = 0/.test(out) ? [item('Application firewall', out)] : [], 1, 'firewall');
  });
rule('NET-02', 'SSH (Remote Login) is on', 'High', 'Remote access',
  'Remote Login lets every account in its "Allow access for" list sign in with a password from any network the Mac joins. The macOS firewall does not block services turned on in Sharing settings.',
  'Turn off "Ensure SSH is running" (enrollment) and the startup-script SSH option (check-in) in Jamf, then disable sshd.',
  [DOC.FIREWALL_SETTINGS], () => {
    const on = launchdLoaded('com.openssh.sshd');
    return res(on ? [item('com.openssh.sshd', 'loaded in launchd (Remote Login on)')] : [], 1, 'sharing service');
  });
rule('NET-03', 'Screen Sharing / Remote Management is on', 'Medium', 'Remote access',
  'Remote Desktop gives full control of the session to anyone with an allowed account.',
  'Limit ARD to a named admin account and only the Macs that need it.',
  [], () => {
    const items = [];
    if (launchdLoaded('com.apple.screensharing'))
      items.push(item('com.apple.screensharing', 'loaded in launchd (Screen Sharing or Remote Management on)'));
    const ard = readFile('/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd');
    if (ard && /enabled/i.test(ard)) items.push(item('Remote Management (ARD)', 'RemoteManagement.launchd says enabled'));
    return res(items, 2, 'sharing services');
  });
rule('NET-04', 'Third-party remote-control apps are installed', 'Medium', 'Remote access',
  'Each remote-control app is another inbound path that bypasses Jamf and SSO.',
  'Standardise on one tool, restrict who can connect, and remove the rest with Restricted Software.',
  [], () => {
    const apps = ['/Applications', '/Applications/Utilities'].concat(consoleUser() ? [`/Users/${consoleUser()}/Applications`] : []);
    const found = {}, add = (name, path) => (found[name] = found[name] || []).push(path);
    let listed = 0;
    for (const d of apps.concat(['/Library/LaunchDaemons', '/Library/LaunchAgents', '/opt'])) {
      const r = sh(`/bin/ls -1 ${shq(d)}`);
      if (r.rc !== 0) continue;   // a folder that could not be listed was not checked
      listed += 1;
      for (const n of r.out.split('\n').filter(Boolean)) {
        const path = `${d}/${n}`;
        if (apps.includes(d)) {
          if (!n.endsWith('.app')) continue;
          for (const [name, pat] of Object.entries(REMOTE_CONTROL_APPS)) if (pat.test(n)) add(name, path);
          continue;
        }
        const hit = `${n} ${n.endsWith('.plist') ? launchdLabel(path) : ''}`.match(REMOTE_CONTROL_BUNDLE);
        if (hit) add(Object.keys(REMOTE_CONTROL_APPS).find(k => REMOTE_CONTROL_APPS[k].test(hit[0])) || hit[0], path);
      }
    }
    if (!listed) throw new MissingData('none of the application, launchd or /opt folders could be listed');
    return res(Object.entries(found).map(([n, paths]) => item(n, paths.join(', '))), listed, 'folders');
  });
function launchdLabel(path) {
  const d = FIXTURE ? plist(readFile(path) || '') : ObjC.deepUnwrap($.NSDictionary.dictionaryWithContentsOfFile(path));
  return (d && d.Label) || '';
}
// launchctl print: 0 = loaded (on), 113 = no such service (off). Anything else is not evidence either way.
function launchdLoaded(label) {
  const rc = sh(`/bin/launchctl print system/${label} >/dev/null`).rc;
  if (rc !== 0 && rc !== 113) throw new MissingData(`launchctl could not report ${label} (exit ${rc})`);
  return rc === 0;
}
function wifiPayloads() { return payloadsOf('com.apple.wifi.managed'); }
rule('NET-05', 'A Wi-Fi profile defines an open network (no encryption)', 'Medium', 'Remote access',
  'An open definition has no encryption and no server check, so whoever runs an access point with that name can read and change the traffic (man-in-the-middle). With AutoJoin on (the default) the Mac joins such an access point by itself; with AutoJoin off the user must pick the network. Rated Low when every open definition has AutoJoin off.',
  'Give the payload the real WPA2/WPA3 Enterprise (EAP) settings with a pinned RADIUS certificate (NET-07), or delete it.',
  [DOC.WIFI], () => {
    const all = wifiPayloads(), items = [];
    let auto = 0;
    for (const [p, c] of all) {
      if (c.EncryptionType !== 'None') continue;
      const on = c.AutoJoin !== false;
      auto += on;
      items.push(item(label(p), `SSID ${JSON.stringify(c.SSID_STR)} EncryptionType=None; AutoJoin ${on ? 'on' : 'off'}${'AutoJoin' in c ? '' : ' (default)'}`));
    }
    return res(items, all.length, 'Wi-Fi payloads', '', auto ? 'Medium' : 'Low');
  });
rule('NET-06', 'A Wi-Fi profile turns off Private Wi-Fi Address', 'Low', 'Remote access',
  'The Mac sends its real hardware MAC address on that network name. Anyone running an access point with that name, including a rogue one, can identify and track the specific Mac. Apple shows a privacy warning for such networks.',
  'Remove DisableAssociationMACRandomization unless network access control needs the real MAC, and never on an open network.',
  [DOC.WIFI, DOC.PRIVATE_MAC], () => {
    const all = wifiPayloads(), items = [];
    let sev = '';
    for (const [p, c] of all) {
      if (c.DisableAssociationMACRandomization !== true) continue;
      const open = c.EncryptionType === 'None';
      if (open) sev = 'Medium';
      items.push(item(label(p), `SSID ${JSON.stringify(c.SSID_STR)}: DisableAssociationMACRandomization=true${open ? '; network is also open (NET-05)' : ''}`));
    }
    return res(items, all.length, 'Wi-Fi payloads', '', sev);
  });
rule('NET-07', 'Enterprise Wi-Fi does not pin its RADIUS server certificate', 'High', 'Remote access',
  'Without TLSTrustedServerNames or a certificate anchor, macOS asks the user whether to trust a RADIUS certificate it does not already trust. A rogue access point copying the SSID ("evil twin") gets the 802.1X sign-in if the user accepts. With PEAP-MSCHAPv2, that network then receives the MS-CHAPv2 exchange, which Microsoft says can be decrypted to recover credentials.',
  'Push a managed 802.1X Wi-Fi profile with TLSTrustedServerNames (the RADIUS server name) and the RADIUS CA as an anchor. This removes the trust prompt, so a rogue server fails closed. Microsoft recommends moving from MS-CHAPv2 to certificate-based EAP-TLS.',
  [DOC.EAP, DOC.MSCHAP], () => {
    const items = [];
    let eap = 0;
    for (const [p, c] of wifiPayloads()) {
      const cfg = c.EAPClientConfiguration;
      if (!cfg || typeof cfg !== 'object') continue;
      eap += 1;
      if (!(cfg.TLSTrustedServerNames || []).length && !(cfg.PayloadCertificateAnchorUUID || []).length)
        items.push(item(label(p), `SSID ${JSON.stringify(c.SSID_STR)}: EAP with no TLSTrustedServerNames and no certificate anchor; the user decides trust`));
      else if (cfg.TLSAllowTrustExceptions === true)
        items.push(item(label(p), `SSID ${JSON.stringify(c.SSID_STR)}: TLSAllowTrustExceptions=true re-enables the trust prompt`));
    }
    if (eap) return res(items, eap, 'enterprise Wi-Fi payloads');
    let mode = '';
    try {
      for (const i of JSON.parse(sh('/usr/sbin/system_profiler SPAirPortDataType -json', {limit: LIMIT}).out).SPAirPortDataType[0].spairport_airport_interfaces || [])
        mode = mode || ((i.spairport_current_network_information || {}).spairport_security_mode || '');
    } catch (e) { /* no Wi-Fi data: decide on profiles alone */ }
    if (/enterprise/i.test(mode))
      return res([item('No managed 802.1X Wi-Fi profile', `connected with ${mode.replace('spairport_security_mode_', '')}, but no installed profile carries EAP settings, so the user decided RADIUS trust at join time`)],
        1, 'Wi-Fi connection');
    return res([], 0, 'enterprise Wi-Fi payloads', 'No managed 802.1X profile and not on an enterprise Wi-Fi network.');
  });

// Updates
rule('OS-01', 'This Mac misses fixes for actively exploited vulnerabilities', 'Critical', 'Updates',
  'Apple\'s security notes for these fixes say Apple "is aware of a report" that the issue may have been exploited (sometimes on iPhone or iPad rather than Mac). This Mac does not have the release that fixes them.',
  'Enforce the update with a Managed Software Update plan or DDM software-update declaration.',
  [DOC.APPLE_SEC, DOC.SOFA], () => {
    const {majors} = osBaseline(), v = verTuple(osVersion()), info = majors[v[0]];
    if (!info) throw new MissingData(`SOFA does not track macOS ${osVersion()}`);
    const missing = [...new Set(info.releases.filter(r => verCmp(verTuple(r.ProductVersion), v) > 0)
      .flatMap(r => r.ActivelyExploitedCVEs || []))].sort();
    return res(missing.length ? [item(`macOS ${osVersion()}`, `missing ${missing.length} exploited-CVE fixes (${missing.slice(0, 6).join(', ')}${missing.length > 6 ? '…' : ''})`)] : [],
      1, 'macOS install', osNote());
  });
rule('OS-02', 'This Mac is behind the latest security release for its macOS version', 'High', 'Updates',
  'Each missed release leaves published vulnerabilities open.',
  'Enforce updates with a deadline (Managed Software Updates or DDM) and track the stragglers.',
  [DOC.APPLE_SEC, DOC.SOFA], () => {
    const {majors, supported} = osBaseline(), v = verTuple(osVersion());
    if (!supported.includes(v[0])) throw new NotApplicable(`macOS ${osVersion()} is no longer supported (OS-03)`);
    const latest = majors[v[0]].latest;
    return res(verCmp(v, verTuple(latest.ProductVersion)) < 0
      ? [item(`macOS ${osVersion()}`, `older than ${latest.ProductVersion} (${String(latest.ReleaseDate).slice(0, 10)})`)] : [],
      1, 'macOS install', osNote());
  });
rule('OS-03', 'This Mac runs a macOS version that no longer gets security updates', 'High', 'Updates',
  'Apple says older macOS versions do not get every known security fix, and in practice it has shipped security updates only for the current macOS and the two before it. This Mac runs an older version than that.',
  'Upgrade or replace this Mac; block it from sensitive resources until then.',
  [DOC.SW_UPDATES, DOC.APPLE_SEC, DOC.SOFA], () => {
    const {supported} = osBaseline(), v = verTuple(osVersion());
    return res(supported.includes(v[0]) ? [] : [item(`macOS ${osVersion()}`, `supported: ${supported.join(', ')}`)], 1, 'macOS install', SOFA.note);
  });

// Platform security
rule('SEC-01', 'SIP or Gatekeeper is off', 'High', 'Platform security',
  'System Integrity Protection and Gatekeeper block tampering with system files and unsigned apps.',
  'Re-enable from Recovery (csrutil enable) and with spctl; investigate why they were turned off.',
  [], () => {
    const commands = [['System Integrity Protection', '/usr/bin/csrutil status', /status: enabled/],
                      ['Gatekeeper', '/usr/sbin/spctl --status', /assessments enabled/]];
    const items = [], missing = [];
    let checked = 0;
    for (const [name, command, enabled] of commands) {
      const r = sh(command);
      if (r.rc !== 0) { missing.push(failure(command, r)); continue; }
      checked += 1;
      if (!enabled.test(r.out)) items.push(item(name, r.out.replace(/\s+/g, ' ')));
    }
    return res(items, checked, 'protections', '', '', missing);
  });
rule('SEC-02', 'Activation Lock is on', 'Medium', 'Platform security',
  'An Activation-Locked Mac needs the user\'s Apple Account or an escrowed bypass code to reuse.',
  'Turn on "Prevent user from enabling Activation Lock" in each PreStage, and confirm Jamf holds a bypass code for this Mac.',
  [DOC.ACTLOCK], () => {
    const s = hardware().activation_lock_status;
    if (!s) throw new MissingData('system_profiler reports no Activation Lock status');
    return res(s === 'activation_lock_enabled' ? [item('Activation Lock', 'enabled')] : [], 1, 'Mac');
  });
rule('SEC-04', 'No profile requires a password after the screen saver starts', 'Medium', 'Platform security',
  'No installed profile requires a password after the screen saver starts (askForPassword). Whether this Mac locks is left to the user\'s Lock Screen setting, which the user can change or delay.',
  'Add askForPassword=true and askForPasswordDelay=0 to the all-computers screen-saver profile.',
  [DOC.SCREENSAVER], () => {
    const asks = payloadsOf('com.apple.screensaver').filter(([, c]) => c.askForPassword === true);
    // A grace period over 5 minutes (2147483647 turns the requirement off) is not enforcement.
    const validDelay = c => typeof c.askForPasswordDelay === 'number' && Number.isFinite(c.askForPasswordDelay)
      && c.askForPasswordDelay >= 0 && c.askForPasswordDelay <= 300;
    const ok = asks.filter(([, c]) => validDelay(c));
    const invalidDelay = asks.some(([, c]) => typeof c.askForPasswordDelay !== 'number'
      || !Number.isFinite(c.askForPasswordDelay) || c.askForPasswordDelay < 0);
    const delayList = asks.map(([p, c]) => `${p.name}: ${c.askForPasswordDelay === undefined ? 'missing' : c.askForPasswordDelay}`).join(', ');
    const me = consoleUser();
    // sysadminctl reports the calling user's setting, so as root ask on behalf of the signed-in user.
    const cmd = isRoot() ? `/usr/bin/sudo -n -u ${shq(me)} /usr/sbin/sysadminctl -screenLock status` : '/usr/sbin/sysadminctl -screenLock status';
    const now = me ? sh(cmd).out.replace(/^.*\]\s*/s, '') : '';
    return res(ok.length ? [] : [item('Screen saver', asks.length
      ? `askForPassword is set, but askForPasswordDelay is ${invalidDelay ? 'missing or invalid' : 'over 300 seconds'} (${delayList})`
      : 'no installed profile sets askForPassword')], 1, 'Mac',
      (ok.length ? `Enforced by: ${ok.map(([p]) => p.name).join(', ')}. ` : '') + (now ? `User setting: ${now}.` : ''));
  });
rule('SEC-05', 'No password policy applies', 'High', 'Platform security',
  'The login password also unlocks FileVault. Without a password policy only macOS\'s built-in rule applies.',
  'Scope a password policy to all managed Macs (keep only documented exceptions). Apple deprecates the Passcode payload in macOS 27; use the PasscodeSettings declaration there.',
  [DOC.PASSCODE, DOC.PASSCODE_DDM], () => {
    const pol = plist(must('/usr/bin/pwpolicy getaccountpolicies')) || {};
    // com.apple.defaultpasswordpolicy.* is macOS's own built-in rule, not a managed policy.
    const ids = (pol.policyCategoryPasswordContent || []).map(p => p.policyIdentifier || '?')
      .filter(id => !/^com\.apple\.defaultpasswordpolicy/.test(id));
    return res(ids.length ? [] : [item('Global account policies', 'no password-content policy beyond the macOS default')], 1, 'Mac',
      ids.length ? `Password-content policies: ${ids.join(', ')}.` : '');
  });

// Profiles
rule('PRF-01', 'Installed profiles set the same key to different values', 'High', 'Profiles',
  'For the Restrictions payload, Apple says managing the same restriction in different payloads "results in unexpected behavior". Other payload types follow their own merge rules, so the effective value cannot be read from any one profile.',
  'Keep each key in exactly one profile; strip untouched keys from full templates.',
  [DOC.RESTRICTIONS], () => {
    const seen = {};
    for (const p of computerProfiles()) for (const c of p.payloads) {
      if (!SINGLE_INSTANCE_PAYLOADS.has(c.PayloadType)) continue;
      for (const [k, v] of Object.entries(c)) {
        if (k.startsWith('Payload') || (v && typeof v === 'object')) continue;
        (seen[`${k} (${c.PayloadType})`] = seen[`${k} (${c.PayloadType})`] || []).push([p, k, v]);
      }
    }
    const items = [];
    for (const [key, rows] of Object.entries(seen).sort()) {
      if (new Set(rows.map(r => JSON.stringify(r[2]))).size < 2) continue;
      items.push(item(key, rows.map(([p, k, v]) => `${p.name}=${safeValue(k, v)}`).join(', ')));
    }
    return res(items, Object.keys(seen).length, 'payload keys');
  });
function pppc() { return payloadsOf('com.apple.TCC.configuration-profile-policy'); }
rule('PRF-04', 'A privacy profile gives Full Disk Access to Terminal or a script interpreter', 'Medium', 'Profiles',
  'Anything run through that shell inherits Full Disk Access to mail, messages, Safari data and other users\' files.',
  'Grant Full Disk Access to the specific signed tool that needs it, never to a shell or Terminal.',
  [DOC.PPPC], () => {
    const all = pppc(), items = [];
    for (const [p, c] of all) for (const e of ((c.Services || {}).SystemPolicyAllFiles || [])) {
      const allowed = e.Allowed === true || e.Allowed === 1 || e.Authorization === 'Allow';
      if (allowed && SHELL_IDENTIFIERS.has(e.Identifier)) items.push(item(label(p), `Full Disk Access → ${e.Identifier}`));
    }
    return res(items, all.length, 'privacy payloads', '', items.length ? 'High' : '');
  });
rule('PRF-06', 'A privacy profile gives remote-control apps full disk, screen and accessibility access', 'Medium', 'Profiles',
  'The remote-control tool can then read every file and drive the session on this Mac, so its accounts become keys to it.',
  'Scope these approvals only to Macs that support staff need to reach.',
  [DOC.PPPC], () => {
    const all = pppc(), items = [];
    for (const [p, c] of all) {
      const grants = new Set();
      for (const [svc, entries] of Object.entries(c.Services || {})) {
        if (!['SystemPolicyAllFiles', 'ScreenCapture', 'Accessibility', 'PostEvent'].includes(svc)) continue;
        for (const e of entries || []) {
          const allowed = e.Allowed === true || e.Allowed === 1 || ['Allow', 'AllowStandardUserToSetSystemService'].includes(e.Authorization);
          if (allowed && REMOTE_CONTROL_BUNDLE.test(e.Identifier || '')) grants.add(`${svc} → ${e.Identifier}`);
        }
      }
      if (grants.size) items.push(item(label(p), [...grants].sort().join('; ')));
    }
    return res(items, all.length, 'privacy payloads');
  });

// ---- run and report ----------------------------------------------------------------------------------

function runRules() {
  const out = [];
  for (const r of RULES) {
    const rec = {id: r.id, title: r.title, category: r.category, severity: r.severity, why: r.why, fix: r.fix, docs: r.docs};
    try {
      const x = r.fn();
      const incomplete = x.missing.length > 0;
      Object.assign(rec, {status: x.items.length ? 'FAIL' : incomplete ? 'SKIP' : 'PASS', items: x.items,
                          checked: x.checked, unit: x.unit,
                          note: [x.note, incomplete ? `Missing evidence: ${x.missing.join('; ')}` : ''].filter(Boolean).join('; '),
                          severity: x.severity || r.severity, incomplete});
      if (!x.items.length && !x.checked && !incomplete)
        Object.assign(rec, {status: 'SKIP', note: [`Nothing to check (0 ${x.unit})`, x.note].filter(Boolean).join('; ')});
    } catch (e) {
      if (e instanceof MissingData) Object.assign(rec, {status: 'SKIP', items: [], checked: 0, unit: '',
        note: `Not checked: ${e.message}`, incomplete: true});
      else if (e instanceof NotApplicable) Object.assign(rec, {status: 'SKIP', items: [], checked: 0, unit: '',
        note: `Not applicable: ${e.message}`, incomplete: false});
      else Object.assign(rec, {status: 'ERROR', items: [], checked: 0, unit: '',
        note: `${e.name || 'Error'} (details withheld from the report)`, incomplete: true});
    }
    out.push(rec);
  }
  const rank = {FAIL: 0, ERROR: 1, SKIP: 2, PASS: 3};
  return out.sort((a, b) => rank[a.status] - rank[b.status] || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || (a.id < b.id ? -1 : 1));
}

function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function facts() {
  const hw = hardware(), e = enrollment();
  return [['Mac', sh('/usr/sbin/scutil --get ComputerName').out || '?'],
          ['macOS', osVersion()],
          ['Model', [hw.machine_name, hw.chip_type || hw.cpu_type].filter(Boolean).join(', ') || '?'],
          ['Signed-in user', consoleUser() || 'nobody'],
          ['MDM', e.rc !== 0 ? 'unknown' : e.enrolled ? `${e.server}${e.approved ? '' : ' (not user approved)'}` : 'not enrolled'],
          ['Coverage', isRoot() ? 'full (admin)' : 'reduced (no admin password)']];
}

function renderHtml(results, assets, reasons) {
  const fails = results.filter(r => r.status === 'FAIL'), passed = results.filter(r => r.status === 'PASS');
  const unrun = results.filter(r => r.status === 'SKIP' || r.status === 'ERROR');
  const cls = s => `c-${s.toLowerCase()}`;
  const docLink = u => `<a href="${esc(u)}">${esc((assets.doc_titles || {})[u] || u.split('/')[2])}</a>`;
  const out = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
    `<title>Jamf Security Audit</title><style>${(assets.css || '').replace(/</g, '')}</style></head><body><main>`];
  out.push('<header class="mast"><div><h1>Jamf Security Audit</h1><div class="host">This Mac, checked for common Jamf security gaps</div></div><dl class="facts">'
    + facts().map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('') + '</dl></header>');
  out.push('<nav class="tape" aria-label="Every rule, worst first">' + results.map(r => {
    const c = r.status === 'FAIL' ? cls(r.severity) : r.status === 'PASS' ? 'c-pass' : 'c-skip';
    const l = `${r.id}: ${r.title} (${r.status.toLowerCase()})`;
    return `<a class="${c}" href="#${esc(r.id)}" title="${esc(l)}" aria-label="${esc(l)}"></a>`;
  }).join('') + '</nav>');
  const legend = SEVERITIES.map(s => [cls(s), fails.filter(r => r.severity === s).length, s.toLowerCase()])
    .concat([['c-skip', unrun.length, 'not evaluated'], ['c-pass', passed.length, 'passed']]);
  out.push('<ul class="legend">' + legend.map(([c, n, t]) => `<li class="${c}"><b>${n}</b>${esc(t)}</li>`).join('') + '</ul>');
  out.push(`<p class="caption">${results.length} checks, worst first. Each mark links to its result.</p>`);
  if (reasons.length) out.push(`<p class="warn"><b>Incomplete audit:</b> ${esc(reasons.join('; '))}. A missing finding in this report is not a pass.</p>`);
  for (const s of SEVERITIES) {
    const group = fails.filter(r => r.severity === s);
    if (!group.length) continue;
    out.push(`<section class="${cls(s)}"><h2>${s}<small>${group.length} finding${group.length === 1 ? '' : 's'}</small></h2>`);
    for (const r of group) {
      out.push(`<article class="finding" id="${esc(r.id)}"><header><div class="kicker"><span class="id">${esc(r.id)}</span>${esc(r.category)}</div>`
        + `<h3>${esc(r.title)}</h3><div class="tally"><b>${r.items.length}</b><span>of ${r.checked} ${esc(r.unit)}</span></div></header>`
        + `<div class="prose"><p>${esc(r.why)}</p><p><b>Fix:</b> ${esc(r.fix)}</p>`
        + (r.note ? `<p class="note">${esc(r.note)}</p>` : '')
        + (r.docs.length ? '<p class="docs">Sources: ' + r.docs.map(docLink).join('') + '</p>' : '') + '</div>'
        + '<div class="wrap"><table><tr><th>What</th><th>Detail</th></tr>'
        + r.items.map(i => `<tr><td>${esc(i.name)}</td><td>${esc(i.detail)}</td></tr>`).join('') + '</table></div></article>');
    }
    out.push('</section>');
  }
  const list = (title, cssClass, rows, small) => rows.length ? [`<section class="${cssClass}"><h2>${title}<small>${rows.length} check${rows.length === 1 ? '' : 's'}</small></h2><ul class="checks">`
    + rows.map(r => `<li id="${esc(r.id)}"><span class="id">${esc(r.id)}</span>${esc(r.title)}<small>${esc(small(r))}</small></li>`).join('') + '</ul></section>'] : [];
  out.push(...list('Not evaluated', 'c-skip', unrun, r => `${r.status === 'SKIP' ? 'Skipped' : 'Error'}: ${r.note}`));
  out.push(...list('Passed', 'c-pass', passed, r => `${r.checked} ${r.unit} checked${r.note ? '; ' + r.note : ''}`));
  out.push('<section><h2>About this audit</h2><ul class="about">'
    + `<li>Read-only: this Mac was checked with macOS status commands (fdesetup, profiles, dscl, launchctl, pwpolicy, system_profiler). Nothing was changed, and nothing was sent anywhere. The update checks use the public SOFA macOS feed: ${esc(SOFA.note)}.</li>`
    + '<li>Computer-level profiles, the bootstrap token and the FileVault recovery key are readable only with the admin password. Without it those checks are listed under Not evaluated.</li>'
    + '<li>Server-side settings (SSO, API clients, invitations, scopes) and Recovery Lock and LAPS state cannot be read from a Mac, so this audit does not cover them.</li>'
    + '<li>Secret-capable payload values (passwords, tokens, keys) are never copied into this report.</li></ul></section>');
  out.push(`<footer>JamfSecurityAudit host audit ${VERSION}, generated ${new Date().toString().slice(0, 21)}.</footer></main></body></html>`);
  return out.join('\n');
}

function run(argv) {
  const opt = {};
  for (let i = 0; i < argv.length; i++) {
    if (['--html', '--json', '--assets', '--fixture'].includes(argv[i])) opt[argv[i].slice(2)] = argv[++i];
    else if (argv[i] === '--offline') opt.offline = true;
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  if (opt.fixture) {
    // Replayed answers would make a fake report look real, so only the test harness may use them.
    if (ObjC.unwrap($.NSProcessInfo.processInfo.environment.objectForKey('JAMF_HOST_AUDIT_FIXTURE')) !== '1')
      throw new Error('--fixture is for the test suite only (set JAMF_HOST_AUDIT_FIXTURE=1)');
    FIXTURE = Object.assign(JSON.parse(readFile(opt.fixture)), {allowRead: opt.assets});
  }
  loadSofa(opt.offline);
  const results = runRules();
  const reasons = [];
  const crashed = results.filter(r => r.status === 'ERROR').map(r => r.id);
  if (crashed.length) reasons.push(`${crashed.length} check${crashed.length === 1 ? '' : 's'} could not run (${crashed.join(', ')})`);
  const missing = results.filter(r => r.incomplete && r.status !== 'ERROR').map(r => r.id);
  if (missing.length) reasons.push(`${missing.length} check${missing.length === 1 ? '' : 's'} lacked reliable evidence (${missing.join(', ')})`);
  if (!isRoot()) reasons.push('run without the admin password, so checks that need it were skipped');
  let assets = {};
  try { assets = JSON.parse(readFile(opt.assets) || '{}'); } catch (e) { /* plain report without the shared stylesheet */ }
  if (opt.html) writePrivate(opt.html, renderHtml(results, assets, reasons));
  if (opt.json) writePrivate(opt.json, JSON.stringify({version: VERSION, generated: new Date().toISOString(), facts: facts(),
    incomplete: reasons, results}, null, 1));
  const lines = results.filter(r => r.status !== 'PASS')
    .map(r => `${r.status.padEnd(5)} ${r.severity.padEnd(8)} ${r.id.padEnd(7)} ${r.title}`);
  lines.push(`${results.filter(r => r.status === 'PASS').length} of ${results.length} checks passed on ${facts()[0][1]}`);
  if (reasons.length) lines.push(`INCOMPLETE AUDIT: ${reasons.join('; ')}`);
  // osascript prints run()'s return value and exits 0; an error thrown above exits non-zero. The launcher reads
  // the INCOMPLETE AUDIT line.
  return lines.join('\n');
}
