# Rule sources: primary-source claim check

This file records the primary sources behind the explanatory text of the audit rules. Each section quotes an earlier draft of a rule's text. It then gives a verdict against the sources and suggests new wording. The audit now uses that wording in substance.

All quotes are verbatim. They show each page as it read when the rules were written. Pages change, so check the live page before you rely on a quote.

The Apple developer pages came from their JSON form (`https://developer.apple.com/tutorials/data/documentation/<path>.json`). The URLs below are the human-readable forms. The Jamf pages came from the Jamf Pro Documentation 11.32.0 map on learn.jamf.com (the "current" docs).

Verdict key:

- **SUPPORTED:** the primary source says it.
- **PARTLY:** part of the claim is right. The section names the part that is wrong or unsupported.
- **CONTRADICTED:** the primary source says the opposite.
- **NOT FOUND:** the search found no primary source.

---

## 1. ACC-07: Automatic login

**Earlier draft:** "Automatic login: The Mac logs a user in at boot without a password, which defeats FileVault pre-boot auth after unlock."

**Verdict: CONTRADICTED.** macOS does not allow automatic login while FileVault is on, so automatic login cannot "defeat FileVault pre-boot auth". If automatic login is on, FileVault is off. The real risk is that anyone who restarts the Mac reaches the desktop. A different setting, `DisableFDEAutoLogin`, controls whether the FileVault unlock at boot also completes the user's login. That setting is not the "Automatic login" setting.

Quotes:

Source: https://support.apple.com/guide/mac-help/mchlp1158/mac (Mac User Guide, macOS 27)
> Important: Automatic login allows anyone to access your Mac simply by restarting it. If automatic login is enabled, make sure your Mac doesn’t automatically log in an administrator. When FileVault is turned on, automatic login is disabled.

Source: https://support.apple.com/en-us/102316 (published May 19, 2026)
> If the automatic login setting is dimmed or doesn't show the account name, then manual login is required. For example, manual login is required in these circumstances:

> FileVault is turned on.

Source: https://developer.apple.com/documentation/devicemanagement/loginwindow (key `DisableFDEAutoLogin`, default false)
> If true, the system disables the automatic login option when using FileVault.

**Suggested wording:** "Automatic login: anyone who restarts this Mac gets the chosen account's desktop without a password. macOS turns automatic login off when FileVault is on, so this setting also means FileVault is off on this Mac."

---

## 2. OS-03: Which macOS versions Apple patches

**Earlier draft:** "Apple patches only the current macOS and the two before it."

**Verdict: PARTLY.** Apple does not publish an "N-2" support policy. Apple's only published statement says that previous versions do not get all known security fixes. That statement is stronger than the claim: even the two previous versions get only some of the fixes. "Current plus two before it" describes what Apple's release list shows in practice, not a stated policy.

Quotes:

Source: https://support.apple.com/guide/deployment/depc4c80847a/web (Apple Platform Deployment, "About software updates")
> Note: Because of dependency on architecture and system changes to any current version of Apple operating systems (for example, iOS 27, macOS 27, and so on), not all known security issues are addressed in previous versions (for example, iOS 26, macOS 26, and so on).

Source: https://support.apple.com/en-us/100100 (Apple security releases). This shows the practice, not a policy. On 14 Sep 2026 Apple released "macOS Golden Gate 27", "macOS Tahoe 26.7", and "macOS Sequoia 15.8". On 28 Sep 2026 it released "macOS Tahoe 26.7.1" and "macOS Sequoia 15.8.1". The most recent Sonoma entry is "macOS Sonoma 14.8.9", dated 06 Aug 2026.

**Suggested wording:** "Apple states that versions before the current macOS do not receive all known security fixes. In practice, Apple shipped security updates only for the current release and the two before it. Older releases get no fixes at all."

---

## 3. FV-04: FileVault recovery key escrow

**Earlier draft:** "Jamf only receives a recovery key when an escrow payload (com.apple.security.FDERecoveryKeyEscrow) is installed. A key made without one is never stored."

**Verdict: CONTRADICTED.** Jamf documents a second escrow path. When a Disk Encryption policy enables FileVault, the Jamf binary escrows the personal recovery key (PRK) immediately, with no escrow payload. Jamf's current docs (11.32.0) still document policy-based enablement and do not mark it as deprecated.

"Never stored" is also too absolute. Jamf can issue and escrow a new PRK by policy. On macOS 26 or later, an escrow profile installed while a bootstrap token is present rotates the PRK and escrows the new one.

Note: one sentence on Jamf's "Preparation" page contradicts the sentences that follow it on the same page (quoted below). The other Jamf pages agree with the policy path.

Quotes:

Source: https://learn.jamf.com/r/en-US/jamf-pro-documentation-current/FileVault (11.32.0)
> Deploy a disk encryption configuration with a policy

> With this method, the settings install at the time the policy is configured to be run, prompting the end user to turn on FileVault either at login or logout. If configured to use a PRK, the Jamf management framework on the computer escrows the key with Jamf Pro immediately upon running the policy. Jamf recommends this method for environments where advanced user experience customizations or custom triggers are required.

Source: https://learn.jamf.com/r/en-US/jamf-pro-documentation-current/Preparing_for_FileVault_Deployment (11.32.0, revised 2026-06-16)
> While FileVault can be enabled on a computer by either a policy or a configuration profile, personal recovery keys are only escrowed by Jamf Pro via a configuration profile.

> When enabled with a Disk Encryption policy, the PRK is immediately escrowed by the Jamf binary when FileVault is enabled on the computer.

> For computers with macOS 26 or later, if a FileVault recovery key escrow profile is installed or updated while a bootstrap token is present, macOS will automatically rotate the PRK. The new PRK is then escrowed to Jamf Pro during the computer's next inventory update.

Source: https://learn.jamf.com/r/en-US/jamf-pro-documentation-current/Issuing_a_new_FileVault_Recovery_Key (11.32.0)
> Individual —A new personal (also known as "individual") recovery key is generated on each computer and then submitted to Jamf Pro for storage.

> A FileVault enabled user account with a secure token

Source: https://developer.apple.com/documentation/devicemanagement/fderecoverykeyescrow (the macOS-native path)
> If FileVault is enabled after the system installs this payload, the system encrypts the FileVault PRK with the specified certificate, wrapped with a CMS envelope and stored at /var/db/FileVaultPRK.dat. The SecurityInfo command makes this encrypted data available to the MDM server.

**Suggested wording:** "Jamf has no recovery key for this Mac. Jamf receives a key in three ways. The first is an escrow payload that is present when FileVault is enabled. The second is a Jamf Disk Encryption policy that enables FileVault. The third is a new key that a policy issues or that macOS 26 or later rotates. Issue a new key so that this Mac can be recovered."

---

## 4. SEC-04: Screen saver password

**Earlier draft:** "Without askForPassword in a profile, the screen saver only blanks the display, and users can turn the lock prompt off."

**Verdict: PARTLY.** No source supports the first half. Apple does not document the out-of-box default for "Require password after screen saver begins or display is turned off". Without a profile, the user's Lock Screen setting decides the behavior, and that setting may already require a password. The sources support the second half: users can change the setting. Apple's documented `askForPassword` default of false is the payload key's default, not the macOS default.

Quotes:

Source: https://developer.apple.com/documentation/devicemanagement/screensaver
> askForPassword: If true, the device prompts the user for a password when the screen saver is unlocked or stopped. When you use this prompt, you must also provide askForPasswordDelay.

> askForPasswordDelay: The number of seconds to delay before the device requires a password to unlock or stop the screen saver (the grace period). A value of 2147483647 (hexadecimal equivalent of 0x7FFFFFFF) disables this requirement, and a value of 0 immediately requires the password. To use this option, you must set askForPassword to true.

(Each quote after a key name is verbatim. Apple shows the key name as the heading.)

Source: https://support.apple.com/guide/mac-help/mh11784/mac
> Require password after screen saver begins or display is turned off

> Lock your Mac when it’s left in an idle state. When the Mac wakes, a user login password must be entered before the Mac can be used. You can select the amount of time after the screen saver or sleep begins before a password is required.

Source: https://support.apple.com/en-us/102316
> You might still need to enter your password when your Mac wakes from sleep or stops using the screen saver. You can change this behavior as follows:

> macOS Ventura 13 or later: Choose System Settings from the Apple menu [Apple logo], then click Lock Screen in the sidebar. Configure the "Require password after screen saver begins or display is turned off" setting as desired.

macOS default value: NOT FOUND. The pages mh11784, mchlp2270, mchl4b68853d and 102316 do not state the default.

**Suggested wording:** "No profile enforces a screen-saver password (askForPassword). Whether the screen locks depends on each user's Lock Screen setting, which users can change or delay."

---

## 5. SEC-05: Default local password rules

**Earlier draft:** "Without a policy, accounts may keep 4-character passwords."

**Verdict: NOT FOUND (no Apple documentation).** The search found no Apple page that states the default password rules for macOS local accounts. Apple's "four-digit PIN" default applies to iPhone and iPad, not Mac:

Source: https://support.apple.com/guide/deployment/depeadc2af0b/web
> By default, the user’s passcode can be defined as a six-digit personal identification number (PIN) on Face ID and Touch ID–capable devices or a four-digit PIN on all other devices. On devices with iOS and iPadOS, you can choose from an extensive set of passcode policies to meet your security needs.

Local observation (not a primary source): on a test Mac with macOS 27.0, the read-only command `pwpolicy -getaccountpolicies` shows one global content policy. The policy has these values:

- Identifier: `com.apple.defaultpasswordpolicy.fde`
- Rule: `policyAttributePassword matches '.{4,}+'`
- Apple's localized description: "Enter a password that is four characters or more."

This observation supports the claim. But an observation of one Mac is not Apple documentation.

Related fact for remediation: Apple marks the Passcode payload (`com.apple.mobiledevice.passwordpolicy`) as deprecated in macOS 27 (`deprecatedAt: 27.0`, https://developer.apple.com/documentation/devicemanagement/passcode). Apple's replacement is the declarative Passcode configuration (https://support.apple.com/guide/deployment/depf72b010a8/web).

**Suggested wording:** "This Mac has no deployed password policy, so only the built-in macOS local rule applies. On a macOS 27 test Mac, that rule (`com.apple.defaultpasswordpolicy.fde`) requires only 4 characters."

---

## 6. NET-01: Firewall and sharing services

**Earlier draft:** "With SSH and Screen Sharing on, the firewall is the only local filter on the organisation's network and public Wi-Fi."

**Verdict: CONTRADICTED.** The macOS application firewall does not filter the services that a user enables in Sharing settings. Apple says those services connect through the firewall. The firewall blocks them only when "Block all incoming connections" is on. With Remote Login and Screen Sharing on, nothing in the firewall restricts who can reach them.

Quotes:

Source: https://support.apple.com/guide/mac-help/mh34041/mac
> A firewall can protect your Mac from unwanted contact initiated by other computers when you’re connected to the internet or a network. However, your Mac can still allow access through the firewall for some services and apps. For example:

> If you turn on a sharing service, such as file sharing, macOS opens a specific port for the service to communicate through.

Source: https://support.apple.com/guide/mac-help/mh11783/mac
> Certain shared services can connect through the firewall when they are turned on in Sharing settings. For additional security, you can prevent connections to these incoming services by turning off the service in Sharing settings.

> Block all incoming connections

> Prevent incoming connections to nonessential services and apps.

> Allow built-in apps and services that are signed by a valid certificate authority to be automatically added to the list of allowed apps, without your authorization.

Source: https://developer.apple.com/documentation/devicemanagement/firewall (key `AllowSigned`, default true)
> If true, the system allows built-in software to receive incoming connections.

**Suggested wording:** "Remote Login (SSH) and Screen Sharing are on. The macOS firewall does not block services that Sharing settings enable. Any network that the Mac joins can reach them, including the organisation's network and public Wi-Fi. Disable them, or limit 'Allow access for' to named admins."

---

## 7. DIR-01: Active Directory binding and mobile accounts

**Earlier draft:** "AD binding keeps mobile accounts and machine passwords on the Mac and breaks logins away from the organisation's network."

**Verdict: PARTLY.** Apple supports the first half. A bound Mac keeps a computer-account password in the System keychain, and mobile accounts cache the user's password. Apple contradicts "breaks logins away from the organisation's network" for mobile accounts. Apple designs mobile accounts for login while the Mac is disconnected.

The real off-network problems are different. Password changes made off the network no longer match the directory and the login keychain. Accounts that are not mobile accounts (Apple's payload default for `ADCreateMobileAccountAtLogin` is false) have no cached credentials.

Quotes:

Source: https://support.apple.com/guide/directory-utility/ior6d33c187e/mac
> Mobile user accounts cache the user’s information, including their password, so the user can log in to the Mac when it’s disconnected from the organization’s network. Changes made in the directory service won’t be updated on the Mac until it reconnects to the organization’s network.

> If the network account password is changed while a Mac isn’t actively connected to the directory service, it’s only changed in the locally cached credential store. When the user reconnects to the directory service and logs in, the remote directory service is updated and the Mac is unable to unlock the login keychain.

Source: https://support.apple.com/guide/directory-utility/diru11f4f748/mac
> When a Mac system is bound to Active Directory, it sets a computer account password that’s stored in the system keychain and is automatically changed by the Mac. The default password interval is every 14 days, but you can use the directory payload or dsconfigad command–line tool to set any interval that your policy requires.

Source: https://developer.apple.com/documentation/devicemanagement/directoryservice (key `ADCreateMobileAccountAtLogin`, default false)
> If true, the system creates a mobile account at login.

**Suggested wording:** "This Mac is bound to AD. It keeps a computer-account password in the System keychain and caches mobile-account passwords. Mobile accounts still allow login away from the organisation's network. But password changes made off the network no longer match AD and the login keychain. Accounts that are not mobile accounts allow no login off the network."

---

## 8. OS-01: Fixes for exploited CVEs

**Earlier draft:** "Apple shipped fixes for CVEs it reports as exploited in the wild."

**Verdict: PARTLY.** Apple does not say "exploited in the wild." Apple says it "is aware of a report that this issue may have been exploited". The report often concerns a different platform. In the current macOS example below, the report is about iOS before iOS 27, not macOS.

Quotes (current example, macOS Tahoe 26.7.1, released September 28, 2026):

Source: https://support.apple.com/en-us/149228
> Impact: Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

> CVE-2026-86950: Meta Product Security

Earlier example, macOS Tahoe 26.3:

Source: https://support.apple.com/en-us/126348
> Impact: An attacker with memory write capability may be able to execute arbitrary code. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report.

**Suggested wording:** "This Mac is missing fixes for CVEs that Apple says it 'is aware of a report' may have been exploited in targeted attacks. The wording is Apple's. The report may concern iOS."

---

## 9. PRF-01: Conflicting values across profiles

**Earlier draft:** "Apple documents that conflicting values for one key across profiles give unexpected behavior; whichever installs last may win."

**Verdict: PARTLY.** Apple documents "unexpected behavior" only for the Restrictions payload (managing the same restriction in different payloads). Apple's current general guidance says the result depends on the configuration. Several payloads follow documented merge rules:

- Firewall uses the most restrictive union.
- PPPC uses the more restrictive settings.
- System Extensions combine.

The search found no Apple statement that "whichever installs last wins". An older Apple sentence ("the resulting behavior is undefined") no longer appears on the current page dep9a318a393.

Quotes:

Source: https://developer.apple.com/documentation/devicemanagement/restrictions
> The system allows multiple Restrictions payloads. However, don’t attempt to manage the same restriction in different payloads. Doing so results in unexpected behavior.

Source: https://support.apple.com/guide/deployment/dep9a318a393/web (published September 17, 2026)
> If you have multiple configurations of the same type, the resulting behavior depends on the specific configuration. For more information whether duplicates are supported and the merging behavior, see the Declarations list on the Apple Developer documentation website.

Source: https://developer.apple.com/documentation/devicemanagement/firewall
> If more than one profile contains this payload, the system uses the most restrictive union of settings.

Source: https://support.apple.com/guide/deployment/dep38df53c2a/web (PPPC)
> If there is more than one payload of this type, the operating system uses the more restrictive settings.

**Suggested wording:** "Two profiles set different values for the same key. For Restrictions, Apple says this 'results in unexpected behavior'. Other payloads follow their own merge rules, so the effective value is not predictable from either profile alone."

---

## 10. ACC-08: Platform SSO "Admin" authorization mode

**Earlier draft:** "With authorization mode Admin, every user who signs in with Platform SSO is added to the local admin group."

**Verdict: SUPPORTED** for `UserAuthorizationMode`, which applies "each time the user authenticates". If the audit reads `NewUserAuthorizationMode` instead, "Admin" applies only to accounts created at login. Name the key that the rule checks. Separately, if Platform SSO creates the only account on the Mac, that account becomes an administrator regardless of mode.

Quotes:

Source: https://developer.apple.com/documentation/devicemanagement/extensiblesinglesignon/platformsso-data.dictionary
> UserAuthorizationMode: The permission to apply to an account each time the user authenticates. Allowed values:

> Admin: The system adds the account to the local administrators group.

> NewUserAuthorizationMode: The permission to apply to newly created accounts at login. Allowed values:

> Admin: The system adds the account to the local administrators group.

(Each quote after a key name is verbatim. Apple shows the key name as the heading.)

Source: https://support.apple.com/guide/deployment/dep7bbb05313/web
> Platform SSO offers granular rights management to provide users with the appropriate level of privileges they need on their Mac. To do so, Platform SSO can apply the following privileges to an account each time the user authenticates:

> Administrator: Adds the account to the local administrator group.

> If the user account macOS creates is the only account on the Mac, that account becomes a local administrator account.

**Suggested wording:** "UserAuthorizationMode is Admin. Each time a user authenticates with Platform SSO, macOS adds that account to the local administrators group."

---

## 11. MDM-03: Bootstrap token

**Earlier draft:** "Without a bootstrap token, MDM cannot grant secure tokens, install some updates, or approve kernel extensions on Apple silicon."

**Verdict: PARTLY.** Apple's pages support the update and kernel-extension parts. On Apple silicon, the bootstrap token lets MDM authorize software updates and kernel-extension enablement without a user authenticating.

The secure-token part names the wrong actor. macOS, not MDM, grants secure tokens. The bootstrap token lets macOS grant them to new accounts (mobile accounts, Platform SSO) without an admin's authentication. Without a bootstrap token, macOS can still grant secure tokens, but an existing secure-token admin must authenticate.

Quotes:

Source: https://support.apple.com/guide/deployment/dep24dbdcf9e/web (published September 17, 2026)
> A bootstrap token enables macOS to grant a secure token to accounts including accounts created on-demand using Platform Single Sign-on and mobile accounts without needing to authenticate separately with an already secure token-enabled administrator account.

> On a Mac with Apple silicon, a bootstrap token can also be used to:

> Authorize the installation of software updates.

> Silently authorize an Erase All Content and Settings device management command (macOS 12.0.1 or later).

> Create new users when they first log in with Platform SSO (macOS 13 or later).

Source: https://support.apple.com/guide/deployment/depa5fb8376f/web
> Device management services can set the secure boot policy automatically to Reduce Security using a bootstrap token when a profile to allow a kernel extension is applied.

Source: https://developer.apple.com/documentation/devicemanagement/securityinforesponse/securityinfo-data.dictionary
> BootstrapTokenRequiredForKernelExtensionApproval: If true, the device can accept a Bootstrap Token from the MDM server instead of prompting for user authentication prior to enabling kernel extensions.

> BootstrapTokenRequiredForSoftwareUpdate: If true, the device can accept a Bootstrap Token from the MDM server instead of prompting for user authentication prior to installation.

**Suggested wording:** "No bootstrap token is escrowed. New mobile and Platform SSO accounts cannot get a secure token unless an admin authenticates. On Apple silicon, MDM also cannot authorize software updates, Erase All Content and Settings, or kernel-extension enablement unless a user authenticates."

---

## 12. NET-07: 802.1X server trust and PEAP/MS-CHAPv2

**Earlier draft:** (a) "Without TLSTrustedServerNames or a certificate anchor, macOS asks the user whether to trust whatever certificate the network presents." (b) "With PEAP/MS-CHAPv2, captured MS-CHAPv2 traffic can be cracked to recover the password."

**Verdict: PARTLY.** Part (a) is SUPPORTED. `TLSAllowTrustExceptions` defaults to true. The trust dialog appears when the system does not already trust the server certificate.

Part (b) cites the wrong scope. Microsoft Advisory 2743314 is about unencapsulated MS-CHAPv2 (PPTP) and names PEAP as the mitigation. In PEAP, a rogue server receives the inner MS-CHAPv2 exchange only if the client completes TLS with that server. For example, this happens after a user accepts the trust dialog from part (a). Microsoft does not state that last step in 2743314. This file infers that link from the two sources.

Microsoft's Credential Guard page does put PEAP-MSCHAPv2 Wi-Fi in the same attack class as NTLMv1. That page recommends certificate-based EAP.

Quotes:

Source: https://developer.apple.com/documentation/devicemanagement/wifi/eapclientconfiguration-data.dictionary
> TLSTrustedServerNames: The list of accepted server certificate common names. If a server presents a certificate that isn’t in this list, the system doesn’t trust it. If you specify this property, the system disables dynamic trust (the certificate dialog) unless you also specify ‘TLSAllowTrustExceptions’ with the value ‘true’.

> PayloadCertificateAnchorUUID: An array of the UUID of each certificate payload in the same profile to trust for authentication. Use this key to prevent the device from asking the user whether to trust the listed certificates. The device disables dynamic trust (the certificate dialogue) if you specify this property without also enabling ‘TLSAllowTrustExceptions’.

> TLSAllowTrustExceptions (default true): If ‘true’, allows a dynamic trust decision by the user. The dynamic trust is the certificate dialogue that appears when the system doesn’t trust a certificate. If ‘false’, the authentication fails if the system doesn’t already trust the certificate. As of iOS 8, Apple no longer supports this key.

(Each quote after a key name is verbatim. Apple shows the key name as the heading and the default as an attribute. The "no longer supports" note applies to iOS. Apple lists the key as "Removed: iOS 8+ | iPadOS 8+" and as available on "macOS 10.7+".)

Source: https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2743314 (Microsoft Security Advisory 2743314, "Unencapsulated MS-CHAP v2 Authentication Could Allow Information Disclosure", published August 20, 2012)
> Only VPN solutions that rely on PPTP in combination with MS-CHAP v2 as the sole authentication method are vulnerable to this issue.

> An attacker has to be able to intercept the victim's MS-CHAP v2 handshake in order to exploit this weakness, by performing man-in-the-middle attacks or by intercepting open wireless traffic. An attacker who obtained the MS-CHAP v2 authentication traffic could then use the exploit code to decrypt a user's credentials.

> For information on how to secure your MS-CHAP v2/PPTP based tunnel with PEAP, see Microsoft Knowledge Base Article 2744850.

Source: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues
> If you're using WiFi and VPN endpoints that are based on MS-CHAPv2, they're subject to similar attacks as for NTLMv1.

> For WiFi and VPN connections, it's recommended to move from MSCHAPv2-based connections (such as PEAP-MSCHAPv2 and EAP-MSCHAPv2), to certificate-based authentication (such as PEAP-TLS or EAP-TLS).

**Suggested wording:** "(a) The Wi-Fi profile has no TLSTrustedServerNames or certificate anchor. When a network presents a certificate that the Mac does not already trust, macOS asks the user whether to trust it. (b) If a user accepts the certificate of a rogue network, that network receives the inner MS-CHAPv2 exchange. Microsoft says that this exchange can be decrypted to recover credentials (Advisory 2743314). Microsoft recommends a move to EAP-TLS."

---

## 13. MDM-02: User-approved MDM

**Earlier draft:** "Without user-approved MDM, kernel/system-extension approvals and privacy (PPPC) payloads do not apply."

**Verdict: SUPPORTED.** Apple marks the PPPC, Kernel Extension Policy, and System Extensions payloads as "Requires user-approved MDM" on macOS. Side note: Apple's PPPC page in Platform Deployment also requires supervision, but the developer reference lists supervision as "N/A". These two Apple sources disagree.

Quotes:

Source: https://developer.apple.com/documentation/devicemanagement/privacypreferencespolicycontrol (Profile availability table)
> Requires user-approved MDM | macOS

Source: https://developer.apple.com/documentation/devicemanagement/systempolicykernelextensions (Profile availability table)
> Requires user-approved MDM | macOS

Source: https://developer.apple.com/documentation/devicemanagement/systemextensions (Profile availability table)
> Requires user-approved MDM | macOS

Source: https://support.apple.com/guide/deployment/dep38df53c2a/web (PPPC)
> Supported approval method: Requires user approval.

> Supervision is required if you apply this payload using a device management service.

Source: https://support.apple.com/guide/deployment/dep88f99b98a/web (Kernel Extension Policy)
> Supported approval method: Requires user approval.

**Suggested wording:** "MDM enrollment is not user-approved, so macOS does not apply PPPC (privacy), Kernel Extension Policy, or System Extensions payloads from Jamf."
