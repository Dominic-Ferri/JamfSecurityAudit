-- JamfSecurityAudit launcher: double-click the .app to run the bundled
-- jamf_host_audit.js in a fresh Terminal window.
--
-- It opens
-- Contents/Resources/run-jamfsecurityaudit.command via `open` (LaunchServices)
-- instead of `tell application "Terminal" ... do script`, so the app needs NO
-- Automation permission and never hits error -1743.
-- Raw event codes keep the same Standard Additions calls compilable when
-- osacompile cannot load their terminology (observed on macOS 27.2).
on run
	set cmdPath to POSIX path of («event earsffdr» me) & "Contents/Resources/run-jamfsecurityaudit.command"
	«event sysoexec» "/usr/bin/open -a Terminal " & quoted form of cmdPath
end run
