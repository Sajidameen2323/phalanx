PHALANX
Protection for your Windows PC

Phalanx finds and removes malware, watches for new threats as they arrive,
blocks dangerous websites, and checks that Windows' own protections are on.
It runs alongside Microsoft Defender and adds to it; keep Defender on.


GETTING STARTED

Protection starts as soon as setup finishes: it runs in the Phalanx
protection service, for the whole PC, whether or not the app is open and
even with nobody signed in. It watches everyone's Downloads folder, checks
every program as it starts, and scans disk images and USB drives when they
appear.

1. Open Phalanx from the Start menu.
2. Web protection: choose "Connect browsers" (setup did this for you if you
   left that option on), then add the Browser Guard extension to each
   browser once (the page shows how). Each Windows user does this once.
3. Dashboard: run a quick scan.

The app opens in the tray when you sign in, to show notifications. Closing
the window or quitting it does not stop protection.


CHANGES THAT NEED AN ADMINISTRATOR

Anything that weakens protection asks for Windows' administrator approval:
turning protection or one of its checks off, adding an exclusion or an
allowed site, restoring or deleting a quarantined file, and so on.
Strengthening it never asks. Malware running as you can ask for these
changes, but it cannot approve them. Phalanx cannot protect against malware
that already has administrator rights.


WHAT IT DOES

- Scans files, programs and archives (ZIP, 7z) for known malware, and
  spots programs padded to slip past size limits.
- Moves threats into a quarantine you can restore from.
- Blocks malware and phishing sites in your browsers, or for the whole PC
  with its DNS filter, and can block ads and trackers.
- Stealer check: looks for what password-stealing malware leaves behind.
- Checks Windows security and privacy settings, and can switch them on.
- Reports suspicious commands, such as ones a fake "verify you are human"
  page asks you to paste into the Run box. If a website ever asks you to
  press Win+R and paste something, don't.


YOUR DATA

History, quarantine, protection settings and downloaded signatures are
kept by the service in %ProgramData%\Phalanx, which only administrators can
change. Your own app settings (appearance, notifications, AI Inspect) are in
%LOCALAPPDATA%\threat-scanner. Phalanx connects to the internet only to
download signature updates and browser version information, and to Google
Gemini if you turn on AI Inspect.


UNINSTALLING

Use Settings > Apps > Installed apps > Phalanx. If you set Windows to use
Phalanx's DNS filter, the uninstaller puts your previous DNS settings back
first. The protection service is removed, and you choose whether to keep
the data; keep it if you may need to restore a quarantined file.


MORE

phalanx-cli.exe in this folder does the same from the command line:
run "phalanx-cli --help".

Documentation and source: https://github.com/Sajidameen2323/phalanx
License: MIT, see LICENSE.txt.
