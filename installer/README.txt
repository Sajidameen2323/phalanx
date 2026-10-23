PHALANX
Protection for your Windows PC

Phalanx finds and removes malware, watches for new threats as they arrive,
blocks dangerous websites, and checks that Windows' own protections are on.
It runs alongside Microsoft Defender and adds to it; keep Defender on.


GETTING STARTED

1. Open Phalanx from the Start menu.
2. Protection: turn on real-time protection. It watches your Downloads
   folder, checks every program as it starts, and scans disk images and USB
   drives when they appear.
3. Web protection: choose "Connect browsers", then add the Browser Guard
   extension to each browser once (the page shows how).
4. Dashboard: run a quick scan.

Closing the window keeps Phalanx running in the tray. To stop it, right-click
the tray icon and choose Quit.


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

History, quarantine, settings and downloaded signatures are kept in
%LOCALAPPDATA%\threat-scanner. Phalanx connects to the internet only to
download signature updates and browser version information, and to Google
Gemini if you turn on AI Inspect.


UNINSTALLING

Use Settings > Apps > Installed apps > Phalanx. If you set Windows to use
Phalanx's DNS filter, the uninstaller puts your previous DNS settings back
first (Windows asks for permission). You choose whether to keep your data
folder; keep it if you may need to restore a quarantined file.


MORE

phalanx-cli.exe in this folder does the same from the command line:
run "phalanx-cli --help".

Documentation and source: https://github.com/Sajidameen2323/phalanx
License: MIT, see LICENSE.txt.
