; Phalanx installer (Inno Setup 6.7 or later).
;
; Build:  cargo build --release
;         "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\phalanx.iss
; Output: target\installer\Phalanx-Setup-<version>.exe
;
; The version is read from the built phalanx.exe (Cargo.toml's version,
; embedded by build.rs); pass /DAppVersion=x.y.z to override it.
;
; Installs for the whole PC (administrator rights, asked once): protection
; runs in the Phalanx service as LocalSystem, which setup installs and
; starts, and the app starts in the tray at every user's sign-in to show
; its notifications. A per-user 0.4.x install is upgraded: its user's data
; is moved into the service's folder (%ProgramData%\Phalanx) and the old
; copy is removed, keeping its data folder. On uninstall, Windows' DNS
; settings are put back if Phalanx's DNS filter was set up, the service is
; removed, and the data folder is kept unless the user chooses to delete it.

#define AppName "Phalanx"
#define AppGuid "6B0E3B5A-7C2D-4E57-9F1A-5D7C1B3E2A90"
#define AppExe "phalanx.exe"
#define CliExe "phalanx-cli.exe"
#define ServiceExe "phalanx-service.exe"
; The Windows service's name (src/service/mod.rs).
#define ServiceName "Phalanx"
#define AppUrl "https://github.com/Sajidameen2323/phalanx"
; The app's single-instance mutex (src/gui/desktop.rs).
#define AppMutex "Local\ThreatScanner.SingleInstance"
#define Release "..\target\release"
#ifndef AppVersion
  #define AppVersion GetStringFileInfo(Release + "\" + AppExe, "ProductVersion")
#endif
#if AppVersion == ""
  #error phalanx.exe has no version information: build it where windres is available (see build.rs), or pass /DAppVersion=x.y.z
#endif

[Setup]
AppId={{{#AppGuid}}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
AppCopyright=Copyright (c) 2026 Sajid Ameen
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
VersionInfoDescription={#AppName} Setup
MinVersion=10.0
DefaultDirName={autopf}\{#AppName}
; Always Program Files: a 0.4.x per-user folder is not reused.
UsePreviousAppDir=no
DisableDirPage=yes
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\target\installer
OutputBaseFilename=Phalanx-Setup-{#AppVersion}
SetupIconFile=..\assets\phalanx.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/ultra64
SolidCompression=yes
; Light or dark, following Windows, like the app.
WizardStyle=modern dynamic
; Phalanx itself is asked to quit in [Code]; this closes what else holds its
; files, such as the browser connector a browser keeps running.
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Open {#AppName} in the tray when anyone signs in, to show its notifications"; GroupDescription: "Protection:"
Name: "browsers"; Description: "Connect my browsers for web protection (Browser Guard)"; GroupDescription: "Protection:"

[Files]
Source: "{#Release}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Release}\{#CliExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Release}\{#ServiceExe}"; DestDir: "{app}"; Flags: ignoreversion
; A short guide for users; the full README is for developers.
Source: "README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
; Same name and notification identity as the shortcut the app registers
; itself, so toasts keep popping up as Phalanx.
Name: "{commonprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; AppUserModelID: "Phalanx.Desktop"
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#AppName}"; ValueData: """{app}\{#AppExe}"" --background"; Tasks: autostart; Flags: uninsdeletevalue
; Removed on uninstall even when the task was not chosen this time.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "{#AppName}"; Flags: dontcreatekey uninsdeletevalue

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; Unregister the browser connector (HKCU native-messaging keys) before the
; program files go.
Filename: "{app}\{#CliExe}"; Parameters: "web disconnect"; RunOnceId: "DisconnectBrowsers"; Flags: runhidden

[UninstallDelete]
Type: files; Name: "{commonprograms}\{#AppName}.lnk"

[Code]
const
  DataFolder = '{commonappdata}\Phalanx';
  { A 0.4.x install: per user, with its data in the user's profile. }
  OldUninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{{#AppGuid}}_is1';
  OldDataFolder = '{localappdata}\threat-scanner';
  OldDnsBackup = '{localappdata}\threat-scanner\web\windows-dns-backup.json';

var
  OldUninstaller: String;

function PhalanxRunning(): Boolean;
begin
  Result := CheckForMutexes('{#AppMutex}');
end;

{ Asks a running Phalanx to quit through `Exe --quit`. A copy that cannot be
  asked (older versions, without --quit) is quit by the user from the tray.
  False if the user gives up. }
function QuitPhalanx(const Exe: String; Silent: Boolean): Boolean;
var
  Code: Integer;
begin
  Result := True;
  while PhalanxRunning() do
  begin
    if (Exe <> '') and FileExists(Exe) then
      Exec(Exe, '--quit', '', SW_HIDE, ewWaitUntilTerminated, Code);
    if not PhalanxRunning() then
      Break;
    if Silent then
    begin
      Result := False;
      Exit;
    end;
    if MsgBox('Phalanx is still running.' + #13#10#13#10 +
              'Right-click its icon in the taskbar''s notification area and choose Quit, then choose Retry.',
              mbError, MB_RETRYCANCEL) = IDCANCEL then
    begin
      Result := False;
      Exit;
    end;
  end;
end;

function InitializeSetup(): Boolean;
var
  Location: String;
begin
  Result := True;
  { A 0.4.x per-user install, to upgrade from. }
  OldUninstaller := '';
  if RegQueryStringValue(HKCU, OldUninstallKey, 'UninstallString', OldUninstaller) then
    OldUninstaller := RemoveQuotes(OldUninstaller);
  if not PhalanxRunning() then
    Exit;
  if not WizardSilent() then
    if MsgBox('Phalanx is open. Setup will close it while it installs, then start it again.',
              mbInformation, MB_OKCANCEL) = IDCANCEL then
    begin
      Result := False;
      Exit;
    end;
  Location := '';
  if RegQueryStringValue(HKLM, OldUninstallKey, 'InstallLocation', Location) or
     RegQueryStringValue(HKCU, OldUninstallKey, 'InstallLocation', Location) then
    Location := AddBackslash(Location) + '{#AppExe}';
  { Not installed by setup (or moved): ask with the copy in this setup. }
  if not FileExists(Location) then
  begin
    ExtractTemporaryFile('{#AppExe}');
    Location := ExpandConstant('{tmp}\{#AppExe}');
  end;
  Result := QuitPhalanx(Location, WizardSilent());
end;

{ The service holds phalanx-service.exe open: stop it before the files are
  replaced. Not installed is fine. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  Exec(ExpandConstant('{sys}\net.exe'), 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

{ Runs the CLI (hidden) and returns its exit code, or -1 if it did not run. }
function Cli(const Params: String): Integer;
begin
  if not Exec(ExpandConstant('{app}\{#CliExe}'), Params, '', SW_HIDE, ewWaitUntilTerminated, Result) then
    Result := -1;
end;

{ Brings a 0.4.x user's data into the service's folder, then removes the old
  copy. Its DNS backup is set aside while its uninstaller runs, so Windows'
  DNS keeps pointing at the filter (the service now answers there, and its
  folder has the backup). }
procedure UpgradeFromPerUser();
var
  Tries, Code: Integer;
  Backup, Aside: String;
begin
  if (OldUninstaller = '') or not FileExists(OldUninstaller) then
    Exit;
  WizardForm.StatusLabel.Caption := 'Bringing over your history, quarantine and settings…';
  { The service needs a moment before it answers. }
  for Tries := 1 to 30 do
  begin
    Code := Cli('service migrate');
    if Code = 0 then
      Break;
    Sleep(1000);
  end;
  if Code <> 0 then
    Log('Migration from the per-user install did not finish (exit code ' + IntToStr(Code) + ').');
  Backup := ExpandConstant(OldDnsBackup);
  Aside := Backup + '.moved-to-service';
  if FileExists(Backup) and not RenameFile(Backup, Aside) then
    Aside := '';
  WizardForm.StatusLabel.Caption := 'Removing the previous version…';
  { A browser keeps the old copy's connector running, which would hold its
    folder; Browser Guard starts the new one at its next lookup. }
  Exec(ExpandConstant('{sys}	askkill.exe'), '/F /IM {#CliExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(OldUninstaller, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '', SW_HIDE, ewWaitUntilTerminated, Code);
  { The uninstaller hands over to a copy of itself and returns at once: wait
    for that copy to finish. }
  for Tries := 1 to 120 do
  begin
    if not RegKeyExists(HKCU, OldUninstallKey) then
      Break;
    Sleep(500);
  end;
  if (Aside <> '') and FileExists(Aside) then
    RenameFile(Aside, Backup);
  { The per-user entry still existed when setup registered itself, so Setup
    named this one "Phalanx (All users)": it is the only one now. }
  RegWriteStringValue(HKLM, OldUninstallKey, 'DisplayName', '{#AppName}');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;
  WizardForm.StatusLabel.Caption := 'Starting the protection service…';
  Code := Cli('service install');
  if Code <> 0 then
  begin
    Log('phalanx-cli service install failed (exit code ' + IntToStr(Code) + ').');
    if not WizardSilent() then
      MsgBox('The Phalanx protection service could not be installed (code ' + IntToStr(Code) + '), so this PC is not protected yet.' + #13#10#13#10 +
             'Run setup again, or run "phalanx-cli service install" from a terminal opened as administrator.', mbError, MB_OK);
    Exit;
  end;
  UpgradeFromPerUser();
  { The browser connector is registered per user, for the one installing;
    after the upgrade, whose uninstaller disconnects the old one. }
  if WizardIsTaskSelected('browsers') then
  begin
    WizardForm.StatusLabel.Caption := 'Connecting browsers…';
    if not ExecAsOriginalUser(ExpandConstant('{app}\{#CliExe}'), 'web connect', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
      Log('Connecting browsers failed (exit code ' + IntToStr(Code) + ').');
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := QuitPhalanx(ExpandConstant('{app}\{#AppExe}'), UninstallSilent());
end;

{ If Windows' DNS points at Phalanx's filter, removing Phalanx could leave
  websites unreachable: put back the settings saved when it was set up. }
procedure RestoreDns();
begin
  { Only while Windows still uses the filter: an older backup is stale (the
    check discards it). }
  if Cli('web restore-dns --check') <> 0 then
    Exit;
  if not UninstallSilent() then
    if MsgBox('Windows is set to use Phalanx''s DNS filter. Put your previous DNS settings back now?' + #13#10#13#10 +
              'If you skip this, websites may stop loading once Phalanx is removed.',
              mbConfirmation, MB_YESNO) = IDNO then
      Exit;
  if Cli('web restore-dns') <> 0 then
    if not UninstallSilent() then
      MsgBox('Your DNS settings were not restored. If websites stop loading, open Settings > Network & internet, ' +
             'choose your connection, and set DNS server assignment back to Automatic.', mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Dir, OldDir, Folders: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    RestoreDns();
    if Cli('service uninstall') <> 0 then
      Log('The protection service could not be removed.');
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    Dir := ExpandConstant(DataFolder);
    OldDir := ExpandConstant(OldDataFolder);
    Folders := '';
    if DirExists(Dir) then
      Folders := Dir;
    if DirExists(OldDir) then
      Folders := Folders + #13#10 + OldDir;
    if (Folders <> '') and not UninstallSilent() then
      if MsgBox('Also delete Phalanx''s data?' + #13#10#13#10 + Trim(Folders) + #13#10#13#10 +
                'It holds your scan history, downloaded signatures, settings and QUARANTINED FILES. ' +
                'Keep it if you might reinstall or need to restore a quarantined file.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(Dir, True, True, True);
        DelTree(OldDir, True, True, True);
      end;
  end;
end;
