; Phalanx installer (Inno Setup 6.7 or later).
;
; Build:  cargo build --release
;         "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\phalanx.iss
; Output: target\installer\Phalanx-Setup-<version>.exe
;
; The version is read from the built phalanx.exe (Cargo.toml's version,
; embedded by build.rs); pass /DAppVersion=x.y.z to override it.
;
; Installs per user (no administrator rights), like everything Phalanx
; registers: the Start-menu shortcut, start-with-Windows entry and browser
; connector all live under the current user. A running Phalanx is asked to
; quit first (`phalanx.exe --quit`). On uninstall, Windows' DNS settings are
; put back if Phalanx's DNS filter was set up, and the data folder
; (%LOCALAPPDATA%\threat-scanner: history, quarantine, signatures) is kept
; unless the user chooses to delete it.

#define AppName "Phalanx"
#define AppGuid "6B0E3B5A-7C2D-4E57-9F1A-5D7C1B3E2A90"
#define AppExe "phalanx.exe"
#define CliExe "phalanx-cli.exe"
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
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
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
Name: "autostart"; Description: "Start {#AppName} in the tray when I sign in (real-time protection keeps running)"; GroupDescription: "Protection:"; Flags: unchecked
Name: "browsers"; Description: "Connect my browsers for web protection (Browser Guard)"; GroupDescription: "Protection:"

[InstallDelete]
; Earlier versions installed the developer README.
Type: files; Name: "{app}\README.md"

[Files]
Source: "{#Release}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Release}\{#CliExe}"; DestDir: "{app}"; Flags: ignoreversion
; A short guide for users; the full README is for developers.
Source: "README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
; Same name and notification identity as the shortcut the app registers
; itself, so toasts keep popping up as Phalanx.
Name: "{userprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; AppUserModelID: "Phalanx.Desktop"
Name: "{userdesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#AppName}"; ValueData: """{app}\{#AppExe}"" --background"; Tasks: autostart; Flags: uninsdeletevalue
; Removed on uninstall even when the app (not setup) created them.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "{#AppName}"; Flags: dontcreatekey uninsdeletevalue
Root: HKCU; Subkey: "Software\Classes\AppUserModelId\Phalanx.Desktop"; Flags: dontcreatekey uninsdeletekey

[Run]
Filename: "{app}\{#CliExe}"; Parameters: "web connect"; StatusMsg: "Connecting browsers…"; Tasks: browsers; Flags: runhidden
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Unregister the browser connector (HKCU native-messaging keys) before the
; program files go.
Filename: "{app}\{#CliExe}"; Parameters: "web disconnect"; RunOnceId: "DisconnectBrowsers"; Flags: runhidden

[UninstallDelete]
Type: files; Name: "{userprograms}\{#AppName}.lnk"

[Code]
const
  DataFolder = '{localappdata}\threat-scanner';
  DnsBackup = '{localappdata}\threat-scanner\web\windows-dns-backup.json';
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{{#AppGuid}}_is1';

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
  if not PhalanxRunning() then
    Exit;
  if not WizardSilent() then
    if MsgBox('Phalanx is running. Setup will close it while it installs, then start it again.' + #13#10#13#10 +
              'Real-time protection is off until then.',
              mbInformation, MB_OKCANCEL) = IDCANCEL then
    begin
      Result := False;
      Exit;
    end;
  Location := '';
  if RegQueryStringValue(HKCU, UninstallKey, 'InstallLocation', Location) then
    Location := AddBackslash(Location) + '{#AppExe}';
  { Not installed by setup (or moved): ask with the copy in this setup. }
  if not FileExists(Location) then
  begin
    ExtractTemporaryFile('{#AppExe}');
    Location := ExpandConstant('{tmp}\{#AppExe}');
  end;
  Result := QuitPhalanx(Location, WizardSilent());
end;

function InitializeUninstall(): Boolean;
begin
  Result := QuitPhalanx(ExpandConstant('{app}\{#AppExe}'), UninstallSilent());
end;

{ If Windows' DNS points at Phalanx's filter, removing Phalanx could leave
  websites unreachable: put back the settings saved when it was set up. }
procedure RestoreDns();
var
  Code: Integer;
begin
  if not FileExists(ExpandConstant(DnsBackup)) then
    Exit;
  if not UninstallSilent() then
    if MsgBox('Windows is set to use Phalanx''s DNS filter. Put your previous DNS settings back now?' + #13#10#13#10 +
              'Windows will ask for permission. If you skip this, websites may stop loading once Phalanx is removed.',
              mbConfirmation, MB_YESNO) = IDNO then
      Exit;
  if not Exec(ExpandConstant('{app}\{#CliExe}'), 'web restore-dns', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    if not UninstallSilent() then
      MsgBox('Your DNS settings were not restored. If websites stop loading, open Settings > Network & internet, ' +
             'choose your connection, and set DNS server assignment back to Automatic.', mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Dir: String;
begin
  if CurUninstallStep = usUninstall then
    RestoreDns();
  if CurUninstallStep = usPostUninstall then
  begin
    Dir := ExpandConstant(DataFolder);
    if DirExists(Dir) and not UninstallSilent() then
      if MsgBox('Also delete Phalanx''s data folder?' + #13#10#13#10 + Dir + #13#10#13#10 +
                'It holds your scan history, downloaded signatures, settings and QUARANTINED FILES. ' +
                'Keep it if you might reinstall or need to restore a quarantined file.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(Dir, True, True, True);
  end;
end;
