; Phalanx installer (Inno Setup 6).
;
; Build:  cargo build --release
;         "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\phalanx.iss
; Output: target\installer\Phalanx-Setup-<version>.exe
;
; Installs per user (no administrator rights), like everything Phalanx
; registers: the Start-menu shortcut, start-with-Windows entry and browser
; connector all live under the current user. The data folder
; (%LOCALAPPDATA%\threat-scanner: history, quarantine, signatures) is kept on
; uninstall unless the user chooses to delete it.

#define AppName "Phalanx"
#ifndef AppVersion
  #define AppVersion "0.2.1"
#endif
#define AppExe "phalanx.exe"
#define CliExe "phalanx-cli.exe"
#define Release "..\target\release"

[Setup]
AppId={{6B0E3B5A-7C2D-4E57-9F1A-5D7C1B3E2A90}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
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
WizardStyle=modern
; The app's single-instance mutex: setup asks the user to quit it first.
AppMutex=Local\ThreatScanner.SingleInstance
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start {#AppName} in the tray when I sign in (folder protection keeps running)"; GroupDescription: "Protection:"; Flags: unchecked
Name: "browsers"; Description: "Connect my browsers for web protection (Browser Guard)"; GroupDescription: "Protection:"

[Files]
Source: "{#Release}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Release}\{#CliExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

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

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Dir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    Dir := ExpandConstant(DataFolder);
    if DirExists(Dir) and not UninstallSilent then
      if MsgBox('Also delete Phalanx''s data folder?' + #13#10#13#10 + Dir + #13#10#13#10 +
                'It holds your scan history, downloaded signatures, settings and QUARANTINED FILES. ' +
                'Keep it if you might reinstall or need to restore a quarantined file.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(Dir, True, True, True);
  end;
end;
