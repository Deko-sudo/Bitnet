; BitNet Password Manager Setup Script
; Requires Inno Setup 6.2+ (https://jrsoftware.org/isdl.php)
;
; Build the project first:
;   .\scripts\build-desktop.ps1 -Configuration Release -Platform x64
;
; Then compile this script:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\scripts\bitnet-setup.iss

#define MyAppName "BitNet Password Manager"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "BitNet Team"
#define MyAppExeName "BitNet.Desktop.exe"
#define MyAppId "{{B4E5A1C2-3F8D-4A7B-9C6E-1D2F3A4B5C6D}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\BitNet
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=no
OutputDir={#SourcePath}\..\target\installer
OutputBaseFilename=BitNet-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile={#SourcePath}\..\browser-extension\icons\icon48.png
LicenseFile={#SourcePath}\..\LICENSE.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "nativemessaging"; Description: "Register Native Messaging host for Chrome/Edge/Firefox"; GroupDescription: "Browser Integration"
Name: "browserextension"; Description: "Copy browser extension files"; GroupDescription: "Browser Integration"

[Dirs]
Name: "{app}\Native"; Permissions: users-full
Name: "{app}\BrowserExtension"; Permissions: users-full

[Files]
; --- Desktop Application ---
Source: "{#SourcePath}\..\BitNet.Desktop\bin\x64\Release\net8.0-windows10.0.19041.0\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}\..\BitNet.Desktop\bin\x64\Release\net8.0-windows10.0.19041.0\*.dll"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs
Source: "{#SourcePath}\..\BitNet.Desktop\bin\x64\Release\net8.0-windows10.0.19041.0\*.runtimeconfig.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}\..\BitNet.Desktop\bin\x64\Release\net8.0-windows10.0.19041.0\*.deps.json"; DestDir: "{app}"; Flags: ignoreversion

; --- Native Binaries ---
Source: "{#SourcePath}\..\BitNet.Desktop\Native\bitnet_ffi.dll"; DestDir: "{app}\Native"; Flags: ignoreversion
Source: "{#SourcePath}\..\BitNet.Desktop\Native\bitnet-native-host.exe"; DestDir: "{app}\Native"; Flags: ignoreversion

; --- Browser Extension ---
Source: "{#SourcePath}\..\browser-extension\manifest.json"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion; Tasks: browserextension
Source: "{#SourcePath}\..\browser-extension\background.js"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion; Tasks: browserextension
Source: "{#SourcePath}\..\browser-extension\content.js"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion; Tasks: browserextension
Source: "{#SourcePath}\..\browser-extension\popup.html"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion; Tasks: browserextension
Source: "{#SourcePath}\..\browser-extension\popup.js"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion; Tasks: browserextension
Source: "{#SourcePath}\..\browser-extension\manifest-firefox.json"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion; Tasks: browserextension
Source: "{#SourcePath}\..\browser-extension\icons\*"; DestDir: "{app}\BrowserExtension\icons"; Flags: ignoreversion recursesubdirs; Tasks: browserextension

; --- Native Host Manifest Template ---
Source: "{#SourcePath}\..\browser-extension\com.bitnet.nativehost.json"; DestDir: "{app}\BrowserExtension"; Flags: ignoreversion; Tasks: nativemessaging

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Browser Extension"; Filename: "{app}\BrowserExtension"; Tasks: browserextension
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Register Native Messaging host for Chrome
Root: HKLM; Subkey: "Software\Google\Chrome\NativeMessagingHosts\com.bitnet.nativehost"; ValueType: string; ValueName: ""; ValueData: "{app}\BrowserExtension\com.bitnet.nativehost.json"; Flags: uninsdeletekey; Tasks: nativemessaging
Root: HKCU; Subkey: "Software\Google\Chrome\NativeMessagingHosts\com.bitnet.nativehost"; ValueType: string; ValueName: ""; ValueData: "{app}\BrowserExtension\com.bitnet.nativehost.json"; Flags: uninsdeletekey; Tasks: nativemessaging

; Register for Edge
Root: HKLM; Subkey: "Software\Microsoft\Edge\NativeMessagingHosts\com.bitnet.nativehost"; ValueType: string; ValueName: ""; ValueData: "{app}\BrowserExtension\com.bitnet.nativehost.json"; Flags: uninsdeletekey; Tasks: nativemessaging
Root: HKCU; Subkey: "Software\Microsoft\Edge\NativeMessagingHosts\com.bitnet.nativehost"; ValueType: string; ValueName: ""; ValueData: "{app}\BrowserExtension\com.bitnet.nativehost.json"; Flags: uninsdeletekey; Tasks: nativemessaging

; Register for Firefox
Root: HKLM; Subkey: "Software\Mozilla\NativeMessagingHosts\com.bitnet.nativehost"; ValueType: string; ValueName: ""; ValueData: "{app}\BrowserExtension\com.bitnet.nativehost.json"; Flags: uninsdeletekey; Tasks: nativemessaging
Root: HKCU; Subkey: "Software\Mozilla\NativeMessagingHosts\com.bitnet.nativehost"; ValueType: string; ValueName: ""; ValueData: "{app}\BrowserExtension\com.bitnet.nativehost.json"; Flags: uninsdeletekey; Tasks: nativemessaging

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch BitNet"; Flags: postinstall skipifsilent nowait

[Code]
function InitializeSetup(): Boolean;
var
  Path: string;
begin
  Path := ExpandConstant('{app}');
  
  // Update native host manifest with installed path
  if WizardIsTaskSelected('nativemessaging') then
  begin
    // Write updated manifest with correct native host path
    SaveStringToFile(
      Path + '\BrowserExtension\com.bitnet.nativehost.json',
      '{"name":"com.bitnet.nativehost","description":"BitNet Password Manager Native Host","path":"'
      + StringReplace(Path, '\', '\\', [rfReplaceAll]) + '\\Native\\bitnet-native-host.exe","type":"stdio","allowed_origins":["chrome-extension://*/"],"allowed_extensions":["bitnet@bitnet.dev"]}',
      False);
  end;
  
  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  NeedsRestart := False;
  Result := '';
end;