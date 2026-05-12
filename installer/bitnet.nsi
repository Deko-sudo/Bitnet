!define APPNAME "BitNet"
!define APPVERSION "2.2.0"
!define APPEXE "BitNet.exe"
!define COMPANY "BitNet"

Name "${APPNAME} ${APPVERSION}"
OutFile "${APPNAME}-${APPVERSION}-setup.exe"
InstallDir "$PROGRAMFILES\${APPNAME}"
RequestExecutionLevel admin

!include "MUI2.nsh"

Var StartMenuFolder

!define MUI_ICON ""
!define MUI_UNICON ""
!define MUI_WELCOMEPAGE_TITLE "Welcome to BitNet Setup"
!define MUI_WELCOMEPAGE_TEXT "BitNet is a zero-trust password manager with Rust-backed cryptography.$\r$\n$\r$\nThis wizard will install ${APPNAME} ${APPVERSION} on your computer."
!define MUI_FINISHPAGE_TITLE "Installation Complete"
!define MUI_FINISHPAGE_TEXT "${APPNAME} has been installed successfully.$\r$\n$\r$\nThe application data directory is at:$\r$\n$APPDATA\${APPNAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_RESERVEFILE_LANGDLL

LangString APPNAME_LANG ${LANG_ENGLISH} "${APPNAME}"
LangString APPNAME_LANG ${LANG_RUSSIAN} "${APPNAME}"
LangString DESKDOWN_LANG ${LANG_ENGLISH} "Download BitNet is starting..."
LangString DESKDOWN_LANG ${LANG_RUSSIAN} "Загрузка BitNet запускается..."

Section "BitNet (required)" SecMain
    SectionIn RO

    SetOutPath "$INSTDIR"

    File /r "dist\BitNet\*"

    CreateDirectory "$APPDATA\${APPNAME}"

    WriteUninstaller "$INSTDIR\uninstall.exe"

    !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
        CreateDirectory "$SMPROGRAMS\${APPNAME}"
        CreateShortCut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\${APPEXE}" "" "$INSTDIR\${APPEXE}" 0
        CreateShortCut "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk" "$INSTDIR\uninstall.exe"
    !insertmacro MUI_STARTMENU_WRITE_END

    CreateShortCut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${APPEXE}"

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${APPVERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${COMPANY}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "InstallLocation" '"$INSTDIR"'
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoRepair" 1

    nsExec::ExecToStack 'netsh advfirewall firewall add rule name="BitNet" dir=in action=allow protocol=TCP localport=8200 profile=private enable=yes'
SectionEnd

Section "Uninstall"
    Delete "$DESKTOP\${APPNAME}.lnk"

    !insertmacro MUI_STARTMENU_GETFOLDER "Application" $StartMenuFolder
    Delete "$SMPROGRAMS\$StartMenuFolder\${APPNAME}.lnk"
    Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall ${APPNAME}.lnk"
    RMDir "$SMPROGRAMS\$StartMenuFolder"

    RMDir /r "$INSTDIR"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

    nsExec::ExecToStack 'netsh advfirewall firewall delete rule name="BitNet"'

    MessageBox MB_YESNO "$(DESKDOWN_LANG)$\r$\n$\r$\nDelete your vault data ($APPDATA\${APPNAME})?" IDYES +2
        Goto +2
    RMDir /r "$APPDATA\${APPNAME}"
SectionEnd