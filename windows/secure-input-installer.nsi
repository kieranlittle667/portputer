; Separate per-machine secure-input package. No application or user data.
Unicode true
SetCompressor /SOLID lzma
RequestExecutionLevel admin
ManifestDPIAware true
!include "MUI2.nsh"
!include "x64.nsh"
!define PRODUCT "Portputer Secure Input"
!define KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\PortputerSecureInput"
Name "${PRODUCT}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\Portputer Secure Input"
VIProductVersion "${VERSION_NUMBERS}.${BUILD}"
VIAddVersionKey /LANG=1033 "ProductName" "${PRODUCT}"
VIAddVersionKey /LANG=1033 "FileDescription" "${PRODUCT} installer"
VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Apache License 2.0"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
Function .onInit
    ${IfNot} ${RunningX64}
        SetErrorLevel 1
        Abort
    ${EndIf}
    SetRegView 64
    SetShellVarContext all
    ; A caller's /D= must never redirect privileged files to user storage.
    StrCpy $INSTDIR "$PROGRAMFILES64\Portputer Secure Input"
    ReadRegDWORD $0 HKLM "${KEY}" "Build"
    IntCmp $0 ${BUILD} ready ready 0
        MessageBox MB_OK|MB_ICONSTOP "A newer secure-input package is already installed." /SD IDOK
        SetErrorLevel 1
        Abort
    ready:
FunctionEnd
Function un.onInit
    SetRegView 64
    SetShellVarContext all
    StrCpy $INSTDIR "$PROGRAMFILES64\Portputer Secure Input"
FunctionEnd
!macro StopService PREFIX
Function ${PREFIX}StopService
    System::Call 'advapi32::OpenSCManagerW(p 0, p 0, i 1) p.r0'
    StrCmp $0 0 failed
    System::Call 'advapi32::OpenServiceW(p r0, w "PortputerSecureInput", i 0x24) p.r1'
    StrCmp $1 0 close_manager
    System::Alloc 28
    Pop $2
    System::Call 'advapi32::ControlService(p r1, i 1, p r2)'
    StrCpy $4 0
    wait:
        System::Call 'advapi32::QueryServiceStatus(p r1, p r2) i.r3'
        StrCmp $3 0 close_service_failed
        IntOp $3 $2 + 4
        System::Call '*$3(i.r3)'
        IntCmp $3 1 stopped
        IntOp $4 $4 + 1
        IntCmp $4 300 close_service_failed
        Sleep 100
        Goto wait
    stopped:
        System::Free $2
        System::Call 'advapi32::CloseServiceHandle(p r1)'
    close_manager:
        System::Call 'advapi32::CloseServiceHandle(p r0)'
        Return
    close_service_failed:
        System::Free $2
        System::Call 'advapi32::CloseServiceHandle(p r1)'
        System::Call 'advapi32::CloseServiceHandle(p r0)'
    failed:
        SetErrorLevel 1
        MessageBox MB_OK|MB_ICONSTOP "Secure-input support could not be stopped. No files were replaced." /SD IDOK
        Abort
FunctionEnd
!macroend
!insertmacro StopService ""
!insertmacro StopService "un."
Section "Install"
    Call StopService
    SetOutPath "$INSTDIR"
    CreateDirectory "$INSTDIR\Previous"
    ClearErrors
    IfFileExists "$INSTDIR\portputer-input-service.exe" 0 no_backup
        CopyFiles /SILENT "$INSTDIR\portputer-input-service.exe" "$INSTDIR\Previous"
        IfErrors backup_failed
    no_backup:
    ClearErrors
    !ifdef NSIS_WIN32_MAKENSIS
        File "${STAGE}\portputer-input-service.exe"
        File "${STAGE}\LICENSE.txt"
    !else
        File "${STAGE}/portputer-input-service.exe"
        File "${STAGE}/LICENSE.txt"
    !endif
    IfErrors install_failed
    ExecWait '"$INSTDIR\portputer-input-service.exe" --install' $0
    StrCmp $0 0 installed
    install_failed:
        Call StopService
        IfFileExists "$INSTDIR\Previous\portputer-input-service.exe" 0 rollback_done
            CopyFiles /SILENT "$INSTDIR\Previous\portputer-input-service.exe" "$INSTDIR"
            ExecWait '"$INSTDIR\portputer-input-service.exe" --install'
        rollback_done:
        SetErrorLevel 1
        MessageBox MB_OK|MB_ICONSTOP "Secure-input installation failed. The previous helper was restored where available." /SD IDOK
        Abort
    backup_failed:
        ExecWait '"$SYSDIR\sc.exe" start PortputerSecureInput'
        SetErrorLevel 1
        MessageBox MB_OK|MB_ICONSTOP "The existing helper could not be backed up. No files were replaced." /SD IDOK
        Abort
    installed:
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "${KEY}" "DisplayName" "${PRODUCT}"
    WriteRegStr HKLM "${KEY}" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "${KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "${KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "${KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
    WriteRegDWORD HKLM "${KEY}" "Build" ${BUILD}
    WriteRegDWORD HKLM "${KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${KEY}" "NoRepair" 1
    Delete "$INSTDIR\Previous\portputer-input-service.exe"
    RMDir "$INSTDIR\Previous"
SectionEnd
Section "Uninstall"
    Call un.StopService
    ExecWait '"$INSTDIR\portputer-input-service.exe" --uninstall' $0
    StrCmp $0 0 +3
        SetErrorLevel 1
        Abort
    Delete "$INSTDIR\portputer-input-service.exe"
    Delete "$INSTDIR\LICENSE.txt"
    Delete "$INSTDIR\Previous\portputer-input-service.exe"
    RMDir "$INSTDIR\Previous"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"
    DeleteRegKey HKLM "${KEY}"
SectionEnd
