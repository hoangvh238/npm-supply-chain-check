@echo off

setlocal enabledelayedexpansion
 
REM --- Output to both console and log file ---

set "LOG=%~dp0security-check-result.txt"

if "%~1"=="__INNER__" goto :run

call "%~f0" __INNER__ 2>&1 | powershell -NoProfile -Command "$input | Tee-Object -FilePath '%LOG%'"

echo.

echo   Result saved to: %LOG%

pause

exit /b
 
:run

echo ============================================================

echo   Developer Machine Security Check

echo   Checking for gh-token-monitor / router_init malware

echo   Date: %date% %time%

echo   Machine: %COMPUTERNAME%  User: %USERNAME%

echo ============================================================

echo.
 
set "FOUND_ISSUES=0"

set "HAS_WSL=0"

where wsl >nul 2>&1

if !errorlevel!==0 set "HAS_WSL=1"
 
REM -------------------------------------------------------

echo [1/7] macOS LaunchAgent

echo   N/A - This is a Windows machine - skipped

echo.
 
REM -------------------------------------------------------

echo [2/7] Linux systemd user service - via WSL

if "!HAS_WSL!"=="1" (

    wsl sh -c "test -f ~/.config/systemd/user/gh-token-monitor.service && echo INFECTED || echo CLEAN" > "%TEMP%\sec_check_svc.txt" 2>nul

    findstr /c:"INFECTED" "%TEMP%\sec_check_svc.txt" >nul 2>&1

    if !errorlevel!==0 (

        set "FOUND_ISSUES=1"

        echo   *** WARNING: gh-token-monitor.service DETECTED ***

        echo.

        echo   --- File details ---

        wsl ls -la ~/.config/systemd/user/gh-token-monitor.service 2>&1

        echo.

        echo   --- File contents ---

        wsl cat ~/.config/systemd/user/gh-token-monitor.service 2>&1

        echo.

        echo   --- Service status ---

        wsl sh -c "systemctl --user status gh-token-monitor 2>&1"

        echo.

        echo   === REMEDIATION ===

        echo   1. Stop the service:

        echo      wsl systemctl --user stop gh-token-monitor

        echo   2. Disable it:

        echo      wsl systemctl --user disable gh-token-monitor

        echo   3. Delete the file:

        echo      wsl rm ~/.config/systemd/user/gh-token-monitor.service

        echo   4. Reload systemd:

        echo      wsl systemctl --user daemon-reload

        echo   =====================

    ) else (

        echo   OK - not found

    )

    del "%TEMP%\sec_check_svc.txt" 2>nul

) else (

    echo   WSL not available - skipped

)

echo.
 
REM -------------------------------------------------------

echo [3/7] systemctl gh-token units - via WSL

if "!HAS_WSL!"=="1" (

    wsl sh -c "systemctl --user list-units 2>/dev/null | grep -i gh-token || true" > "%TEMP%\sec_check_systemctl.txt" 2>nul

    findstr /i "gh-token" "%TEMP%\sec_check_systemctl.txt" >nul 2>&1

    if !errorlevel!==0 (

        set "FOUND_ISSUES=1"

        echo   *** WARNING: gh-token systemd units DETECTED ***

        echo.

        echo   --- Active units ---

        type "%TEMP%\sec_check_systemctl.txt"

        echo.

        echo   --- All related unit files ---

        wsl sh -c "systemctl --user list-unit-files 2>/dev/null | grep -i gh-token" 2>&1

        echo.

        echo   === REMEDIATION ===

        echo   For each unit found above:

        echo   1. wsl systemctl --user stop ^<unit-name^>

        echo   2. wsl systemctl --user disable ^<unit-name^>

        echo   3. Delete the unit file from ~/.config/systemd/user/

        echo   4. wsl systemctl --user daemon-reload

        echo   =====================

    ) else (

        echo   OK - no matching units

    )

    del "%TEMP%\sec_check_systemctl.txt" 2>nul

) else (

    echo   WSL not available - skipped

)

echo.
 
REM -------------------------------------------------------

echo [4/7] Cron jobs - via WSL

if "!HAS_WSL!"=="1" (

    wsl sh -c "crontab -l 2>/dev/null | grep -in 'gh-token\|router_init\|router_runtime\|token-monitor' || true" > "%TEMP%\sec_check_cron.txt" 2>nul

    findstr /i "gh-token router_init router_runtime token-monitor" "%TEMP%\sec_check_cron.txt" >nul 2>&1

    if !errorlevel!==0 (

        set "FOUND_ISSUES=1"

        echo   *** WARNING: Suspicious cron jobs DETECTED ***

        echo.

        echo   --- Matching cron entries ---

        type "%TEMP%\sec_check_cron.txt"

        echo.

        echo   --- Full crontab ---

        wsl crontab -l 2>&1

        echo.

        echo   === REMEDIATION ===

        echo   1. Edit crontab:

        echo      wsl crontab -e

        echo   2. Remove any lines referencing gh-token, router_init,

        echo      router_runtime, or token-monitor

        echo   3. Save and exit

        echo   4. Verify: wsl crontab -l

        echo   =====================

    ) else (

        echo   OK - no suspicious cron jobs

    )

    del "%TEMP%\sec_check_cron.txt" 2>nul

) else (

    echo   WSL not available - skipped

)

echo.
 
REM -------------------------------------------------------

echo [5/7] Claude AI tool configuration

if exist "%USERPROFILE%\.claude\settings.json" (

    echo   File exists: %USERPROFILE%\.claude\settings.json

    echo.

    echo   --- Full contents ---

    type "%USERPROFILE%\.claude\settings.json"

    echo.

    echo.

    findstr /i "router_init router_runtime gh-token token-monitor" "%USERPROFILE%\.claude\settings.json" > "%TEMP%\sec_check_claude.txt" 2>nul

    findstr /i "router_init router_runtime gh-token token-monitor" "%TEMP%\sec_check_claude.txt" >nul 2>&1

    if !errorlevel!==0 (

        set "FOUND_ISSUES=1"

        echo   *** WARNING: Suspicious entries in Claude settings ***

        echo.

        echo   --- Suspicious lines ---

        type "%TEMP%\sec_check_claude.txt"

        echo.

        echo   === REMEDIATION ===

        echo   1. Open the file:

        echo      notepad "%USERPROFILE%\.claude\settings.json"

        echo   2. Remove any tool permissions or commands referencing:

        echo      router_init, router_runtime, gh-token-monitor

        echo   3. If unsure, delete and let Claude recreate it:

        echo      del "%USERPROFILE%\.claude\settings.json"

        echo   =====================

    ) else (

        echo   OK - no suspicious entries detected in Claude settings

    )

    del "%TEMP%\sec_check_claude.txt" 2>nul

) else (

    echo   OK - %USERPROFILE%\.claude\settings.json not found

)

echo.
 
REM -------------------------------------------------------

echo [6/7] Unexpected background processes

echo   Searching for: router_init, router_runtime, gh-token-monitor

echo.
 
call :check_process router_init

call :check_process router_runtime

call :check_process gh-token-monitor
 
REM Also do a broader PowerShell-based WMI search - excludes its own process

echo   --- Broad command-line scan ---

powershell -NoProfile -Command "$myPid = $PID; Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $myPid -and $_.CommandLine -match 'router_init|router_runtime|gh-token-monitor|token-monitor' -and $_.CommandLine -notmatch 'Get-CimInstance Win32_Process' } | Select-Object ProcessId, Name, CommandLine | Format-List" > "%TEMP%\sec_check_procs.txt" 2>&1

findstr /i "ProcessId" "%TEMP%\sec_check_procs.txt" >nul 2>&1

if !errorlevel!==0 (

    set "FOUND_ISSUES=1"

    echo   *** WARNING: Suspicious process command lines detected ***

    echo.

    type "%TEMP%\sec_check_procs.txt"

    echo.

    echo   === REMEDIATION ===

    echo   Kill each PID shown above:

    echo     taskkill /F /PID ^<pid^>

    echo   Then find and remove the executable.

    echo   =====================

) else (

    echo   OK - no suspicious command lines in running processes

)

del "%TEMP%\sec_check_procs.txt" 2>nul

echo.
 
REM -------------------------------------------------------

echo [7/7] Windows persistence mechanisms

echo.
 
echo   --- Scheduled Tasks ---

schtasks /query /fo CSV /nh 2>nul | findstr /i "gh-token router_init router_runtime token-monitor" > "%TEMP%\sec_check_tasks.txt" 2>&1

findstr /i "gh-token router_init router_runtime token-monitor" "%TEMP%\sec_check_tasks.txt" >nul 2>&1

if !errorlevel!==0 (

    set "FOUND_ISSUES=1"

    echo   *** WARNING: Suspicious scheduled tasks DETECTED ***

    echo.

    echo   --- Matching tasks ---

    type "%TEMP%\sec_check_tasks.txt"

    echo.

    echo   === REMEDIATION ===

    echo   Delete each suspicious task:

    echo     schtasks /delete /tn "^<TaskName^>" /f

    echo   =====================

) else (

    echo   OK - no suspicious scheduled tasks

)

del "%TEMP%\sec_check_tasks.txt" 2>nul

echo.
 
echo   --- Registry Run keys ---

call :check_regkey "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

call :check_regkey "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"

echo.
 
echo   --- Startup folder ---

set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

dir /b "%STARTUP%" 2>nul | findstr /i "gh-token router_init router_runtime token-monitor" > "%TEMP%\sec_check_startup.txt" 2>&1

findstr /i "gh-token router_init router_runtime token-monitor" "%TEMP%\sec_check_startup.txt" >nul 2>&1

if !errorlevel!==0 (

    set "FOUND_ISSUES=1"

    echo   *** WARNING: Suspicious file in Startup folder ***

    echo.

    echo   --- Matching files ---

    type "%TEMP%\sec_check_startup.txt"

    echo.

    echo   --- Startup folder path ---

    echo   !STARTUP!

    echo.

    echo   === REMEDIATION ===

    echo   Delete the suspicious files from the Startup folder above.

    echo   =====================

) else (

    echo   OK - Startup folder is clean

)

del "%TEMP%\sec_check_startup.txt" 2>nul

echo.
 
REM -------------------------------------------------------

echo ============================================================

if "!FOUND_ISSUES!"=="1" (

    echo   *** ISSUES FOUND - Review WARNING items above ***

    echo   After remediation, re-run this script to confirm cleanup.

    echo.

    echo   Additional recommended steps:

    echo   1. Rotate any GitHub tokens / PATs immediately

    echo   2. Rotate any API keys or secrets on this machine

    echo   3. Check GitHub account for unauthorized SSH keys or PATs:

    echo      https://github.com/settings/tokens

    echo      https://github.com/settings/keys

    echo   4. Review recent GitHub activity:

    echo      https://github.com/settings/security-log

    echo   5. Run a full antivirus scan

    echo   6. Notify your security team

) else (

    echo   ALL CLEAR - No indicators of compromise found.

)

echo ============================================================

echo.

goto :eof
 
REM ------------------------------------------------------- 

REM Subroutine: check a single process name 

REM -------------------------------------------------------

:check_process

tasklist /FI "IMAGENAME eq %1*" 2>nul | find /i "%1" >nul 2>&1

if !errorlevel!==0 (

    set "FOUND_ISSUES=1"

    echo   *** WARNING: %1 process DETECTED ***

    echo.

    echo   --- Process details ---

    tasklist /FI "IMAGENAME eq %1*" /V /FO LIST

    echo.

    echo   --- Process command line ---

    wmic process where "name like '%1%%'" get ProcessId,CommandLine /FORMAT:LIST 2>nul

    echo.

    echo   --- Process file location ---

    wmic process where "name like '%1%%'" get ExecutablePath /FORMAT:LIST 2>nul

    echo.

    echo   === REMEDIATION ===

    echo   1. Kill the process:  taskkill /F /IM %1* /T

    echo   2. Find and delete the executable shown above

    echo   3. Check startup entries - see check 7 - for persistence

    echo   =====================

    echo.

) else (

    echo   OK - %1 not running

)

goto :eof
 
REM ------------------------------------------------------- 

REM Subroutine: check a single registry key 

REM -------------------------------------------------------

:check_regkey

reg query %1 2>nul | findstr /i "gh-token router_init router_runtime token-monitor" > "%TEMP%\sec_check_reg.txt" 2>&1

findstr /i "gh-token router_init router_runtime token-monitor" "%TEMP%\sec_check_reg.txt" >nul 2>&1

if !errorlevel!==0 (

    set "FOUND_ISSUES=1"

    echo   *** WARNING: Suspicious registry entry in %1 ***

    echo.

    echo   --- Matching entries ---

    type "%TEMP%\sec_check_reg.txt"

    echo.

    echo   --- Full key contents ---

    reg query %1 2>nul

    echo.

    echo   === REMEDIATION ===

    echo   Delete the suspicious value:

    echo     reg delete %1 /v "^<ValueName^>" /f

    echo   =====================

) else (

    echo   OK - %1 is clean

)

del "%TEMP%\sec_check_reg.txt" 2>nul

goto :eof

GitHub
GitHub is where people build software. More than 150 million people use GitHub to discover, fork, and contribute to over 420 million projects.
 
