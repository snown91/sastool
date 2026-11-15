@echo off
rem Read-only live test. Usage: livetest.cmd <drive#>   (elevated)
cd /d %~dp0
set D=%1
set O=livetest_%D%.txt
echo sastool read-only live test, drive %D% > %O%
for %%C in ("tur %D%" "info %D%" "inquiry %D%" "readcap %D%" "vpd %D% --all" "logs %D%" "log %D% all" "modes %D%" "mode %D% 08" "errors %D%" "opcodes %D%" "luns %D%" "sense %D%" "mode-set %D% 08 WCE=1 --dry-run" "raw %D% --cdb a30c80000000000000a00000 --in 160") do (
  echo. >> %O%
  echo ===== sastool %%~C ===== >> %O%
  python -m sastool --trace %%~C >> %O% 2>&1
  echo [exit code !errorlevel!] >> %O%
)
