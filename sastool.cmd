@echo off
rem Launcher: sastool <command> ...   (run from an elevated prompt)
setlocal
set PYTHONPATH=%~dp0;%PYTHONPATH%
python -m sastool %*
