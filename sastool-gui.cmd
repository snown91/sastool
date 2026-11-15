@echo off
rem Launcher for the sastool GUI. Drive commands need an elevated session;
rem the GUI offers a "Restart as administrator" button if you start it normally.
setlocal
set PYTHONPATH=%~dp0;%PYTHONPATH%
start "" pythonw -m sastool.gui
