@echo off
REM subtake — one-click "Setup" button.
REM Double-clicking this file installs the program (subtake / subtake-gui
REM commands + desktop shortcut). Pass -BuildExe to also build dist\subtake.exe.
REM
REM To build the standalone exe, right-click this file... actually run:
REM   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -BuildExe -Shortcut
REM This default double-click install:
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Shortcut %*
pause
