@echo off
set LOG=D:\Rust\Rany_OS\tools\link-args.log
echo %DATE% %TIME% >> "%LOG%"
echo %* >> "%LOG%"
rem Forward to the real link.exe (assumed in PATH)
link.exe %*
exit /b %ERRORLEVEL%