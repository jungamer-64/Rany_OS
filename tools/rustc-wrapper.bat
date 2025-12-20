@echo off
rem wrapper to log rustc invocations and forward to real rustc
set LOG=D:\Rust\Rany_OS\tools\rustc-args.log
echo %DATE% %TIME% >> "%LOG%"
echo %* >> "%LOG%"
rem call rustc in PATH
rustc %*
exit /b %ERRORLEVEL%