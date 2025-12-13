@echo off
REM Wrapper to run Codacy Analysis CLI (Windows)
SETLOCAL
SET JAR=%~dp0codacy-analysis-cli-assembly.jar
IF NOT EXIST "%JAR%" (
  echo Error: %JAR% not found
  exit /b 2
)
java -jar "%JAR%" %*
ENDLOCAL
