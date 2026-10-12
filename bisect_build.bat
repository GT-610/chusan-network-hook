@echo off
setlocal enabledelayedexpansion
REM Build one DLL per commit between v0.1.0 and HEAD into artifacts\<short-sha>\ so the
REM regression can be bisected on real hardware. Sources are extracted with PowerShell
REM because git's bundled tar is not available on this host.

set ROOT=%~dp0
set ART=%ROOT%artifacts
if not exist "%ART%" mkdir "%ART%"

set VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools
if not exist "%VSROOT%" (
  for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSROOT=%%i
)

cd /d "%ROOT%"
if not exist ".git" (
  echo [bisect] not a git repository: %ROOT%
  exit /b 1
)

call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -arch=x86 -host_arch=x64 >nul
if errorlevel 1 exit /b 1

for /f "usebackq delims=" %%c in (`git rev-list --reverse v0.1.0..HEAD`) do (
  set "SHA=%%c"
  for /f "delims=" %%s in ('git rev-parse --short=8 !SHA!') do set "SHORT=%%s"
  set "OUT=%ART%\!SHORT!"
  if not exist "!OUT!" mkdir "!OUT!"
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Set-Location '!ROOT!'; git show '!SHA!:src/network_hook.cpp' | Set-Content -Encoding UTF8 '!OUT!\network_hook.cpp'"
  if not exist "!OUT!\network_hook.cpp" (
    echo [bisect] !SHORT! : could not extract src
    exit /b 1
  )
  cl /nologo /std:c++17 /O2 /MT /W4 /I"!OUT!" /DWIN32 /D_WINDOWS /D_USRDLL /LD ^
    "!OUT!\network_hook.cpp" ^
    /Fo"!OUT!\x86.obj" ^
    /link /MACHINE:X86 /DYNAMICBASE /NXCOMPAT /OUT:"!OUT!\chusan_network_hook_x86.dll" ^
    ws2_32.lib iphlpapi.lib bcrypt.lib
  if errorlevel 1 (
    echo [bisect] !SHORT! : x86 build FAILED
    exit /b 1
  )
  echo [bisect] !SHORT! : x86 ok
)

call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1
for /f "usebackq delims=" %%c in (`git rev-list --reverse v0.1.0..HEAD`) do (
  set "SHA=%%c"
  for /f "delims=" %%s in ('git rev-parse --short=8 !SHA!') do set "SHORT=%%s"
  set "OUT=%ART%\!SHORT!"
  cl /nologo /std:c++17 /O2 /MT /W4 /I"!OUT!" /DWIN32 /D_WINDOWS /D_USRDLL /LD ^
    "!OUT!\network_hook.cpp" ^
    /Fo"!OUT!\x64.obj" ^
    /link /MACHINE:X64 /DYNAMICBASE /NXCOMPAT /OUT:"!OUT!\chusan_network_hook_x64.dll" ^
    ws2_32.lib iphlpapi.lib bcrypt.lib
  if errorlevel 1 (
    echo [bisect] !SHORT! : x64 build FAILED
    exit /b 1
  )
  echo [bisect] !SHORT! : x64 ok
)

echo [bisect] done
exit /b 0
