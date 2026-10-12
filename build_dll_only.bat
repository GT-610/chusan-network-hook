@echo off
setlocal
set ROOT=%~dp0
set OUT=%ROOT%build
if not exist "%OUT%" mkdir "%OUT%"

set VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools
if not exist "%VSROOT%" (
  for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSROOT=%%i
)

call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -arch=x86 -host_arch=x64 >nul
if errorlevel 1 exit /b 1

echo [build] x86 chusan_network_hook.dll (tag %1)
cl /nologo /std:c++17 /O2 /MT /W4 /I"%ROOT%src" /DWIN32 /D_WINDOWS /D_USRDLL /LD ^
  "%ROOT%src\network_hook.cpp" ^
  /Fo"%OUT%\network_hook_x86.obj" ^
  /link /MACHINE:X86 /DYNAMICBASE /NXCOMPAT /OUT:"%OUT%\chusan_network_hook_x86.dll" ^
  /PDB:"%OUT%\chusan_network_hook_x86.pdb" ws2_32.lib iphlpapi.lib bcrypt.lib
if errorlevel 1 exit /b 1

echo [build] x64 chusan_network_hook.dll (tag %1)
call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /O2 /MT /W4 /I"%ROOT%src" /DWIN32 /D_WINDOWS /D_USRDLL /LD ^
  "%ROOT%src\network_hook.cpp" ^
  /Fo"%OUT%\network_hook_x64.obj" ^
  /link /MACHINE:X64 /DYNAMICBASE /NXCOMPAT /OUT:"%OUT%\chusan_network_hook_x64.dll" ^
  /PDB:"%OUT%\chusan_network_hook_x64.pdb" ws2_32.lib iphlpapi.lib bcrypt.lib
if errorlevel 1 exit /b 1

echo [build] done
exit /b 0
