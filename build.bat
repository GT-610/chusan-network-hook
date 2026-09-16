@echo off
setlocal

set "ROOT=%~dp0"
set "OUT=%ROOT%build"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Visual Studio Installer vswhere.exe was not found.
  exit /b 1
)
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
if not defined VSROOT (
  echo Visual C++ build tools were not found.
  exit /b 1
)
if not exist "%OUT%" mkdir "%OUT%"

call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /O2 /MT /W4 /DWIN32 /D_WINDOWS /D_USRDLL /LD ^
  "%ROOT%src\network_hook.cpp" ^
  /Fo"%OUT%\network_hook_x64.obj" ^
  /link /MACHINE:X64 /DYNAMICBASE /NXCOMPAT /OUT:"%OUT%\chusan_network_hook_x64.dll" ^
  /PDB:"%OUT%\chusan_network_hook_x64.pdb" ws2_32.lib iphlpapi.lib bcrypt.lib
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /O2 /MT /W4 /DWIN32 /D_WINDOWS ^
  "%ROOT%tests\smoketest.cpp" ^
  /Fo"%OUT%\network_hook_smoketest_x64.obj" ^
  /link /MACHINE:X64 /SUBSYSTEM:CONSOLE /OUT:"%OUT%\network_hook_smoketest_x64.exe" ws2_32.lib
if errorlevel 1 exit /b 1

call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -arch=x86 -host_arch=x64 >nul
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /O2 /MT /W4 /DWIN32 /D_WINDOWS ^
  "%ROOT%tests\smoketest.cpp" ^
  /Fo"%OUT%\network_hook_smoketest_x86.obj" ^
  /link /MACHINE:X86 /SUBSYSTEM:CONSOLE /OUT:"%OUT%\network_hook_smoketest_x86.exe" ws2_32.lib
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /O2 /MT /W4 /DWIN32 /D_WINDOWS /D_USRDLL /LD ^
  "%ROOT%src\network_hook.cpp" ^
  /Fo"%OUT%\network_hook_x86.obj" ^
  /link /MACHINE:X86 /DYNAMICBASE /NXCOMPAT /OUT:"%OUT%\chusan_network_hook_x86.dll" ^
  /PDB:"%OUT%\chusan_network_hook_x86.pdb" ws2_32.lib iphlpapi.lib bcrypt.lib
if errorlevel 1 exit /b 1

copy /Y "%ROOT%network_hook.ini" "%OUT%\network_hook.ini" >nul

echo Built:
echo   %OUT%\chusan_network_hook_x64.dll
echo   %OUT%\chusan_network_hook_x86.dll
echo   %OUT%\network_hook_smoketest_x64.exe
echo   %OUT%\network_hook_smoketest_x86.exe
exit /b 0
