@echo off
setlocal EnableExtensions

pushd "%~dp0"

set "OUT_DIR=%~dp0..\bin\Win64_Shipping_Server"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if "%WINDIVERT_DIR%"=="" (
  echo [ERROR] WINDIVERT_DIR is not set.
  echo.
  echo Example:
  echo   set WINDIVERT_DIR=C:\WinDivert-2.2.2-A
  echo   build_rdp_guard.bat
  echo.
  popd
  exit /b 1
)

if not exist "%WINDIVERT_DIR%\include\windivert.h" (
  echo [ERROR] windivert.h was not found:
  echo   %WINDIVERT_DIR%\include\windivert.h
  popd
  exit /b 1
)

if not exist "%WINDIVERT_DIR%\x64\WinDivert.lib" (
  echo [ERROR] WinDivert.lib was not found:
  echo   %WINDIVERT_DIR%\x64\WinDivert.lib
  popd
  exit /b 1
)

where cl.exe >nul 2>nul
if errorlevel 1 (
  if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
  )

  if defined VSINSTALL if exist "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" (
    call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat"
  )
)

where cl.exe >nul 2>nul
if errorlevel 1 (
  echo [ERROR] cl.exe was not found.
  echo Install "Desktop development with C++" or run from "x64 Native Tools Command Prompt for VS".
  popd
  exit /b 1
)

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

cl /nologo /O2 /W4 /I"%WINDIVERT_DIR%\include" "%~dp0rdp_3389_guard.c" /link /OUT:"%OUT_DIR%\rdp_3389_guard.exe" /LIBPATH:"%WINDIVERT_DIR%\x64" WinDivert.lib Ws2_32.lib
if errorlevel 1 (
  echo [ERROR] RDP guard build failed.
  popd
  exit /b %errorlevel%
)

copy /Y "%WINDIVERT_DIR%\x64\WinDivert.dll" "%OUT_DIR%\" >nul
copy /Y "%WINDIVERT_DIR%\x64\WinDivert64.sys" "%OUT_DIR%\" >nul

echo.
echo Built and copied files to:
echo   %OUT_DIR%
echo.
echo Run example:
echo   "%OUT_DIR%\rdp_3389_guard.exe" --allow YOUR.PUBLIC.IP

popd
exit /b 0
