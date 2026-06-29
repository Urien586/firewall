@echo off
setlocal EnableExtensions

pushd "%~dp0"

set "OUT_DIR=%~dp0..\bin\Win64_Shipping_Server"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if "%WINDIVERT_DIR%"=="" (
  echo [ERROR] WINDIVERT_DIR is not set.
  echo.
  echo Download/extract WinDivert, then run for example:
  echo   set WINDIVERT_DIR=C:\WinDivert-2.2.2-A
  echo   build.bat
  echo.
  popd
  exit /b 1
)

if not exist "%WINDIVERT_DIR%\include\windivert.h" (
  echo [ERROR] windivert.h was not found:
  echo   %WINDIVERT_DIR%\include\windivert.h
  echo.
  echo Check WINDIVERT_DIR. It must point to the extracted WinDivert SDK root.
  popd
  exit /b 1
)

if not exist "%WINDIVERT_DIR%\x64\WinDivert.lib" (
  echo [ERROR] WinDivert.lib was not found:
  echo   %WINDIVERT_DIR%\x64\WinDivert.lib
  echo.
  echo Check that you downloaded the WinDivert binary package, not only source files.
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
  echo.
  echo Install "Desktop development with C++" or "Build Tools for Visual Studio",
  echo then run this from "x64 Native Tools Command Prompt for VS".
  echo.
  popd
  exit /b 1
)

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

cl /nologo /LD /O2 /W4 /I"%WINDIVERT_DIR%\include" "%~dp0windivert_game_filter.c" /link /OUT:"%OUT_DIR%\windivert_game_filter.dll" /LIBPATH:"%WINDIVERT_DIR%\x64" WinDivert.lib Ws2_32.lib
if errorlevel 1 (
  echo [ERROR] C build failed.
  popd
  exit /b %errorlevel%
)

copy /Y "%WINDIVERT_DIR%\x64\WinDivert.dll" "%OUT_DIR%\" >nul
copy /Y "%WINDIVERT_DIR%\x64\WinDivert64.sys" "%OUT_DIR%\" >nul

echo.
echo Built and copied files to:
echo   %OUT_DIR%
echo.
echo Files:
echo   windivert_game_filter.dll
echo   WinDivert.dll
echo   WinDivert64.sys

popd
exit /b 0
