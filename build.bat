@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo   CS:GO Legacy Headless Client - Build Script
echo =======================================================
echo.

set "CONFIG=Release"
set "ARCH=x64"
set "BUILD_DIR=build"
set "RUN_TESTS=0"
set "CLEAN=0"

:parse_args
if "%~1"=="" goto after_args
if /i "%~1"=="--test" (
    set "RUN_TESTS=1"
    shift
    goto parse_args
)
if /i "%~1"=="--tests" (
    set "RUN_TESTS=1"
    shift
    goto parse_args
)
if /i "%~1"=="--clean" (
    set "CLEAN=1"
    shift
    goto parse_args
)
if /i "%~1"=="--debug" (
    set "CONFIG=Debug"
    shift
    goto parse_args
)
if /i "%~1"=="--release" (
    set "CONFIG=Release"
    shift
    goto parse_args
)
if /i "%~1"=="--x86" (
    set "ARCH=Win32"
    shift
    goto parse_args
)
if /i "%~1"=="--win32" (
    set "ARCH=Win32"
    shift
    goto parse_args
)
if /i "%~1"=="--x64" (
    set "ARCH=x64"
    shift
    goto parse_args
)
if /i "%~1"=="--help" (
    echo Usage: build.bat [options]
    echo.
    echo Options:
    echo   --clean     Clean build directory before compiling
    echo   --test      Run test suite after build completes
    echo   --release   Build Release configuration ^(default^)
    echo   --debug     Build Debug configuration
    echo   --x64       Target 64-bit architecture ^(default^)
    echo   --x86       Target 32-bit architecture
    echo.
    exit /b 0
)
echo Unknown option: %~1
exit /b 1

:after_args

:: Check for cmake in PATH
where cmake >nul 2>nul
if %ERRORLEVEL% equ 0 goto cmake_found

:: Attempt to locate CMake via Visual Studio installation
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

if defined VS_PATH (
    if exist "!VS_PATH!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
        set "PATH=!VS_PATH!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;!PATH!"
        goto cmake_found
    )
    if exist "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" (
        call "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" %ARCH% >nul 2>nul
        where cmake >nul 2>nul
        if %ERRORLEVEL% equ 0 goto cmake_found
    )
)

echo [ERROR] CMake could not be found in PATH or Visual Studio installation.
echo Please install CMake or Visual Studio with C++ desktop development tools.
exit /b 1

:cmake_found
echo Found CMake:
where cmake
echo.

if "%CLEAN%"=="1" (
    if exist "%BUILD_DIR%" (
        echo Cleaning %BUILD_DIR% directory...
        rmdir /s /q "%BUILD_DIR%"
    )
)

if exist "%BUILD_DIR%\CMakeCache.txt" (
    echo Configuring project with CMake using existing cache in %BUILD_DIR%...
    cmake -B "%BUILD_DIR%"
) else (
    echo Configuring project with CMake [%ARCH%]...
    cmake -B "%BUILD_DIR%" -A "%ARCH%"
)
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configuration failed.
    exit /b %ERRORLEVEL%
)

echo.
echo Compiling project [%CONFIG%]...
cmake --build "%BUILD_DIR%" --config "%CONFIG%"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build compilation failed.
    exit /b %ERRORLEVEL%
)

echo.
echo =======================================================
echo   Build Successful!
echo =======================================================
if exist "%BUILD_DIR%\%CONFIG%\headless-csgo.exe" (
    echo Output: %BUILD_DIR%\%CONFIG%\headless-csgo.exe
)
echo.

if "%RUN_TESTS%"=="1" (
    echo Running CTest suite [%CONFIG%]...
    ctest --test-dir "%BUILD_DIR%" -C "%CONFIG%" --output-on-failure
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] One or more tests failed.
        exit /b %ERRORLEVEL%
    )
    echo All tests passed successfully!
)

exit /b 0
