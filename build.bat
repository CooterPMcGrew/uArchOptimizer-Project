@echo off
setlocal enabledelayedexpansion

echo ============================================
echo     uArchOptimizer Build Script
echo ============================================

:: Set paths
set ROOT_DIR=%~dp0
set BUILD_DIR=%ROOT_DIR%build
set SRC_DIR=%ROOT_DIR%src
set CPP_SRC=%SRC_DIR%\cpp
set BENCHMARK_SRC=%SRC_DIR%\benchmarks

:: Create build directory if it doesn't exist
if not exist "%BUILD_DIR%" (
    echo Creating build directory...
    mkdir "%BUILD_DIR%"
)

echo.
echo Building uArchDetector...
g++ "%CPP_SRC%\uArchDetector.cpp" "%CPP_SRC%\cpu_utils.cpp" "%CPP_SRC%\microarch_mapper.cpp" -o "%BUILD_DIR%\uArchDetector.exe"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build uArchDetector
    exit /b %ERRORLEVEL%
) else (
    echo [SUCCESS] Built uArchDetector.exe
)

echo.
echo Building benchmarks...

:: Scalar benchmark
echo Building benchmark_scalar.exe...
g++ "%BENCHMARK_SRC%\benchmark.cpp" -o "%BUILD_DIR%\benchmark_scalar.exe" -D SCALAR_ONLY -O0
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build benchmark_scalar.exe
    exit /b %ERRORLEVEL%
) else (
    echo [SUCCESS] Built benchmark_scalar.exe
)

:: Optimized benchmark
echo Building benchmark_optimized.exe...
g++ "%BENCHMARK_SRC%\benchmark.cpp" -o "%BUILD_DIR%\benchmark_optimized.exe" -O3 -march=native -mavx2 -ffast-math
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build benchmark_optimized.exe
    exit /b %ERRORLEVEL%
) else (
    echo [SUCCESS] Built benchmark_optimized.exe
)

:: Combined benchmark with instrumentation
echo Building benchmark.exe...
g++ "%BENCHMARK_SRC%\benchmark.cpp" -o "%BUILD_DIR%\benchmark.exe" -O2
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build benchmark.exe
    exit /b %ERRORLEVEL%
) else (
    echo [SUCCESS] Built benchmark.exe
)

echo.
echo All components built successfully!
echo Executables are located in %BUILD_DIR%

echo.
echo ============================================
echo          Build Complete
echo ============================================

endlocal
