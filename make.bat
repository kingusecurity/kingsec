@echo off
REM KingSec - Windows developer task shortcuts
REM Usage: make.bat <target>
REM
REM Requires Python 3.11+ and pip installed.

setlocal enabledelayedexpansion

if "%1"=="" goto help

if "%1"=="install" goto install
if "%1"=="lint" goto lint
if "%1"=="fmt" goto fmt
if "%1"=="type" goto type
if "%1"=="test" goto test
if "%1"=="cov" goto cov
if "%1"=="check" goto check
if "%1"=="clean" goto clean
if "%1"=="help" goto help

echo Unknown target: %1
goto help

:install
echo Installing KingSec in development mode...
pip install -e ".[dev]"
if errorlevel 1 exit /b 1
echo Dependencies installed.
goto end

:lint
echo Running ruff linter...
python -m ruff check .
goto end

:fmt
echo Running ruff formatter...
python -m ruff format .
goto end

:type
echo Running mypy type checker...
python -m mypy
goto end

:test
echo Running pytest...
python -m pytest
goto end

:cov
echo Running pytest with coverage...
python -m pytest --cov
goto end

:check
echo Running full quality gate...
python -m ruff check .
if errorlevel 1 exit /b 1
python -m mypy
if errorlevel 1 exit /b 1
python -m pytest
if errorlevel 1 exit /b 1
echo All checks passed.
goto end

:clean
echo Cleaning caches and build artifacts...
if exist .pytest_cache rmdir /s /q .pytest_cache
if exist .mypy_cache rmdir /s /q .mypy_cache
if exist .ruff_cache rmdir /s /q .ruff_cache
if exist htmlcov rmdir /s /q htmlcov
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist .coverage del /q .coverage 2>nul
echo Done.
goto end

:help
echo KingSec developer shortcuts
echo.
echo Usage: make.bat ^<target^>
echo.
echo Targets:
echo   install   Install KingSec in development mode
echo   lint      Run ruff linter
echo   fmt       Run ruff formatter
echo   type      Run mypy type checker
echo   test      Run pytest
echo   cov       Run pytest with coverage
echo   check     Run full quality gate (lint + type + test)
echo   clean     Remove caches and build artifacts
echo   help      Show this help
goto end

:end
