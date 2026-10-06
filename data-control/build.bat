    ::# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
    ::# Giovanna Esmelardi, Gustavo Enrique
    ::# SPDX-License-Identifier: GPL-3.0-or-later
    ::# Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.

@echo off
setlocal enabledelayedexpansion
title PhantomFix — Build

echo.
echo  ==========================================
echo   PhantomFix Data-Control — Build Script
echo  ==========================================
echo.

:: ── Verifica Python ───────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERRO] Python nao encontrado. Instale e adicione ao PATH.
    pause & exit /b 1
)

:: ── Verifica Inno Setup ───────────────────────────────────────────────────────
set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist %ISCC% (
    echo [AVISO] Inno Setup nao encontrado em %ISCC%
    echo         Ajuste o caminho no build.bat se necessario.
    set SKIP_INNO=1
) else (
    set SKIP_INNO=0
)

:: ── 1. Dependencias ───────────────────────────────────────────────────────────
echo [1/3] Instalando dependencias...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERRO] Falha ao instalar dependencias.
    pause & exit /b 1
)
echo       OK
echo.

:: ── 2. PyInstaller ────────────────────────────────────────────────────────────
echo [2/3] Gerando executavel com PyInstaller...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist PhantomFix.spec del PhantomFix.spec

pyinstaller --onefile --windowed --icon=phantom.ico --add-data "phantom.ico;." --name=PhantomFix main_data_control.py
if errorlevel 1 (
    echo [ERRO] PyInstaller falhou.
    pause & exit /b 1
)
echo       OK — dist\PhantomFix.exe gerado
echo.

:: ── 3. Inno Setup ─────────────────────────────────────────────────────────────
if "%SKIP_INNO%"=="1" (
    echo [3/3] Inno Setup pulado ^(nao encontrado^).
    echo       Compile installer.iss manualmente no Inno Setup Compiler.
) else (
    echo [3/3] Gerando instalador com Inno Setup...
    if not exist installer mkdir installer
    %ISCC% installer.iss
    if errorlevel 1 (
        echo [ERRO] Inno Setup falhou.
        pause & exit /b 1
    )
    echo       OK — installer\PhantomFix-Setup.exe gerado
)

echo.
echo  ==========================================
echo   Build concluido com sucesso!
echo  ==========================================
echo.
if "%SKIP_INNO%"=="0" (
    echo  Distribuivel: installer\PhantomFix-Setup.exe
) else (
    echo  Executavel:   dist\PhantomFix.exe
)
echo.
pause
