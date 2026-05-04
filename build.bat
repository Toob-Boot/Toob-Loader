@echo off
REM ==============================================================================
REM Toob-Loader Build Wrapper
REM ==============================================================================
REM Fügt die RISC-V Toolchain temporär für diesen Befehl dem PATH hinzu,
REM ohne die globalen Windows-Umgebungsvariablen zu belasten.

set "TOOLCHAIN_BIN=C:\Espressif\tools\riscv32-esp-elf\esp-14.2.0_20251107\riscv32-esp-elf\bin"

REM Prüfen, ob der Pfad schon im PATH ist, um doppelte Einträge zu vermeiden
echo %PATH% | findstr /I /C:"%TOOLCHAIN_BIN%" >nul
if errorlevel 1 (
    set "PATH=%TOOLCHAIN_BIN%;%PATH%"
)

REM Build-Ordner anlegen, falls noch nicht vorhanden
if not exist "build_c6_ninja" (
    echo [INFO] Build-Ordner fehlt. Führe Initiale Konfiguration aus...
    python configure.py
)

REM Build starten und Argumente weiterreichen
echo [INFO] Starte Build...
cmake --build build_c6_ninja %*
