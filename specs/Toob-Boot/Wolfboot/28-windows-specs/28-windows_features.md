> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/Windows.md`


# 28. Windows Native Build Constraints

Dieses Dokument spezifiziert die Einschränkungen und Verträge, um das Toob-Boot Target-Tooling (`keygen`, `sign` etc.) nativ auf einem Windows Host-System ohne eine ausufernde Visual Studio Installation ("Windows Barebones") zu kompilieren.

## 1. Native Windows Build Environment
Toob-Boot lässt sich auf Windows in minimalen Umgebungen kompilieren (nur DOS Command-Prompt oder VS Code).

- [ ] **LLVM & Clang Compiler Pflicht**: Es wird vertraglich verlangt, dass anstelle von Microsofts MSVC-Compiler zwingend die LLVM Compiler-Infrastruktur (`clang.exe`) zur Übersetzung der Host-Tools genutzt wird. Die Installation kann schlank über den Windows Package Manager (Winget) bezogen werden: `winget install -e --id LLVM.LLVM`.

## 2. CMake Integration Contract
Das Build-System (CMake) benötigt auf Windows einen Pointer, da es sonst fälschlicherweise nach C++ Build-Tools auf dem System sucht.

| Konfigurations-Bereich | Vertrag & Invariante |
|------------------------|----------------------|
| `CMakeUserPresets.json` | Der Entwickler **MUSS** eine lokale Preset-Datei anlegen (referenziert über `cmake/preset-examples/CMakeUserPresets.json.sample`). |
| `cacheVariables.HOST_CC` | Die JSON-Zuweisung muss zwingend den absoluten Pfad zur installierten LLVM Executable tragen, damit CMake gezwungen wird, MSVC zu ignorieren. String-Vertrag: `"HOST_CC": "C:/Program Files/LLVM/bin/clang.exe"`. |
