# Host-basiertes Testing (Sandbox Setup)

> Wie kompiliere und teste ich Toob-Boot auf x86_64 / ARM64 macOS und Linux ohne jegliche Hardware oder Dev-Boards?

Toob-Boot löst architektonischen Bloat (`#ifdef DEV_MODE`) durch natives GNU `--wrap` Link-Time Mocking. Die Bootloader Core-Logik weiß nicht, ob sie auf echtem Silizium läuft oder in einem Posix-Sandbox-Prozess auf deinem PC iteriert.

## 1. Voraussetzungen

MacOS (via Homebrew):
```bash
brew install gcc cmake llvm
```

Linux (Ubuntu/Debian):
```bash
sudo apt-get install gcc cmake libasan6 libfuzzer-8-dev afl++
```

## 2. Der Sandbox-Build

Wir kompilieren Toob-Boot als Host-Binary (`sandbox` Target). Der Kernel der State-Machine läuft so in Bruchteilen einer Millisekunde durch und generiert Gcov Code-Coverage.

```bash
# Erstellt den CMake Build für den eigenen PC
toob build --target sandbox --build-type Debug

# Führt alle SIL Unit-Integration-Tests aus
./build/sandbox/toob-test-runner
```

## 3. Fuzzing (AFL++)

Da das `core/` komplett frei von statischen Flash-Layern agiert, können wir den `SUIT-Parser` oder `Delta-Patcher` blind mit Trash füttern, um Buffer-Overflows und Malleability aufzudecken.

```bash
# Baut exklusive LibFuzzer-Targets (z.B. fuzz_suit_parser.c)
toob build --target sandbox --fuzz-targets

# Startet den Fuzzer über das SUIT-Manifest Verzeichnis (Corpus)
./build/sandbox/fuzz_suit_parser -max_total_time=3600 ./test/fuzz/corpus/
```

Diesen Command lassen unsere CI-Pipelines nach PR-Merges auf Nightly-Instanzen stundenlang glühen.
