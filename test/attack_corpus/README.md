# Toob-Loader Attack Corpus & Independent Judge Runner

Deklarativer Regressions- und Red-Team-Evaluierungskorpus gemäß [docs/red_team_architecture.md](../../docs/red_team_architecture.md).

## Verzeichnisaufbau eines Attack-Bundles

```text
ATK-XXXX-<chip>-<phase>-<slug>/
  attack.toml      # Metadaten, runner, severity_class (P0..P3), expected_outcome, root_cause_key
  scenario.json    # Deklarative Schrittfolge (kein ausführbarer Host-/Emulator-Code)
  oracle.json      # Maschinelle Verifikationskriterien (UART, Stage-0-SHA256, BPROT, SRAM, Gate)
  payload/         # C-Quellen für bösartige Gast-Apps, Evil-Packages, Flash-/eFuse-Overlays
```

## Anti-Tampering-Regeln für Red-Team-Einreichungen

- **Keine Ziel-Manipulation:** `toobloader/`, `cmake/`, `test/renode_*`, `test/qemu_*`, `scripts/` dürfen vom Red-Team nicht verändert werden (`--verify-clean-target`).
- **Verbotene Payload-Endungen:** `.resc`, `.repl`, `.cs`, `.py`, `.ps1`, `.sh`, `.bat`, `.cmd`, `.exe`, `.dll`, `.so` sowie Symlinks und `..`-Pfadausbrüche werden mit `INVALID_SUBMISSION` abgewiesen.
- **Deduplizierung:** Mehrere PoCs mit identischem `root_cause_key` werden auf den Erstfund dedupliziert (`0` Punkte für Varianten).

## Ausführung

```powershell
# Unit-Tests für Schema, Anti-Tampering & Scoring
python -B -m unittest discover -s test/attack_corpus -p "test_*.py" -v

# Vollständige Phase-0-Regression (Renode nRF52840 + QEMU ESP32-C6 + Build-Gates + Host-SIL)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_attack_corpus.ps1 -Mode regression

# Schneller Host-/Gate-Lauf ohne Emulatoren
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_attack_corpus.ps1 -Mode regression -Quick
```
