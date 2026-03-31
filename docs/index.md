# Toob-Boot Dokumentations-Index

Willkommen in der Dokumentation für **Toob-Boot**, den P10-konformen, ausfallsicheren und Hardware-agnostischen Bootloader.
Dieses Repository beinhaltet die vollständigen Spezifikationen und Architektur-Dokumente.

---

## 🏛️ 1. Kern-Architektur (Die Master-Files)
Diese Dokumente sind die unumstößliche "Single Source of Truth" für die Systementwicklung.

- **[concept_fusion.md](./concept_fusion.md)**
  *Der Master-Blueprint.* Beschreibt die 5-Schichten Struktur, die transaktionale Update-Engine (WAL, TMR), Speicher-Layouts und die P10-Ausfallsicherheit.
- **[hals.md](./hals.md)**
  *Der Hardware-Vertrag.* Definiert exakt die 7 C-Struct Traits (z. B. `flash_hal_t`, `confirm_hal_t`), über die Toob-Boot hardware-unabhängig operiert. Inklusive Versionierung und Glitch-Schutz (`0x55AA55AA`).

## 🛠️ 2. Sub-Spezifikationen (Deep-Dives)
Ausgelagerte Spezifikationen für spezifische Teilsysteme.

- **[libtoob_api.md](./libtoob_api.md)** — C-Interface für das Feature-OS (`.noinit` Handshake, Confirm-Boot).
- **[stage_1_5_spec.md](./stage_1_5_spec.md)** — Notfall-Bootloader-Recovery (Schicht 4a) via UART, COBS, XMODEM und 2FA-Handshake.
- **[merkle_spec.md](./merkle_spec.md)** — Chunk-basierte Streaming-Verifikation des SUIT-Manifests zur Maximierung der SRAM-Effizienz.

## 🏭 3. Lifecycle, Ops & Testing
Richtlinien für Factory-Onboarding, Qualitätssicherung und den Entwickler-Alltag.

- **[getting_started.md](./getting_started.md)** — Developer Quickstart (Toolchain Installer, Kompilieren, Flashen).
- **[provisioning_guide.md](./provisioning_guide.md)** — Vorgaben für OEM-Fabriken (eFuses brennen, JTAG Hard-Lock, Einspielen der Hardware-Identität).
- **[testing_requirements.md](./testing_requirements.md)** — NASA P10 Compliance Metriken, HIL-Simulationen (Hardware In Loop) und Link-Time-Mocking Constraints.

## ⚙️ 4. Tooling & Generatoren
Dokumente, die die Integration externer Tools (`Toobfuzzer3`, `Repowatt CLI`) behandeln.

- **[toobfuzzer_integration.md](./toobfuzzer_integration.md)**
  Erklärt die Magie hinter der `chip_config.h`. Wie die Hardware-Parameter aus dem Toobfuzzer (`aggregated_scan.json` / `blueprint.json`) über das Plugin-System (*Manifest Compiler*) zur Compile-Zeit direkt als Makros verdrahtet werden.

---

## 🗄️ 5. Archiv & Historische Referenzen
Dokumente, die während der Planungsphase essenziell waren, aber nun primär in den Master-Files (`concept_fusion.md` / `hals.md`) aufgegangen sind.

- **[structure_plan.md](./structure_plan.md)** *[Referenz]*
  Beinhaltete den initialen Repository-Verzeichnisbaum und die Idee der "Vendor/Arch/Chip"-Ebenen. Gilt strukturell noch als Leitfaden für Ordner, inhaltlich aber durch `hals.md` abgelöst.
- **[request.md](./request.md)** *[Historisch / Veraltet]*
  Der ursprüngliche LLM-Prompt für die "Stage 4 Injection" des Toobfuzzers. Da diese Pipeline mittlerweile aktiv ist, ist dieses Planungsdokument obsolet.
- **`analysis/`** (Ordner) *[Archiv]*
  Beinhaltet alle Gap-Analysen, die zur Härtung geführt haben (Der P10-Audit-Trail).
