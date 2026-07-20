# Architektur — Chip-Packages der Toob-Registry

**Status:** Zielarchitektur (verabschiedet als Grundlage für BACKLOG-registry-chips.md)
**Scope:** `toob-registry/registry/chips/*` und die Schnittstellen zu `drivers/`, `crypto/`, `arch/`, dem Manifest-Compiler und dem Bootloader-Core. Der Core selbst (`toobloader/`) wird nur dort berührt, wo er Verantwortung *übernimmt* (Bringup-Orchestrierung, ABI v3); seine Sicherheitslogik bleibt unangetastet.

---

## 1. Leitdiagnose

`chip_platform.c` wächst nicht, weil sie zu wenig gesplittet ist, sondern weil sie **drei Rollen mischt**, von denen nur eine legitim chip-spezifischer C-Code ist:

1. **Deklaratives Wiring** — HAL-Trait-Structs mit Funktionspointern und Konstanten befüllen. Das ist reine Datenmontage aus Informationen, die `chip_manifest.json` und `hardware.json` bereits enthalten. Sie gehört *generiert*, nicht handgeschrieben.
2. **Echte Treiber-Implementierungen** — XIP-MMU-Remap, eFuse-Zugriffe, TRNG-Sampling. Das ist legitimer, wachsender Code — aber er gehört in die bestehende Driver-Taxonomie als versionierbare Packages, nicht als Sonderfall in die Chip-Datei.
3. **Init-Orchestrierung** — die geordnete Bringup-Sequenz mit Panic-Mapping. Sie ist bei jedem Chip identisch strukturiert und gehört als Tabellen-Interpreter in den Core, nicht als n-fach kopierte Prozedur in jedes Chip-Package.

Die Zielarchitektur löst `chip_platform.c` entlang dieser drei Linien auf. Endzustand: **die Datei verschwindet fast vollständig**. Ein Chip-Package ist dann eine deklarative Beschreibung plus die unvermeidbaren Quirk-Treiber.

**Architektur-Merksatz:** *Ein Chip-Package beschreibt Hardware. Es implementiert keine Logik, die der Core orchestrieren, ein Driver-Package kapseln oder der Manifest-Compiler generieren kann.*

---

## 2. Package-Taxonomie (Zielbild)

Die Registry kennt sechs Package-Klassen: `chips`, `drivers`, `crypto`, `arch`, `toolchains`, `integrations`. Für dieses Dokument relevant sind die ersten vier.

### 2.1 Chip-Package (Zielzustand)

```
registry/chips/<chip>/
├── chip_manifest.json      # Identität, Versionen, Driver-Referenzen, slot_capabilities
├── hardware.json           # ALLE Adressen, Offsets, Konstanten, Capabilities (Single Source)
├── startup.c               # Pre-C-Runtime: Stack, BSS, WDT-Sterilisierung, Trap-Vector
├── <chip>_stage1.ld        # Nur chip-spezifische Sections; MEMORY kommt aus generated_memory.ld
└── template_device.toml    # Referenz-Gerätekonfiguration (gepinnt, kohärent)
```

**Nicht mehr enthalten:** `chip_platform.c` (generiert), `chip_config.h` (Aliase wandern in den Codegen), Treiber-Implementierungen (eigene Packages), `mock_efuse.c` (Mocking wird zum Build-Profil des OTP-Driver-Packages, siehe §5.4).

### 2.2 Driver-Taxonomie (erweitert)

Bestehend: `drivers/uart/`, `drivers/flash/`, `drivers/wdt/`, `drivers/rtc/`, `drivers/clock/`.

**Neu:**

- `drivers/slot/` — Slot-Transport-Provider. Implementiert die `exec_model`-spezifischen Operationen (`xip_remap_commit`, `bank_flip`, `exec_addr_select`, `get_active_slot`). Mappt 1:1 auf die vier Core-Provider (`swapscratch`, `oneway`, `swapmove`, `pointer`). Beispiel: `drivers/slot/esp_mmu_remap/` ist die pointer-Provider-Bindung für ESP32-C6.
- `drivers/otp/` — Keystore-/OTP-Zugriff: `read_pubkey`, `read_dslc`, `write_dslc`, Monotonic Counter, Provisioning-Burns. Beispiel: `drivers/otp/esp_efuse/`.
- `drivers/entropy/` — (ABI v3, §4.3) TRNG-Quellen mit dokumentierter Sampling-Disziplin.

Jedes Driver-Package trägt: eigene Version, eigenes Manifest, Conformance-Test-Vektor (§6.4), und deklariert, welchen HAL-Trait (und welche ABI-Version) es bedient.

### 2.3 Verantwortungsmatrix

| Artefakt | Verantwortung | Herkunft |
|---|---|---|
| Hardware-Konstanten (Adressen, Offsets, Timings) | `hardware.json` | Hand + Provenance (§3.3) |
| HAL-Trait-Wiring (`boot_platform_t`-Montage) | Manifest-Compiler | generiert |
| Init-Reihenfolge + Panic-Mapping | Core (`boot_platform_bringup`) | Core-Code, Tabelle pro Chip generiert |
| Quirk-Logik (MMU, eFuse, RNG, WDT-Kill) | Driver-Packages | Hand, conformance-getestet |
| Pre-C-Runtime (`_start`) | `startup.c` im Chip-Package | Hand, minimal |
| Geräte-Konfiguration (Partitionen, Policies) | `template_device.toml` / Kunden-TOML | Hand, compiler-validiert |

---

## 3. Format-Standards

### 3.1 `hardware.json` — Schema-Regeln

`hardware.json` ist die **einzige** Quelle für Zahlenwerte. Der Manifest-Compiler validiert gegen ein formales JSON-Schema (CI-Gate, §6.1). Regeln:

**R1 — Einheitliches Zahlenformat.** Adressen und Masken als Hex-String (`"0x50000000"`), Größen/Zähler/Frequenzen als Dezimalzahl. Nie gemischt für dieselbe Größenklasse. (Ist-Verstoß: `"ram_size": "0x8000"` neben `"size": 4194304`.)

**R2 — Alle Offsets ins JSON.** Register-*Basen* und Register-*Offsets* leben beide im JSON. Es ist unzulässig, Basen im JSON und Offsets im C-Header zu halten (Ist-Verstoß: WDT-Offsets `0x48/0x60/0x64` in `chip_config.h`, `rst_cause_offset` im JSON). Schema:

```json
"register_blocks": {
    "timg0_wdt": {
        "base": "0x60008000",
        "regs": { "config0": "0x48", "feed": "0x60", "wprotect": "0x64" }
    }
}
```

**R3 — Capabilities mit Zwei-Ebenen-Semantik.** Jede Crypto-/Peripherie-Capability unterscheidet Silizium-Präsenz von Boot-Nutzbarkeit:

```json
"crypto_capabilities": {
    "sha256": { "hw_present": true, "boot_usable": false,
                "note": "SHA-Peripherie vorhanden, aber keine BootROM-API; Treiber erst ab Phase X" }
}
```

Damit ist der Ist-Widerspruch (`hw_sha256: true` im JSON vs. „no HW SHA on C6 BootROM" im Code vs. `has_hw_acceleration = false`) unrepräsentierbar: der Compiler leitet `has_hw_acceleration` aus `boot_usable` ab, nie aus `hw_present`.

**R4 — Strukturierte Reset-Causes.** Statt flacher `rst_*`-Konstanten eine Map mit semantischem Tag, aus der der Codegen sowohl die Konstanten als auch die Klassifizierung (crash / intentional / power) für `boot_state.c` ableitet:

```json
"reset_causes": {
    "mask": "0x1F", "reg_offset": "0x0410", "reg_block": "pmu",
    "values": {
        "poweron":    { "code": 1,  "class": "power" },
        "sw_sys":     { "code": 3,  "class": "intentional" },
        "tg0wdt":     { "code": 7,  "class": "crash" },
        "brownout":   { "code": 15, "class": "power" }
    }
}
```

**R5 — Reservierte Fest-Adressen deklarieren.** Jede vom Bootloader beschriebene Fest-Adresse außerhalb der Flash-Slots (Confirm-Storage, Handoff-Region, Diag-Region) wird als `reserved_ram_regions`-Eintrag mit Größe deklariert. Der Compiler prüft Overlaps gegen die Linker-Platzierung (§6.3). Das schließt die Bug-Klasse „Confirm-Nonce überschreibt `.noinit`-Handoff" (Ist-Verdacht bei `0x50000000`) strukturell.

### 3.2 `chip_manifest.json` — Schema-Regeln

**R6 — Pins statt „latest".** `min_core_sdk` und `min_compiler` sind konkrete Versionen (`"core/v0.4.0"`, `">=riscv32-esp-elf-13.2"`). `"latest"` als Minimum ist semantisch leer, nicht reproduzierbar und dieselbe Fehlerklasse wie der im CLI gefixte Lockfile-Bypass. Schema lehnt `"latest"` ab.

**R7 — Kohärenz-Regeln (Compiler-enforced).**
- `slot_capabilities.has_scratch == false` ⇒ Geräte-TOMLs mit `enable_deltas = true` sind nur gültig, wenn das gewählte `exec_model` eine deklarierte scratch-lose Delta-Strategie hat; sonst Build-Abbruch mit Erklärtext. (Ist-Verstoß: `template_device.toml` erzwingt Scratch-Generierung auf einem `has_scratch: false`-Chip — exakt der Brutkasten der bestätigten Delta/Scratch-Adresskollision.)
- `slot_capabilities` im Manifest und `slot_caps` im (generierten) Wiring stammen aus derselben Quelle — das Manifest. Doppelpflege entfällt durch Codegen.
- Jeder in `sources.drivers` referenzierte Treiber muss den im `recovery`-Block genannten Treiber-Namen decken oder der Recovery-Treiber ist separat gelistet.

**R8 — Recovery-Krypto ist eine bewusste Entscheidung.** `recovery.crypto.backend = "none"` ist zulässig, aber nur mit Pflichtfeld `justification` (z. B. „Recovery-Image ist Teil des Stage-1-Merkle-Baums und wird vor dem Start durch Stage 1 verifiziert"). Fehlt die Begründung, bricht der Compiler ab. Templates liefern den signierten Default.

### 3.3 Provenance-Metadaten

Jeder Wert in `hardware.json`, der falsch ein Gerät bricken kann (Register, Regionen, Timings), trägt Herkunft:

```json
"provenance": { "source": "trm", "ref": "ESP32-C6 TRM v1.0 §7.3.2", "verified": "2026-05-12" }
```

Zulässige `source`-Werte: `trm` (Technical Reference Manual), `datasheet`, `rom_disasm`, `scan` (toobfuzzer-Blueprint), `vendor_sdk`. Werte mit `source: scan` gelten als **unverifiziert** und erzeugen im Production-Profil eine Compiler-Warnung; der Ist-Zustand („Derived from scan: skipped" als Beschreibung einer reservierten Region) wird damit sichtbar statt still. Nebenwirkung: Das ist CRA-taugliche Evidenz-Traceability für Hardware-Konstanten — die Provenance-Tabelle ist direkt Technical-Documentation-Material für Annex-I-Nachweise.

### 3.4 Sprachpolitik

Die Registry ist öffentliches Material: Code-Kommentare und Manifest-Texte auf **Englisch**. Deutsch bleibt für interne Docs (`docs/`). Ist-Verstöße: `mock_efuse.c` (durchgehend deutsch), einzelne Blöcke in `chip_platform.c`, `esp32c6_write_dslc`.

---

## 4. HAL-Trait-Architektur

### 4.1 Traits und ABI-Stand

`boot_platform_t` bindet heute (ABI v2): `flash`, `confirm`, `crypto`, `clock`, `wdt`, `console`, `soc`, `provisioning`, `slot_caps`. Init-Reihenfolge (normativ, `docs/hals.md`): clock → flash → wdt → crypto → confirm → console → soc. Pflicht-HALs panicken atomar bei Init-Fehlschlag; Console ist optional.

### 4.2 `slot_caps` als tagged union (ABI v2.1)

Ist-Zustand: vier nullable Funktionspointer (`bank_flip`, `xip_remap_commit`, `exec_addr_select`, `get_active_slot`), von denen je nach `exec_model` bis zu drei NULL sind. Die Fehlerklasse „falscher Pointer fürs Modell gesetzt" ist offen. Ziel: union mit `exec_model`-Tag —

```c
typedef struct {
    slot_exec_model_t exec_model;   /* Tag */
    uint8_t  slot_count;
    bool     has_scratch;
    uint32_t scratch_size;
    uint32_t max_erase_cycles;
    boot_status_t (*get_active_slot)(uint32_t *idx);   /* immer Pflicht */
    union {
        struct { boot_status_t (*bank_flip)(void); }                 dualbank;   /* swapmove   */
        struct { boot_status_t (*xip_remap_commit)(uint32_t addr); } xip_remap;  /* pointer    */
        struct { boot_status_t (*exec_addr_select)(uint32_t addr); } addr_select;/* oneway     */
        /* swapscratch: keine Zusatz-Ops — Copy/Swap läuft über flash_hal */
    } ops;
} slot_caps_t;
```

Der Core dispatcht ausschließlich über den Tag; ein Provider kann die Ops des falschen Modells nicht mehr erreichen. Initializer-Makros (§4.4) erzwingen, dass genau der zum Tag passende Zweig befüllt wird.

### 4.3 Crypto-Trait-Entflechtung (ABI v3, mittelfristig)

`crypto_hal_t` mischt heute drei Concerns: **Algorithmen** (hash/verify — Monocypher oder HW), **Keystore/OTP-State** (`read_pubkey`, DSLC, Monotonic Counter) und **Entropie** (`random`). ABI v3 trennt:

- `crypto_hal_t` → nur Algorithmen: `hash_*`, `verify_signature[_ph]`, `verify_pqc`, `get_hash_ctx_size`, `is_pqc_enforced`, `has_hw_acceleration`.
- `keystore_hal_t` → `read_pubkey`, `read_dslc`, `write_dslc`, `read/advance_monotonic_counter` (+ Provisioning-Konsolidierung: `provisioning_hal_t` wird das Burn-Gesicht desselben Driver-Packages).
- `entropy_hal_t` → `random` mit dokumentierter Sampling-Disziplin pro Quelle.

Strategischer Grund über Code-Hygiene hinaus: Die **Zertifizierungs-Profilgrenze** (`default`/`cnsa`/`fips` aus der Zertifizierungsstrategie) verläuft exakt an der Algorithmen-Kante. Wenn der Trait sie sauber schneidet, ist ein Profilwechsel ein reiner `crypto/`-Package-Swap ohne Berührung von Keystore oder Entropie — und die FIPS-Konsum-Story („Toob läuft auf validierter Krypto") wird eine Bindungs-Entscheidung im Manifest statt eines Core-Umbaus.

### 4.4 Initializer-Makros mit ABI-Stempel

Handbefüllte Designated-Initializer driften (sichtbar an der verrutschten `verify_signature_ph`-Zeile). Pro Trait ein Makro, das `abi_version` automatisch setzt, Pflichtfelder als benannte Parameter erzwingt und Optionales explizit macht:

```c
#define TOOB_FLASH_HAL_V2(_init,_deinit,_read,_write,_erase,_secsz, ...) \
    { .abi_version = TOOB_HAL_ABI_V2, .init=(_init), .deinit=(_deinit), \
      .read=(_read), .write=(_write), .erase_sector=(_erase), \
      .get_sector_size=(_secsz), __VA_ARGS__ }
```

Im Endzustand (generiertes Wiring) sind die Makros die Emissions-Zielsprache des Codegens — Handschreiben bleibt für Out-of-Tree-Ports möglich, aber mit demselben Drift-Schutz.

---

## 5. Auflösung von `chip_platform.c`

### 5.1 Slot-Operationen → `drivers/slot/esp_mmu_remap/`

`esp32c6_xip_remap_commit` + `esp32c6_get_active_slot` werden ein Slot-Driver-Package (pointer-Provider-Bindung). Dabei werden die Ist-Defekte behoben: **alle** MMU-/Cache-Register aus `hardware.json` (Ist: nackte Literale `0x60002380`, `0x600C8098` etc. — Konventionsbruch im eigenen Haus), Page-Count und Sync-Size aus `CHIP_APP_SLOT_SIZE` abgeleitet statt fest 6 Pages / 393216 Bytes (Ist: bricht still, sobald ein Kunde `app_size` im TOML ändert), Timeout zeitbasiert über `clock_hal` statt Iterationszähler, Fehlerdomäne korrekt (`BOOT_ERR_STATE`/eigener MMU-Code statt `BOOT_ERR_FLASH_HW`), und `get_active_slot` fail-fast bei nicht klassifizierbarem MMU-Zustand statt stillem Slot-0-Default.

### 5.2 eFuse-Zugriffe → `drivers/otp/esp_efuse/`

`read_pubkey`/`read_dslc`/`write_dslc`/Monotonic + die fünf Provisioning-Stubs werden ein OTP-Driver-Package mit globalen (nicht-`static`) Symbolen. Registeradressen (`EFUSE_BLK_KEY0_DATA0_REG` etc.) aus `hardware.json` (R2). Die Stub-Semantik (NOT_SUPPORTED bis ROM-Call-Integration) bleibt, wird aber im Package-Manifest als Capability deklariert statt nur im Kommentar erwähnt.

### 5.3 Init-Orchestrierung → Core-`boot_platform_bringup`

Der Core erhält einen Tabellen-Interpreter:

```c
typedef struct {
    boot_hal_kind_t kind;        /* CLOCK, FLASH, WDT, CRYPTO, CONFIRM, CONSOLE, SOC */
    bool            mandatory;
    uint16_t        panic_site;  /* eindeutige site_id für Forensik */
} bringup_step_t;

boot_status_t boot_platform_bringup(const boot_platform_t *p,
                                    const bringup_step_t *steps, size_t n);
```

Der Interpreter läuft die Tabelle in Reihenfolge ab, ruft `init()` des jeweiligen Traits, panickt bei Pflicht-Fehlschlag mit dem **schritt-eindeutigen** `panic_site` (Ist-Defekt: Clock, WDT und Confirm panicken alle mit `BOOT_ERR_STATE` — Feld-Forensik kann sie nicht unterscheiden). Die normative Reihenfolge aus `hals.md` ist damit an genau einer Stelle kodiert. Chips liefern nur die Tabelle — und im Endzustand generiert der Compiler auch die.

### 5.4 Mock-Strategie: Struct-Swap statt Linker-Wrap

Ist-Defekt (P0-Klasse): `mock_efuse.c` nutzt `--wrap`, aber die Zielfunktionen sind `static` und werden nur über Funktionspointer im Struct referenziert — der Linker hat keine aufzulösende Referenz, die Wraps greifen **nie**; Sandbox-Builds lasen mutmaßlich echte (leere) eFuse-Register. Zusätzlich divergieren Mock- und Real-Kontrakte (DSLC 32 B vs. 1 B; `key_index`-Rotation nur im Mock).

Ziel-Mechanik: Mocking ist ein **Build-Profil des Driver-Packages**. `drivers/otp/esp_efuse/` liefert zwei TUs — `esp_efuse.c` (real) und `esp_efuse_mock.c` — mit **identischer öffentlicher Symbolliste und identischem Kontrakt**. Das Profil (`TOOB_PROFILE=sandbox|production`) wählt die TU; das Wiring bleibt unverändert. Kontrakt-Äquivalenz (gleiche Längen-Semantik, gleiches `key_index`-Verhalten, gleiche Fehlercodes) wird vom Conformance-Harness erzwungen (§6.4), und das Post-Link-Audit (§6.3) stellt sicher, dass Mock-Symbole ein Production-ELF nie erreichen.

### 5.5 Wiring → `generated_platform_wiring.inc`

Der Manifest-Compiler (emittiert heute `generated_boot_config.h`, `generated_memory.ld`) emittiert zusätzlich das komplette Wiring: Trait-Struct-Instanzen via Initializer-Makros aus den im Manifest referenzierten Driver-Symbolen, die `boot_platform_t`-Montage, die Bringup-Tabelle, und ein minimales `boot_platform_init()`, das nur noch `arch_*_disable_interrupts()` + `boot_platform_bringup()` ruft. `chip_config.h`-Aliase (WDT-Register für `startup.c`, `ADDR_CONFIRM_RTC_RAM`) wandern in den Codegen und der Shim entfällt.

### 5.6 Verbleibende Handarbeit pro Chip

`startup.c` (Pre-C-Runtime, WDT-Sterilisierung, Trap-Vector — echt chip-spezifisch), Linker-*Fragmente* (Sections-Layout; MEMORY generiert), `hardware.json`, `chip_manifest.json`, Quirk-Treiber-Packages. Ein neuer Chip-Port besteht damit aus JSON + Quirks — das ist zugleich das stärkste Onboarding-Argument für Community-Ports.

---

## 6. Verifikations-Gates (CI)

### 6.1 Schema-Validierung
Formale JSON-Schemas für `hardware.json` und `chip_manifest.json`; TOML-Validierung für Templates. Jeder Registry-PR läuft dagegen. Regeln R1–R8 sind maschinell geprüft, nicht Konvention.

### 6.2 Literal-Bann-Lint
CI-Regel für `chips/` und `drivers/`: keine numerischen Literale außer `0`, `1` und offensichtlichen Schleifen-/Shift-Idiomen in Plattform-/Treiber-C-Dateien — jede Adresse, Maske, Größe stammt aus `generated_boot_config.h`. (Hätte die hartkodierten MMU-Register und die 384-KB-Annahme gefangen.) Whitelist-Mechanismus mit Begründungs-Kommentar für die seltenen legitimen Fälle.

### 6.3 Post-Link-ELF-Audit
`nm`/`readelf`-basiertes Skript nach jedem Link, drei Prüfungen: (a) **Mock-Poison-Pill** — keine `*_mock`-/`__wrap_`-Symbole im Production-Profil; (b) **Adress-Overlap** — `.noinit`-/Section-Platzierung gegen alle `reserved_ram_regions` aus `hardware.json` (Confirm-Storage!) auf Überschneidung geprüft; (c) **Budgets** — Sektionsgrößen gegen `stage1_size`/Partitionsgrenzen aus dem Geräte-TOML. Das ist die Registry-Entsprechung der Python-Brownout-Simulationen: billige, erschöpfende Nachweis-Gates statt Hoffnung.

### 6.4 HAL-Conformance-Harness als Registry-Zulassung
Ein Chip-/Driver-Package kommt nur mit grünem Conformance-Lauf in die Registry. Der Harness prüft pro Trait die Vertragssemantik (Fehlercodes, Grenzwerte, Alignment-Verhalten, Timing-Deklarationen vs. Messung wo möglich) und — neu und durch den Mock-Befund motiviert — **Mock/Real-Kontrakt-Äquivalenz**: beide TUs eines Driver-Packages durchlaufen dieselbe Vektor-Suite; Divergenz in Längen-Semantik, Index-Verhalten oder Fehlercodes ist ein Zulassungs-Fail.

### 6.5 Fail-Fast-Invarianten (normativ)
- Fehlende Codegen-Makros sind `#error`, nie stille Defaults. (Ist-Verstoß: `TOOB_DRIVER_UART_BAUDRATE`-Fallback auf `115200U` maskiert einen kaputten Codegen-Lauf.)
- Nicht klassifizierbare Hardware-Zustände sind Fehler, nie Defaults. (Ist-Verstoß: `get_active_slot` defaultet still auf Slot 0.)
- Jede `boot_panic`-Stelle trägt eine eindeutige `panic_site`-ID.
- Entropie-Quellen dokumentieren und implementieren ihre Sampling-Disziplin (Ist-Verstoß: TRNG-Register in enger Schleife gelesen — korrelierte Werte; aus dieser Quelle stammt der `seal_key`). Mindestwartezeit zwischen Reads, zeitbasiert, mit TRM-Referenz im Code.
- Sensitives Material auf dem Stage-1-Stack (`seal_key`) wird vor `jump_to_os` zeroized.

---

## 7. Migrationspfad

Vier Stufen, jede einzeln shipbar, keine Big-Bang-Umstellung:

**Stufe 1 — Korrektheit im Ist-Zustand** (kein Strukturumbau): Mock-Mechanik ersetzen, Overlap 0x50000000 klären, Delta/Scratch-Kohärenzregel, Fail-Fast-Fixes, RNG-Disziplin. Ergebnis: Der heutige Code ist vertrauenswürdig, bevor er bewegt wird.

**Stufe 2 — Extraktion**: Slot- und OTP-Driver-Packages herauslösen (mechanisch, mit den Fixes aus §5.1/5.2). `chip_platform.c` schrumpft auf Wiring + Bringup.

**Stufe 3 — Core-Bringup**: `boot_platform_bringup` in den Core, Chips liefern Tabellen. Panic-Sites werden unterscheidbar.

**Stufe 4 — Generierung + Gates**: Wiring-Codegen, Schemas, Lint, ELF-Audit, Conformance-Zulassung. `chip_platform.c` und `chip_config.h` entfallen.

ABI v3 (Crypto-Trait-Split) läuft als eigener Strang nach Stufe 2, koordiniert mit der Zertifizierungs-Profilarbeit.

---

## 8. Referenzen

- `docs/hals.md` — normative Init-Reihenfolge, Pflicht-HAL-Panik-Regel
- `docs/structure_plan.md` — bisherige Rolle von `chip_platform.c` (wird durch dieses Dokument abgelöst)
- `docs/concept_fusion.md` §6 — Hybrid-Architektur (Bare-Metal + ROM-Pointer)
- `BACKLOG-registry-chips.md` — Umsetzungs-Backlog zu dieser Architektur
- Slot-Transport-Design (vier Provider: swapscratch, oneway, swapmove, pointer) — Grundlage für §2.2/§4.2
- Zertifizierungsstrategie (Profile `default`/`cnsa`/`fips`) — Grundlage für §4.3