Hier ist der priorisierte Fixplan, geordnet nach Abhängigkeiten und Schweregrad.

---

## Phase 1: Compile-Breaker & funktionale Defekte (sofort)

### Schritt 1 — Finding #8: `boot_identity.c` API-Mismatch

Das Problem: `boot_identity.c` ruft `hash_init(&ctx)` mit 1 Argument und `hash_finalize(ctx, out_id)` auf, aber `crypto_hal_t` definiert `hash_init(void *ctx, size_t ctx_size)` und `hash_finish(void *ctx, uint8_t *digest, size_t *digest_len)`. Die Funktion `hash_finalize` existiert gar nicht im HAL.

**Konkrete Schritte:**

1. `boot_identity.c` öffnen und die Stack-basierte Context-Allokation analog zu `boot_merkle.c` umbauen — also einen `uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE]` auf dem Stack anlegen statt eines `void *ctx = NULL`.

2. Alle Aufrufe korrigieren:
   - `hash_init(&ctx)` → `hash_init(hash_ctx, sizeof(hash_ctx))`
   - `hash_update(ctx, ...)` → `hash_update(hash_ctx, ...)`
   - `hash_finalize(ctx, out_id)` → `hash_finish(hash_ctx, out_id, &digest_len)` mit einer vorab deklarierten `size_t digest_len = 32`

3. Den Capability-Check am Funktionsanfang anpassen: `hash_finalize` durch `hash_finish` ersetzen und `get_hash_ctx_size` als optionalen Guard hinzufügen (wie in `boot_merkle.c`).

4. `boot_secure_zeroize(hash_ctx, sizeof(hash_ctx))` vor dem Return einfügen.

5. Sandbox-Build mit `-Werror -Wstrict-prototypes` verifizieren — der Build muss jetzt sauber durchlaufen.

---

### Schritt 2 — Finding #10: Use-After-Overwrite im Delta-Pfad (`boot_state.c`)

Das Problem: In `_handle_update_flow` zeigt `chunk_hashes->value` in die `crypto_arena`. Nach `boot_delta_apply()` wird die Arena genullt (`boot_secure_zeroize` im Cleanup von `boot_delta.c`). Der anschließende `boot_merkle_verify_stream`-Aufruf liest genullte Hashes — Delta-Updates mit Merkle-Verifikation schlagen immer fehl.

**Konkrete Schritte:**

1. In `_handle_update_flow` (boot_state.c), unmittelbar vor dem `boot_delta_apply`-Aufruf, die Chunk-Hashes aus der Arena in einen dedizierten Stack-Buffer kopieren:

```c
/* VOR boot_delta_apply: Chunk-Hashes retten */
uint8_t saved_chunk_hashes[num_chunks * 32];  // oder dynamisch begrenzt
size_t saved_hashes_len = chunk_hashes->len;
```

Da Stack-Allokation mit variabler Länge P10-widrig ist, stattdessen einen festen Buffer verwenden. Die maximale Anzahl Chunks ist durch `CHIP_APP_SLOT_SIZE / chunk_sz` begrenzt. Pragmatischer Ansatz: Die Hashes in den **oberen Teil der Arena** kopieren, den `boot_delta_apply` nicht überschreibt — dafür die Arena-Partitionierung in `boot_delta.c` anpassen, sodass die Hashes oberhalb des `hsd + write_buf + read_buf` Bereichs liegen.

2. Besser: Einen dedizierten Stack-Buffer mit statisch begrenzter Größe einführen. Da `num_chunks * 32` bei typischen 4KB-Chunks und 256KB-Images maximal `64 * 32 = 2048` Bytes beträgt, ist ein `uint8_t saved_hashes[2048]` auf dem Stack vertretbar:

```c
_Static_assert(CHIP_APP_SLOT_SIZE / 4096 * 32 <= 2048,
    "Saved hash buffer too small for max chunk count");

uint8_t saved_hashes[2048] __attribute__((aligned(8)));
boot_secure_zeroize(saved_hashes, sizeof(saved_hashes));
if (chunk_hashes->len > sizeof(saved_hashes)) {
    verify_status = BOOT_ERR_INVALID_ARG;
} else {
    memcpy(saved_hashes, chunk_hashes->value, chunk_hashes->len);
}
```

3. Den `boot_merkle_verify_stream`-Aufruf nach `boot_delta_apply` auf `saved_hashes` statt `chunk_hashes->value` umbiegen.

4. `boot_secure_zeroize(saved_hashes, sizeof(saved_hashes))` am Ende einfügen.

5. Einen Integrationstest schreiben, der einen Delta-Patch gefolgt von Merkle-Verifikation durchläuft und `BOOT_OK` erwartet.

---

### Schritt 3 — Finding #7: crypto_arena Aliasing in `boot_cloud_cmd.c`

Das Problem: `boot_cloud_cmd_evaluate_flash` übergibt `crypto_arena` sowohl als `envelope_buf` (Input) und als `crypto_arena` (Arbeits-Buffer) an `evaluate_buffer`. Innerhalb von `evaluate_buffer` könnte `boot_derive_device_id` die Arena überschreiben, bevor die Signaturprüfung die Envelope-Daten gelesen hat.

**Konkrete Schritte:**

1. In `boot_cloud_cmd_evaluate_flash` die Arena in zwei disjunkte Zonen aufteilen:

```c
size_t envelope_zone = max_read;
size_t work_zone_offset = (envelope_zone + 7) & ~((size_t)7); /* 8-Byte align */
if (work_zone_offset + 256 > BOOT_CRYPTO_ARENA_SIZE) {
    return BOOT_ERR_INVALID_ARG;
}
uint8_t *work_arena = crypto_arena + work_zone_offset;
size_t work_arena_size = BOOT_CRYPTO_ARENA_SIZE - work_zone_offset;
```

2. Den Aufruf ändern:

```c
boot_status_t result = boot_cloud_cmd_evaluate_buffer(
    platform, crypto_arena, max_read, work_arena, out_cmd);
```

3. Die Signatur von `boot_cloud_cmd_evaluate_buffer` anpassen ist **nicht nötig**, da der vierte Parameter bereits `uint8_t *crypto_arena` heißt und als separater Arbeits-Buffer gedacht ist — das Problem ist ausschließlich, dass der Aufrufer denselben Pointer übergibt.

4. In `evaluate_buffer` sicherstellen, dass `boot_derive_device_id` den `crypto_arena`-Parameter nutzt und nicht den `envelope_buf`-Speicher berührt. Da `boot_derive_device_id` nur Stack-lokale Variablen und den HAL verwendet, ist das bereits der Fall — der Fix liegt rein im Aufrufer.

5. Einen Kommentar am Aufruf hinterlassen, der das Aliasing-Verbot dokumentiert.

---

## Phase 2: HAL-Contract-Härtung (Woche 1-2)

### Schritt 4 — Finding #4: Monotonic Counter ohne Komplement-Prüfung

Vier Stellen lesen den Counter blind ohne Wert-Validierung. Die Mitigation gehört in den HAL-Contract, nicht ad-hoc in jeden Aufrufer.

**Konkrete Schritte:**

1. In `crypto_hal_t` (`boot_hal.h`) den Contract als Doxygen-Kommentar verankern:

```c
/**
 * @brief Read hardware monotonic counter.
 * HAL-Contract: Die Implementierung MUSS den gelesenen Wert intern
 * durch Komplement-Prüfung (read + read_inverted) validieren und
 * bei Diskrepanz BOOT_ERR_VERIFY zurückgeben.
 */
boot_status_t (*read_monotonic_counter)(uint32_t *ctr);
```

2. Eine Wrapper-Funktion im Core einführen (`boot_ct_utils.h` oder eigene Datei):

```c
static inline boot_status_t boot_read_monotonic_counter_safe(
    const boot_platform_t *platform, uint32_t *out_ctr)
{
    if (!platform->crypto->read_monotonic_counter)
        return BOOT_ERR_NOT_SUPPORTED;

    uint32_t val1 = 0, val2 = 0;
    boot_status_t s1 = platform->crypto->read_monotonic_counter(&val1);
    BOOT_GLITCH_DELAY();
    boot_status_t s2 = platform->crypto->read_monotonic_counter(&val2);

    volatile uint32_t shield_1 = 0, shield_2 = 0;
    if (s1 == BOOT_OK && s2 == BOOT_OK && val1 == val2)
        shield_1 = BOOT_OK;
    BOOT_GLITCH_DELAY();
    if (shield_1 == BOOT_OK && s1 == BOOT_OK && s2 == BOOT_OK && val1 == val2)
        shield_2 = BOOT_OK;

    if (shield_1 != BOOT_OK || shield_2 != BOOT_OK)
        return BOOT_ERR_VERIFY;

    *out_ctr = val1;
    return BOOT_OK;
}
```

3. Alle vier Aufrufstellen ersetzen:
   - `boot_cloud_cmd.c` Zeile mit `read_monotonic_counter(&current_counter)` → `boot_read_monotonic_counter_safe(platform, &current_counter)`
   - `boot_panic.c` → gleicher Austausch
   - `boot_rollback.c` → `read_monotonic_counter(&efuse_epoch)` ersetzen
   - `stage0_otp.c` → `read_monotonic_counter(&epoch)` ersetzen

4. Jeden Aufruf mit Return-Code-Check versehen (die meisten ignorieren bisher den Return-Wert).

---

### Schritt 5 — Finding #6: TRNG Health Checks als HAL-Contract

**Konkrete Schritte:**

1. In `crypto_hal_t` den `random`-Function-Pointer um einen Contract-Kommentar erweitern:

```c
/**
 * @brief Generate cryptographic random bytes.
 * HAL-Contract: Die Implementierung MUSS NIST SP 800-90B
 * Repetition Count und Adaptive Proportion Tests intern
 * durchführen. Bei Versagen: BOOT_ERR_CRYPTO zurückgeben.
 */
boot_status_t (*random)(uint8_t *buf, size_t len);
```

2. Optional einen Basis-Health-Check im Core als Defense-in-Depth einfügen — direkt nach dem `random`-Aufruf in `boot_panic.c` (Challenge) und `boot_state.c` (Nonce):

```c
/* Post-TRNG Sanity: Nicht alle Bytes identisch? */
uint8_t or_acc = 0;
for (size_t i = 0; i < 32; i++) or_acc |= challenge_buf[i];
if (or_acc == 0x00 || or_acc == 0xFF) {
    enter_sos_loop(platform); /* TRNG defekt */
}
```

3. In der HAL-Dokumentation (`docs/hals.md`) die SP 800-90B Anforderung als verpflichtend für Vendor-Ports dokumentieren.

---

## Phase 3: Systemische Timing-Orakel-Beseitigung (Woche 2-3)

### Schritt 6 — Finding #2: Smart-Erase Timing-Orakel (4+ Stellen)

Das Early-Break-Pattern beim Erase-Pre-Check leckt Flash-Inhalte über Timing.

**Konkrete Schritte:**

1. Eine gemeinsame `is_fully_erased_constant_time`-Funktion definieren (existiert bereits in `boot_panic.c`, muss in `boot_ct_utils.h` oder eine eigene Datei verschoben werden):

```c
static inline bool is_fully_erased_constant_time(
    const uint8_t *buf, size_t len, uint8_t erased_val)
{
    uint32_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint32_t)(buf[i] ^ erased_val);
    }
    return diff == 0;
}
```

2. In allen vier betroffenen Stellen den Early-Break durch den Akkumulator ersetzen:
   - **`boot_journal.c` → `smart_erase_sector()`**: Die `while`-Schleife mit `break` durch vollständigen Scan ersetzen. Das `needs_erase`-Flag wird per OR-Akkumulator gesetzt statt per `break`.

   - **`boot_swap.c` → `_boot_swap_erase_tracked()`**: Gleicher Umbau.

   - **`boot_delta.c` → `flush_target_buffer()`**: Gleicher Umbau.

   - **`boot_panic.c`**: Nutzt bereits `is_fully_erased_constant_time`, aber der umgebende Loop hat noch ein `break` bei Flash-Read-Fehlern. Der Read-Error-`break` ist akzeptabel (leckt keine Daten), aber für Konsistenz den Akkumulator-Stil anwenden.

3. Jede Stelle mit einem Inline-Kommentar versehen: `/* P10 Timing-Oracle Defense: Full-scan accumulator, no early exit */`

4. Performance-Impact dokumentieren: Der vollständige Scan kostet pro Sektor maximal `sec_size / 64` zusätzliche Reads. Bei 4KB-Sektoren sind das 64 Reads à 64 Bytes — vernachlässigbar gegenüber dem Erase selbst (~20ms).

---

### Schritt 7 — Finding #11: `memcmp` in `boot_swap.c`

**Konkrete Schritte:**

1. In `boot_swap.c` den Identity-Check-Block finden:

```c
if (memcmp(buf_dst, buf_src, step) != 0) {
    is_identical = false;
    break;
}
```

2. Ersetzen durch:

```c
if (constant_time_memcmp_glitch_safe(buf_dst, buf_src, step) != BOOT_OK) {
    is_identical = false;
    break;
}
```

3. Sicherstellen, dass `#include "boot_ct_utils.h"` am Dateianfang steht (ist bereits vorhanden).

4. Das `break` hier ist architektonisch akzeptabel — es entscheidet nur, ob kopiert wird, und der Timing-Unterschied zwischen "identisch" und "verschieden" ist ohnehin durch den nachfolgenden Erase/Write sichtbar. Der Fix ist primär für architektonische Konsistenz.

---

## Phase 4: Stage-0-Härtung (Woche 3)

### Schritt 8 — Finding #9: DSLC=0x00 Dev-Bypass in Stage 0

**Konkrete Schritte:**

1. In `stage0_main.c` den Dev-Bypass-Block in ein Compile-Time-Gate wrappen:

```c
#ifndef TOOB_ALLOW_DEV_BYPASS
  #ifdef NDEBUG
    #error "TOOB_ALLOW_DEV_BYPASS must be explicitly enabled for production builds"
  #endif
  #define TOOB_ALLOW_DEV_BYPASS 0
#endif

/* ... */

if (platform->crypto->read_pubkey(pubkey, 32, key_idx) != BOOT_OK) {
#if TOOB_ALLOW_DEV_BYPASS
    if (confirmed_dslc == 0x00) {
        is_dev_bypass = true;
    } else {
        dead_halt();
    }
#else
    dead_halt(); /* Produktionsmodus: Kein Bypass möglich */
#endif
}
```

2. Im CMake-System (`toob_stage0.cmake`) das Define nur für Sandbox/Debug setzen:

```cmake
if(TOOB_ARCH STREQUAL "host" OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(toob_stage0 PRIVATE TOOB_ALLOW_DEV_BYPASS=1)
endif()
```

3. Die DSLC-Majority-Reads mit zeitversetztem Jitter absichern. Zwischen den 5 Reads in der `for`-Schleife einen TRNG-basierten Delay einfügen:

```c
for (int round = 0; round < 5 && !dslc_found; round++) {
    /* Anti-Sustained-Glitch: Randomisierter Delay zwischen Reads */
    if (round > 0 && platform->crypto->random) {
        uint8_t jitter = 0;
        platform->crypto->random(&jitter, 1);
        for (volatile uint32_t d = 0; d < (uint32_t)(jitter & 0x3F); d++) {
            BOOT_GLITCH_DELAY();
        }
    }
    /* ... bestehender Read-Code ... */
}
```

---

## Phase 5: Krypto-Hardening (Woche 3-4)

### Schritt 9 — Finding #3: Krypto-Blackbox Double-Execution

Die Double-Execution mit randomisiertem Delay ist architektonisch korrekt und bereits im Code implementiert (Double-Check-Pattern überall). Für Stage 0 muss die Abwägung dokumentiert werden.

**Konkrete Schritte:**

1. In `docs/security_model.md` (oder äquivalent) einen Abschnitt "Crypto Verification Trust Model" hinzufügen, der dokumentiert:
   - Stage 1 (`boot_verify.c`, `boot_cloud_cmd.c`, `boot_panic.c`): Double-Check-Pattern mit `BOOT_GLITCH_DELAY()` — bereits implementiert.
   - Stage 0 (`stage0_verify.c`): Double-Check-Pattern ebenfalls implementiert. Eine vollständige Double-Execution (zwei separate `verify_ed25519`-Aufrufe) wird für Stage 0 bewusst nicht implementiert, da das 4-8KB Flash-Budget keine zweite Krypto-Ausführung erlaubt. Das Risiko wird durch den Double-Check auf das Ergebnis mitigiert.

2. Für Stage 1 optional eine echte Double-Execution einführen (in `boot_verify.c`):

```c
/* Optional: Full double-execution for highest assurance */
boot_status_t verify_stat_2 = platform->crypto->verify_ed25519(
    work_buffer, local_env.manifest_size,
    local_env.signature_ed25519, root_pubkey);

if (verify_stat != verify_stat_2) {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
}
```

Dies erhöht die Boot-Zeit um ~30-50ms (Ed25519 auf Cortex-M4). Dokumentieren und per `TOOB_DOUBLE_VERIFY` konfigurierbar machen.

---

### Schritt 10 — Finding #5: SRAM-Manipulation / CFI-Token-Randomisierung

**Konkrete Schritte:**

1. In `boot_state.c` am Anfang von `boot_state_run` die CFI-Tokens aus dem TRNG ableiten:

```c
uint32_t cfi_seed = 0;
if (platform->crypto->random) {
    platform->crypto->random((uint8_t *)&cfi_seed, sizeof(cfi_seed));
}
/* Tokens werden zur Laufzeit berechnet, Angreifer kann Zielwert nicht vorab kennen */
uint32_t cfi_step_1 = cfi_seed ^ 0x11111111;
uint32_t cfi_step_2 = cfi_seed ^ 0x22222222;
/* ... etc. */
```

2. Da dies eine architektonische Verbesserung ist, die alle CFI-Stellen betrifft (boot_state.c, boot_main.c, boot_verify.c, boot_cloud_cmd.c, boot_delta.c, boot_rollback.c, boot_multiimage.c), als **separaten Feature-Branch** implementieren. Die Komplexität ist hoch, da jede `expected_path`-Berechnung ebenfalls dynamisch werden muss.

3. Pragmatischer Zwischenschritt: Die statischen CFI-Konstanten mindestens aus `.rodata` in den Stack verschieben, damit ein Angreifer sie nicht vorab aus dem Flash auslesen kann.

---

### Schritt 11 — Finding #1: Power-Cycle Bypass

Bereits korrekt analysiert und isoliert auf `boot_panic.c`. Die Mitigation (RTC-Backup-Register oder deterministischer Boot-Delay) ist im Analyse-Dokument beschrieben.

**Konkrete Schritte:**

1. In `boot_panic.c` nach dem `session_reset`-Label den `failed_auth_attempts`-Zähler ins RTC-Backup-Register persistieren (falls verfügbar):

```c
if (platform->soc && platform->soc->write_rtc_backup) {
    platform->soc->write_rtc_backup(RTC_SLOT_AUTH_ATTEMPTS, failed_auth_attempts);
}
```

2. Beim Eintritt in `boot_panic` den Zähler aus dem RTC-Register laden:

```c
if (platform->soc && platform->soc->read_rtc_backup) {
    platform->soc->read_rtc_backup(RTC_SLOT_AUTH_ATTEMPTS, &failed_auth_attempts);
}
```

3. Falls kein RTC-Backup verfügbar: Den deterministischen Boot-Delay über `boot_delay_with_wdt` mit einem Minimum von 5 Sekunden beim Eintritt in `boot_panic` erzwingen, unabhängig vom Auth-Attempt-Counter.

---

## Zusammenfassung der Reihenfolge

| Woche | Schritt | Finding | Kategorie                | Aufwand |
| ----- | ------- | ------- | ------------------------ | ------- |
| 0     | 1       | #8      | Compile-Breaker          | 1h      |
| 0     | 2       | #10     | Korrektheit              | 3h      |
| 0     | 3       | #7      | Korrektheit              | 1h      |
| 1     | 4       | #4      | Hardening                | 3h      |
| 1     | 5       | #6      | Hardening                | 2h      |
| 2     | 6       | #2      | Hardening                | 4h      |
| 2     | 7       | #11     | Cleanup                  | 30min   |
| 3     | 8       | #9      | Hardening                | 2h      |
| 3     | 9       | #3      | Dokumentation + optional | 2-4h    |
| 4     | 10      | #5      | Hardening (Architektur)  | 8h      |
| 4     | 11      | #1      | Hardening                | 2h      |

Schritte 1-3 sind blockernd und sollten vor dem nächsten Sandbox-Build abgeschlossen sein. Schritte 4-7 können parallel bearbeitet werden. Schritte 8-11 sind unabhängig voneinander.
