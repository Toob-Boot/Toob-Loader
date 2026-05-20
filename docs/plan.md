Hier ist mein Vorschlag für die Implementierungsreihenfolge, optimiert auf minimale Merge-Konflikte und maximale Testbarkeit nach jeder Phase.

---

## Phase 1: ABI-Fundament (Types, TMR, Handoff)

**Warum zuerst:** Jede spätere Phase baut auf diesen Typen und Struct-Layouts auf. Fehler hier propagieren in alles.

**Kritische Dateien:**

`common/include/boot_types.h` — Neue Enums (`toob_cloud_cmd_t`, `BOOT_ERR_DEVICE_LOCKED`, `BOOT_ERR_CMD_REPLAY`, `BOOT_ERR_CMD_DEVICE_MISMATCH`), neuer WAL-Intent (`WAL_INTENT_CLOUD_CMD = 12`, `WAL_INTENT_DEVICE_LOCKED = 13`). Agent muss die Hamming-Distance-Konvention der Error-Codes strikt einhalten und die bestehenden `_Static_assert`-Ketten nicht brechen.

`toobloader/core/include/boot_journal.h` — `wal_tmr_payload_t` wächst um `uint32_t kdm_sequence` und `uint32_t active_kdm_slot`. Die `_Static_assert(sizeof(wal_tmr_payload_t) == 40, ...)` muss auf den neuen Wert (48) aktualisiert werden. **Höchste Vorsicht:** Der `wal_sector_header_t` enthält die TMR inline und hat ebenfalls eine harte Size-Assert auf 64 Bytes. Die `_padding[8]` muss um die 8 zusätzlichen TMR-Bytes schrumpfen oder der Header wächst — beides hat Kaskadeneffekte auf das gesamte WAL-Layout.

`sdk/libtoob/include/libtoob_types.h` — `toob_handoff_t` bekommt `uint8_t device_id[32]` und `uint8_t wipe_requested`. Die Size-Assert (aktuell 40) und der `crc32_trailer`-Offset-Assert müssen synchron aktualisiert werden. `TOOB_HANDOFF_STRUCT_VERSION` geht auf `0x02000000`. Parallel die `toob_wal_sector_header_t` mit dem `_reserved_tmr_space` anpassen (aktuell 40 Bytes, muss zum neuen TMR passen).

`common/include/boot_hal.h` — `crypto_hal_t` bekommt den neuen Pflicht-Pointer `read_chip_uid`. Optional: `provisioning_hal_t` als neues Struct definieren (kann aber auch Phase H sein).

**Validierung nach Phase 1:** Sandbox-Build (`TOOB_ARCH=host`) muss sauber kompilieren. Alle `_Static_assert`s in `boot_journal.h`, `libtoob_types.h` und `boot_types.h` müssen passen. Bestehende Sandbox-Tests dürfen nicht brechen.

---

## Phase 2: Stage 0 DSLC-Gate

**Warum hier:** Unabhängig von allen anderen Phasen, kleiner Scope, sofort testbar. Blockiert keine anderen Arbeiten.

**Kritische Dateien:**

`toobloader/stage0/stage0_main.c` — Der Majority-Vote DSLC-Check wird **nach** `platform->crypto->init()` und **vor** `stage0_get_active_slot()` eingefügt. Agent muss beachten, dass `stage0_main.c` einen eigenen `boot_panic`-Stub hat (kein echtes Panic-System). Die neue `dead_halt()` muss als `_Noreturn static void` in dieselbe Datei. Der Development-Mode-Bypass (DSLC=0x00 + kein Key) greift in die existierende Signatur-Prüfung bei Punkt 8 ein.

`toobloader/stage0/include/stage0_crypto.h` — Keine neue Funktion nötig, `read_dslc` kommt über `platform->crypto`.

**Achtung:** Stage 0 hat keinen Zugriff auf `boot_journal.h` oder die WAL-Infrastruktur. Der Agent darf keine Core-Header einziehen. Stage 0 nutzt ausschließlich `boot_types.h`, `boot_hal.h`, `boot_crc32.h` und seinen eigenen `stage0_crypto.h`.

---

## Phase 3: CDDL-Schema + zcbor-Codegen

**Warum hier:** Die C-Strukturen für Cloud-Commands müssen existieren, bevor `boot_cloud_cmd.c` geschrieben werden kann.

**Kritische Dateien:**

Neue CDDL-Datei (z.B. `cddl/toob_cloud_cmd.cddl`) — Das Schema aus dem Plan. Agent muss sicherstellen, dass das zcbor-Codegen-Tooling (referenziert in `cmake/toob_core.cmake` unter `generate_manifest`) diese Datei mit aufnimmt.

`cmake/toob_core.cmake` — Der `add_custom_command` für `generate_manifest` muss den neuen CDDL-Input verarbeiten und `boot_cloud_cmd_types.h` / `boot_cloud_cmd_decode.c` generieren. Alternativ die Go-CLI erweitern.

`CMakeLists.txt` — Die neue `TOOB_FEATURE_CLOUD_COMMANDS`-Option einfügen, die `boot_cloud_cmd.c` bedingt kompiliert.

---

## Phase 4: Device-ID Derivation

**Warum hier:** Wird von Phase 5 (Cloud-Command-Verifikation) als Device-ID-Match benötigt, hat aber selbst keine Abhängigkeit auf die Command-Pipeline.

**Kritische Dateien:**

Neue Datei `toobloader/core/boot_identity.c` + `toobloader/core/include/boot_identity.h` — Implementiert `boot_derive_device_id(platform, out_id[32])`. Nutzt `platform->crypto->read_chip_uid()`, `platform->crypto->read_pubkey()` (Index 0), und `platform->crypto->hash_*()`. Agent muss den Domain-Separator-String `"toob-device-id-v1"` exakt wie spezifiziert einhashen.

`toobloader/core/boot_main.c` — In Block 5 (Handoff) die Device-ID berechnen und in `local_handoff.device_id` schreiben. **Vorsicht:** Die `boot_diag_seal()` und der Handoff-CRC müssen nach dem neuen Feld berechnet werden.

`sdk/libtoob/toob_handoff.c` — `toob_get_handoff()` und `toob_validate_handoff()` müssen die neue Struct-Größe und den neuen `TOOB_HANDOFF_STRUCT_VERSION` korrekt prüfen. Hier liegt ein subtiler Migrationspunkt: Geräte im Feld mit Version `0x01000000` dürfen nicht hart abstürzen. Der Agent sollte einen Fallback einbauen.

---

## Phase 5: `boot_cloud_cmd.c` (Kern der Killswitch-Logik)

**Warum hier:** Alle Abhängigkeiten (Types, CDDL-Parser, Device-ID, KDM-Konzept) sind jetzt da.

**Kritische Dateien:**

Neue Datei `toobloader/core/boot_cloud_cmd.c` + `toobloader/core/include/boot_cloud_cmd.h` — Die komplexeste neue Datei. Agent muss strikt das Sequencing-Protokoll einhalten (Parse → Device-ID → Counter → Verify → Advance → Dispatch). Jeder Schritt vor dem Counter-Advance darf **keinen** Seiteneffekt haben. Die KDM-Lade-Logik (A/B-Slot mit TMR-Sequenz-Check) ist eine eigene Subfunktion. Der Agent muss das bestehende Glitch-Shield-Pattern (Double-Check + `BOOT_GLITCH_DELAY()` + CFI-Akkumulator) konsistent anwenden — exakt wie in `boot_verify.c` und `boot_rollback.c`.

`toobloader/core/boot_panic.c` — Der `BOOT_ERR_DEVICE_LOCKED`-Reason muss den Firmware-Flash-Pfad in Block 3 sperren, aber den 2FA-Auth-Pfad (Block 2) weiterhin erlauben, mit der Erweiterung, dass nach erfolgreicher Auth ein UNLOCK-Envelope erwartet wird statt eines Firmware-Streams.

**Besondere Risiken:** Die `crypto_arena` wird von `boot_cloud_cmd.c` exklusiv beansprucht (Zero-Allocation). Der Agent muss sicherstellen, dass kein anderer Code gleichzeitig die Arena nutzt. Da Cloud-Commands vor der Update-Pipeline evaluiert werden, ist das sequenziell sicher — aber nur, wenn die Arena vor Rückgabe gesäubert wird (`boot_secure_zeroize`).

---

## Phase 6: `boot_state.c` Integration

**Warum hier:** Die Command-Pipeline steht, jetzt wird sie in den Orchestrator eingehängt.

**Kritische Dateien:**

`toobloader/core/boot_state.c` — Zwei neue Schritte zwischen Step 2 und Step 3:

Step 2.5: `_handle_cloud_cmd()` — Liest `CHIP_CLOUD_CMD_SLOT`, ruft `boot_cloud_cmd_evaluate()` auf. Bei `TOOB_CMD_KILLSWITCH` schreibt es `WAL_INTENT_DEVICE_LOCKED`. Bei `TOOB_CMD_FORCE_UPDATE` schreibt es `WAL_INTENT_UPDATE_PENDING` (und die normale Pipeline in Step 4 übernimmt). Der CFI-Akkumulator `state_cfi` braucht einen neuen Token (`CFI_STEP_2_5`). **Das ist der heikelste Eingriff:** Der Agent muss den `expected_cfi` am Ende von `state_cleanup` um den neuen Token erweitern und sicherstellen, dass der Token auch bei Skip-Pfaden (kein Command vorhanden) korrekt XOR'd wird.

Step 2.7: Lock-State-Check — Prüft ob `WAL_INTENT_DEVICE_LOCKED` der aktive Intent ist. Wenn ja, nur UNLOCK akzeptieren, sonst → `boot_panic(BOOT_ERR_DEVICE_LOCKED)`.

`toobloader/core/include/boot_state.h` — Kein neues Public-API nötig, aber der Lifecycle-Kommentar muss aktualisiert werden.

---

## Phase 7: libtoob OS-API + Handoff-Erweiterung

**Warum hier:** Die Bootloader-Seite ist fertig, jetzt die OS-Boundary.

**Kritische Dateien:**

`sdk/libtoob/include/libtoob.h` — Neue Funktionen: `toob_submit_cloud_command()`, `toob_get_device_id()`, `toob_is_device_locked()`.

Neue Datei `sdk/libtoob/toob_cloud_submit.c` — Schreibt den Envelope in `CHIP_CLOUD_CMD_SLOT` via `toob_os_flash_erase()` + `toob_os_flash_write()` mit CRC-Read-Back. Danach `toob_wal_naive_append()` mit `TOOB_WAL_INTENT_CLOUD_CMD`. Der Agent muss die bestehende `toob_wal_naive.c`-Lock-Logik beachten: `WAL_INTENT_CLOUD_CMD` darf parallel zu einem `WAL_INTENT_UPDATE_PENDING` existieren (unterschiedliche Slots).

`sdk/libtoob/include/libtoob_config_sandbox.h` — Neue Makros für `CHIP_CLOUD_CMD_SLOT`, `CHIP_KDM_SLOT_A`, `CHIP_KDM_SLOT_B`.

---

## Phase 8: Provisioning-HAL + CLI-Integration

**Warum hier:** Hängt von allem Vorherigen ab, hat aber keinen Einfluss auf den Runtime-Boot-Pfad.

**Kritische Dateien:**

`common/include/boot_hal.h` — Neues `provisioning_hal_t`-Struct. Optional als Feld in `boot_platform_t` (mit NULL-Default für Non-Provisioning-Builds).

`toobloader/core/boot_main.c` — DSLC-Check in Block 2.5 (nach Recovery-Pin, vor State-Machine): Wenn `DSLC == 0x00`, UART-Provisioning-Loop aufrufen statt `boot_state_run()`.

Neue Datei `toobloader/core/boot_provisioning.c` — COBS-basiertes UART-Protokoll, angelehnt an die existierende Logik in `boot_panic.c` Block 2/3.

## Zusammenfassung: Abhängigkeitsgraph

```
Phase 1 (Types/ABI) ──┬──→ Phase 2 (Stage 0 DSLC)
                       ├──→ Phase 3 (CDDL/zcbor)
                       ├──→ Phase 4 (Device-ID)
                       │
                       └──→ Phase 3 + 4 ──→ Phase 5 (boot_cloud_cmd.c)
                                                  │
                                                  ├──→ Phase 6 (boot_state.c)
                                                  ├──→ Phase 7 (libtoob API)
                                                  └──→ Phase 8 (Provisioning)
                                                            │
                                                            └──→ Phase 9 (Tests)
```

Phase 2 kann parallel zu 3-4 laufen. Phase 7 kann parallel zu 6 starten, sofern die Types aus Phase 1 stehen.
