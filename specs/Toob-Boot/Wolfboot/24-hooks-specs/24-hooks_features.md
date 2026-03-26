> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/hooks.md`


# 24. Firmware Hooks & Custom Injectors

Dieses Dokument spezifiziert das dynamische Hook-Framework von Toob-Boot. Es erlaubt Entwicklern, tief in den Startvorgang und in das Fehler-Handling einzugreifen, **ohne** dass der geschützte Kern-Sourcecode des Bootloaders jemals verändert werden muss (`WOLFBOOT_HOOKS_FILE=pfad.c`).

## 1. Lifecycle Hook Contracts
Das Framework emittiert an genau 4 exakt definierten Stellen der Architektur Lebenszeichen. Entwickler können für jeden Hook individuell entscheiden, ob sie ihn per Makro aktivieren und den C-Vertrag implementieren wollen:

| Hook Type | Aktivierungs-Flag | C-Signatur | Vertrag (Wann & Warum?) |
|-----------|-------------------|------------|-------------------------|
| **1. Preinit** | `WOLFBOOT_HOOK_LOADER_PREINIT=1` | `void wolfBoot_hook_preinit(void)` | Wird direkt beim Power-ON gefeuert, noch **bevor** das HAL initialisiert wird (`hal_init`). *Achtung: Hier dürfen keine HW-Resourcen genutzt werden, die Clocks benötigen!* |
| **2. Postinit**| `WOLFBOOT_HOOK_LOADER_POSTINIT=1`| `void wolfBoot_hook_postinit(void)`| Wird nach dem HAL-Init, aber unmittelbar vor der Haupt-Bootlogik (`wolfBoot_start`) aufgerufen. Perfekt für externe Watchdogs. |
| **3. Boot** | `WOLFBOOT_HOOK_BOOT=1` | `void wolfBoot_hook_boot(struct wolfBoot_image *boot_img)` | Der letzte Atemzug. Feuert nach der fertigen Signaturprüfung, direkt vor dem finalen Kernel-Jump (`do_boot()`). **Bonus:** Liefert den verifizierten `wolfBoot_image` Pointer, damit das Hook Version und Metadaten des startenden Gast-OS auslesen kann! |
| **4. Panic** | `WOLFBOOT_HOOK_PANIC=1` | `void wolfBoot_hook_panic(void)` | Das Auffangnetz. Feuert, wenn der Bootvorgang fatal abstürzt, exakt bevor sich das System in die Todesschleife (Infinite Loop) versetzt. Exzellent zum Abwerfen sensibler GPIOs in einen "Safe State". |

## 2. Security Exceptions (Fault Injection)
- [ ] **Glitch-Safety Einschränkung (`WOLFBOOT_ARMORED=1`):** Ist das System gegen physische Fault-Injections (z.B. Laser auf Chip-Bahnen) gehärtet, wird der **Panic-Hook** rein auf "Best-Effort" Basis aufgerufen! Das bedeutet: Die execution des Hooks selbst ist **nicht** durch Armored-Code geschützt. Ein Hacker könnte mit einem Laser-Puls über den Hook einfach in den sicheren State überspringen. Das Framework garantiert aber, dass die nachfolgende Todesschleife (Halt-Loop) gepanzert bleibt und nicht entriegelt werden kann.
