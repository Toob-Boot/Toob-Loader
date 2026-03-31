# Getting Started mit Toob-Boot

> Für Developer: Der schnelle Weg Toob-Boot zu kompilieren und in eigene C/C++ oder Rust Projekte einzubinden.

## 1. Vorbereitungen
Du benötigst das Toob-Ecosystem CLI (`repowatt`/`toob`), welches intern den Manifest-Compiler, den Delta-Patcher und den Fuzzer ausführt.

```bash
# Beispiel-Kommando (Installation via Curl / Cargo etc.)
curl -sL https://repowatt.os/install.sh | bash
```

## 2. Hardware Fuzzing
Damit Toob-Boot auf deinem spezifischen Eval-Board weiß, wie groß Sektoren sind oder wie langsam SPI-Erase Zeiten werden, fuzzst du das Board:

1. Eval-Board anschließen.
2. `toobfuzzer init --target stm32`
3. `toobfuzzer run` (Ermittelt Flash-Alignments und Limitierungen ins `aggregated_scan.json`)

## 3. Kompilieren von Toob-Boot
Der Core liegt in generischem C17 vor. Die HALs (Hardware Abstraction Layers) schreibst du selbst für deine MCU oder nutzt die vorgefertigten ESP32/STM32/nRF HALs von uns.

```bash
# Baut das Bootloader-Binary, injiziert das aggregated_scan.json
toob build --component bootloader
```

Das Ergebnis ist eine `toob_boot_stage1.bin`, die an die allererste physikalische Speicher-Adresse deiner CPU geflasht wird.

## 4. Einsetzen im Feature-OS
In deinem eigentlichen Software-Projekt importierst du die `libtoob` Library.

```c
#include "libtoob.h"

int main(void) {
    // 1. Initialisierung deiner MCU / OS
    system_init();
    
    // 2. Bestätigen an Toob-Boot: Ich baue keinen Boot-Loop!
    uint32_t toob_state = toob_confirm_boot();
    if (toob_state != 0x55AA55AA) {
        printf("Panic: Ungültiger Boot-State!\n");
    }

    // 3. Dein App-Code hier
    // ...
    
    // 4. Update-Prozess (Download via WiFi)
    download_os_to_flash(SLOT_B_ADDR);
    toob_set_next_update(SLOT_B_ADDR);
    reboot();
}
```

## 5. Deployment / Signing
Um dein Feature-OS hochzuladen, musst du es per `toob-sign` verpacken und im SUIT-Format signieren. 
Nur so wird Toob-Boot das Update nach dem Neustart akzeptieren.
