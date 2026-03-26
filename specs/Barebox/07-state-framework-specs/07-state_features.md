> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/state.rst`

# 07. Barebox State Framework (Persistent Storage)

Dieses Dokument spezifiziert das State Framework. Normale Environment-Variablen (NV) sind gefährlich für Produktionssysteme, weil ein Stromausfall während eines Schreibvorgangs das gesamte Environment korrumpieren kann. Barebox löst das Problem mit diesem transaktionssicheren Framework.

## 1. Backend-Formats (Data Storage)
Variablen werden nicht als simples Text-File (wie bei U-Boot) gespeichert, sondern strukturiert abgelegt.

- [ ] **`raw` (Default):** Das Variablen-Set wird als dichter binärer Blob in den Speicher geflusht. Dem Blob wird ein **16-Byte Header** vorangestellt (Magic Value, Size, Data-CRC32 und Header-CRC32). Dies liefert kryptografische Sicherheit; bei Bedarf inklusive HMAC Schutzschicht.
- [ ] **`dtb`:** Speichert alternativ einen vollständigen Device-Tree Blob. (Wird von Barebox aber explizit als experimentell/nicht empfohlen eingestuft).

## 2. Storage Type Strategies (The Wear-Leveling)
Das Framework muss den Speicher vor frühzeitigem Tod bewahren (z.B. NAND Flash wear-out). Das passiert über redundante Layouts, aufgeteilt in zwei Medien-Kategorien:

| Storage Strategy | Verhalten & Invariante | Ziel-Hardware |
|------------------|------------------------|---------------|
| **`direct`** | Die Medien erlauben unendliches Beschreiben einzelner Bytes. Barebox lagert zur Sicherheit zwingend immer **drei redundante Kopien** (Triplets) der Daten in festgelegten Abständen (`stride-size`) direkt nebeneinander ab. | EEPROM, MRAM, SRAM |
| **`circular`** | Die Medien können nur blockweise formatiert werden und erleiden Abnutzung (Wear-out). Barebox appendet eine Zustandsänderung immer an das *Ende* der letzten Kopie innerhalb eines `Eraseblocks`. Erst wenn der gesamte Flash-Block nach etlichen Updates voll ist, wird er physisch gelöscht, um Ressourcen und Lebensdauer zu schonen ("Ring-Buffer" Layout). | Flash-Speicher (NAND / NOR) |

## 3. DeviceTree "Shared" Memory Map
Barebox teilt sich das exakte Wissen über die physische Lage der State-Variablen mit dem Linux-Betriebssystem.

- [ ] **Single Source of Truth:** Das exakte Layout des Speichers wird zwingend in den Devicetree Node `aliases { state = &state_... }` kompiliert. So weiß der Barebox-Bootloader beim Hochfahren und das spätere `barebox-state` Tool des Linux-Systems auf das exakte Byte (`reg`), wie groß der Header ist, wo der EEPROM liegt und welcher Typ (`uint32`) aus dem puren Flash-Silizium gelesen werden muss. Dies verhindert, dass Linux und der Bootloader den Speicher versehentlich asynchron zerschießen.
