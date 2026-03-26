> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/bootchooser.rst`

# 06. Barebox Bootchooser (A/B Redundancy Booting)

Dieses Dokument ist das Kernstück für ausfallsichere embedded Geräte. Es spezifiziert den kompletten Redundanz-Algorithmus (A/B Updates), wie Systeme zwischen Master- und Backup-Partitionen verhandeln und Fallbacks auslösen.

## 1. Der Bootchooser Algorithmus
Das Skript arbeitet komplett mathematisch zustandsbasiert und triggert den Boot über das Kommando `boot bootchooser`.

| Steuerungsvariable | Logik & Zustand |
|--------------------|-----------------|
| `priority` | Das Primär-Kriterium. Die Partition (`system0` / `system1`) mit dem höchsten Wert wird immer zuerst gebootet. Fällt die `priority` auf `0`, gilt das Target als permanent deaktiviert/kaputt. |
| `remaining_attempts` | Der "Strike Out"-Zähler. Er wird mit jedem physikalischen Start-Versuch um 1 verringert. Fällt er auf 0, überspringt der Algorithmus dieses Boot-Target augenblicklich und versucht das nächst-beste (z.B. ein Fallback/Recovery System). |

## 2. Boot-Verifizierung (Linux-Userspace Handshake)
Barebox kann physikalisch *nicht* wissen, ob Linux erfolgreich bis zur GUI durchgebootet ist oder in einer Kernel-Panic hängt. Barebox verringert nur den `remaining_attempts` Counter.
- [ ] **Marking a Boot as Successful:** Es liegt in der Verantwortung des hochgefahrenen Linux-OS (z.B. in Systemd), dem Bootloader mitzuteilen, dass alles funktionierte. Dafür nutzt Linux das Tool `barebox-state`, welches die `remaining_attempts` wieder auf den Standardwert hochsetzt (z.B. 3).
- [ ] **Attempts Lock (`attempts_locked`):** In Systemen, die extrem häufig von Benutzern brutal resettet/rebootet werden, könnte der Strike-Zähler die Partition "kaputt-zählen", ohne dass Software schuld war. Ist dieses Lock gesetzt, werden die `remaining_attempts` eingefroren, und ein Slot bleibt unendlich lang "Aktiv".

## 3. Storage Backend Contracts (State Framework vs. NV)
Daten über Prioritäten und Fehlschläge müssen Stromausfälle sicher überleben.

- [ ] **NV Variables Backend:** Nur für Testumgebungen! Barebox rät zwingend davor ab, simple NV-Variablen (Environment) für diese Zähler in Produktionssystemen zu nutzen, da sie nicht "Power-Fail Safe" (atomic) beschrieben werden können.
- [ ] **Barebox State Framework:** *Der* Produktions-Vertrag für Bootchooser. Die Metadaten werden im DeviceTree (`reg` / `#address-cells`) als fest verdrahtete, redundante Struktur definiert und z.B. kryptografisch sicher und abnutzungsfrei in einen EEPROM oder reservierten NAND-Block geschrieben.
- [ ] **OTA Update Integration:** Der Bootchooser liefert das saubere Backend für moderne OTA Update-Systeme. Barebox nennt dabei explizit **RAUC** (ein populäres A/B Update Framework), welches sich passgenau in diesen Bootchooser einklinkt.
