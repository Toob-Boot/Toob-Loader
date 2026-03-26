---
description: Spec-Driven Dokumentations-Extraktion (Malus.sh Style) zur lückenlosen Erfassung von Features.
---

# Spec-Driven Extraction Principles

Dieser Workflow erzwingt die strikten Prinzipien der Clean-Room Dokumentations-Extraktion, basierend auf den Reverse-Engineering-Specs. Ziel ist es, aus Quell-Dokumentationen (z.B. `.md` Dateien) verhaltensbasierte, lückenlose Spezifikationen zu generieren.

## 1. Exhaustive Feature Extraction (Keine Lücken)
Du musst **ALLES** dokumentieren, was ein Feature, eine Architekturentscheidung, ein Datenfluss, ein Krypto-Format oder ein Zustand (State) ist.
- **Lückenlosigkeit [HARD-GATE]:** Jeder im Text beschriebene Ablauf (Branch, Error Handling, Memory Layout, Boot-Sequenz, Hardware-Abstraktion) MUSS in der Spezifikation abgedeckt sein. Verlasse das Dokument erst, wenn jeder Aspekt abstrahiert wurde.
- **Fokus auf das Soll-Verhalten:** Historische Bugfixes, Patch-Notes, Workarounds für alte Compiler oder "in Version X wurde Y behoben"-Kommentare werden **NICHT** spezifiziert. Wir dokumentieren das reine Architektur-Soll-Verhalten.

## 2. Implementation-Free (What, not How)
Entferne alle C-spezifischen oder code-spezifischen Implementierungsdetails aus der Spezifikation (soweit architektonisch sinnvoll).
- **Negativ-Beispiel:** *Die Funktion `wolfBoot_update()` ruft intern `hal_flash_write()` auf.*
- **Positiv-Beispiel:** *Der Update-Prozess speichert den Payload über eine abstrakte Hardware-Schnittstelle in den nicht-flüchtigen Speicher.*
- **Bootloader-Ausnahme:** Geht es um harte Architekturgrenzen (z.B. "RSA-2048 Signatur", "Sektor-Größe muss 4096 Byte betragen", "Magic Byte 0x57"), dann SIND das Features und müssen exakt so übernommen werden.

## 3. Given/When/Then Format (Behavioral Specs)
Formuliere Abläufe, Systemzustände und Akzeptanzkriterien im BDD-Stil (Given/When/Then), um sie später direkt als Blueprint für die Implementierungs-KI ("Team B") nutzbar zu machen.

**Beispiel Firmware Update:**
- **Given** ein signiertes Firmware-Image liegt in der Update-Partition
- **When** der Bootloader beim Startup die Partitionstabelle prüft
- **Then** wird die Signatur des Images validiert
- **And** bei Erfolg in die Boot-Partition kopiert

## 4. State & Data Contracts
Halte exakte Daten-Verträge (Contracts) fest: Header-Layouts, Magic Bytes, Kryptografische Schlüssel-Typen, Ein- und Ausgabewerte von Subsystemen.

## Ausführung
Wenn dieser Slash-Command `/spec-driven-extraction` aufgerufen wird, erzwingt die KI bei der Extraktion folgende Checks, bevor sie das Ergebnis liefert:
1. Sind wirklich *alle* Features des Original-Dokuments erfasst worden?
2. Sind historische Bugfixes/Workarounds erfolgreich ignoriert worden?
3. Ist die Spezifikation frei von unnötigen Implementierungsdetails (Funktionsnamen, Variablen)?
4. Sind Abläufe sauber im Given/When/Then Pattern strukturiert?
