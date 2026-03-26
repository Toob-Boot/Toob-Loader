> **Quelle/Referenz:** Analysiert aus `barebox/SECURITY.md`

# 14. Barebox Security Policy

Dieses kurze Dokument ist das organisatorische Security-Manifest des Barebox-Projekts auf GitHub. Es enthält keine technischen Implementierungen (diese folgen im nächsten Dokument), legt aber die strukturellen Verträge für den produktiven Einsatz fest.

## 1. Release & Support Strategie (LTS)
Barebox weicht hier radikal von klassischen Enterprise-Modellen ab:

- [ ] **No LTS Branches:** Barebox pflegt **keine** "Long Term Support" (LTS) Versionen. Wenn eine Sicherheitslücke gefunden wird, wird diese *ausschließlich* im neuesten Main-Release gepatcht. Wer Barebox in kritischen Systemen einsetzt, muss sein Update-Backend so skalieren, dass es immer das allerneueste Major-Release mitgehen kann.
- [ ] **Backward Compatibility Guarantee:** Um den aggressiven Upgrade-Pfad (No LTS) für Industrie-User erträglich zu machen, liefert Barebox eine harte architektonische Garantie: Jede neue Barebox-Version ist abwärtskompatibel zu alten Linux-Kernel-Releases. Ein Bootloader-Update zerstört also nie ("never break userspace"-Äquivalent) den Boot-Pfad zum Betriebssystem.

## 2. Vulnerability Management
- [ ] **Coordinated Disclosure:** Security Bugs dürfen nicht als Public Issue im Tracker geöffnet werden, sondern werden isoliert über `security@barebox.org` koordiniert, bevor ein Fix gemeinsam mit den Entdeckern veröffentlicht wird.
