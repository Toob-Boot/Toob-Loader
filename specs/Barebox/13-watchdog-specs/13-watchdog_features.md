> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/watchdog.rst`

# 13. Barebox Watchdog Framework

Dieses Dokument abstrahiert den Umgang mit Hardware-Watchdogs (die das System bei Hängern in den Reset zwingen). Es offenbart einige sehr pragmatische Konstruktionen, um fehlerhaftes Hardware-Design von Mikroprozessoren auf Software-Level zu heilen.

## 1. Das "Autoping" (Poller) Dilemma
Manche SoC-Architekturen wachen aus dem Reset direkt mit einem scharfen, nicht abstellbaren Hardware-Watchdog auf, der extrem kurze Timeouts hat (z.B. Atheros mit nur 7 Sekunden). Barebox würde bei einem Netzwerk-Boot sofort brutal vom Watchdog gekillt werden, bevor der Linux-Kernel überhaupt vollständig per TFTP heruntergeladen ist.

- [ ] **Die `autoping` Notlösung:** Über `wdog0.autoping=1` registriert Barebox einen Poller, der exakt alle 500ms im Hintergrund den Watchdog füttert (streichelt), völlig unbemerkt vom laufenden Bootvorgang.
- [ ] **Security/Safety Warnung:** Die Dokumentation bezeichnet dieses Feature offen als "Bedrohung" (Threat). Wenn Barebox in einer Endlosschleife hängt, die *zufällig* den Poller-Hintergrundprozess weiter aufruft, neutralisiert Barebox den Hardware-Watchdog effektiv selbst! Ein gebricktes Board würde dann nie mehr neustarten. Autoping darf laut Spezifikation nur bei schlechten Hardware-Designs (oder in der Entwicklung) verwendet werden.

## 2. Default Watchdogs & Priorities
Da moderne Platinen oft mehrere Watchdogs haben (z.B. einen schwachen internen SoC-Watchdog und einen starken PMIC-Stromnetz-Watchdog), verwaltet Barebox diese nach Prioritäten.

| Watchdog Eigenschaft | Vertrag & Routing |
|----------------------|-------------------|
| **Priority System** | Jeder Watchdog bekommt einen numerischen `priority` Wert. Barebox Befehle (wie `wd` oder `boot -w`) triggern generell *nur* den Watchdog mit der höchsten Priorität (Default Watchdog). |
| **Architektur-Vorgabe** | Die Vorgabe der Entwickler lautet: Einem starken PMIC-Watchdog (der das gesamte Mainboard stromlos macht) **muss** immer eine höhere Priorität eingeräumt werden als dem internen CPU-Watchdog, da letzterer Peripherie-Hänger nicht resetten kann (siehe "System Reset" Spec). |

## 3. The Linux Handoff (`boot.watchdog_timeout`)
Die kritischste Phase im System-Lebenszyklus ist der Wechsel vom Bootloader in den Linux-Kernel.
- [ ] **Scharfschalten vor dem Sprung:** Wenn Barebox per `boot`-Kommando den Linux-Kernel startet, verliert es die Kontrolle. Damit ein abgestürztes Linux-Binary (z.B. eine fehlerhafte Kernel-Panic) das System nicht für immer aufhängt, kann Barebox über `global boot.watchdog_timeout=10` den primären Watchdog kurz vor dem Kernel-Sprung noch einmal hart auf (z.B.) 10 Sekunden aufziehen. 
- [ ] **Übergabe-Vertrag:** Der Linux-Kernel muss nun schnell genug booten, um seinen eigenen Watchdog-Device-Driver hochzufahren und das Füttern (Ping) von Barebox rechtzeitig zu übernehmen, bevor der 10s Timer ausläuft.
