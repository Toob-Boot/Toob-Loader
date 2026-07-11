# Toob-Boot — Security Model (`security_model.md`)

> **Rolle dieses Dokuments.** Single Source of Truth für das Bedrohungs- und Fault-Modell des Bootloader-Cores. Es ist (a) die *Spezifikation*, gegen die die Fail-Safe-Primitiven (FIH, Terminal-Halt) entworfen werden, und (b) die Voraussetzung, um später *irgendeine* defensive Schicht begründet zu beschneiden. Eine Schicht ohne Zeile in der Matrix (§5) existiert ohne dokumentierten Zweck und ist damit ein Audit-Kandidat.
>
> **Pflege.** Lebendes Dokument. Jede neu eingeführte defensive Schicht braucht genau eine Zeile in §5 mit benanntem Angriff und benannter Annahme. Code-Snippets der Primitiven werden später ergänzt — dieses Dokument bleibt implementierungsunabhängig.

---

## 0. Geltungsbereich

**In Scope.** Der On-Device-Bootloader: Stage 0 (immutable, ROM/erstes Flash), Stage 1 (der verifizierte, aktualisierbare Core), Stage 1.5 (Serial-Rescue). Konkret: die Verifikations-, Update-, Swap-, Rollback-, Persistenz- und Control-Plane-Logik bis zum Handoff an die Applikation.

**Out of Scope (eigene Dokumente/Trust-Domänen).**
- Die Registry-Cloud (serverseitige Signatur-Erzeugung, Schlüsselverwahrung, Build-Pipeline) — eigene Bedrohungsmodellierung. Hier wird die Registry nur als *Quelle signierter Artefakte* betrachtet, der der Bootloader **nicht** vertraut, bevor er die Signatur geprüft hat.
- Die Sicherheit der Applikation/des OS nach dem Handoff. Der Bootloader behandelt App und OS als untrusted.
- Invasive Silizium-Angriffe (Decap, FIB, Microprobing) — siehe Nicht-Ziele (§7).

---

## 1. Schutzziele

In Prioritätsreihenfolge, weil sie bei Konflikt gegeneinander abgewogen werden müssen:

1. **Authentizität & Integrität.** Nur von der Registry autorisierte, unveränderte Images werden ausgeführt. Kein unverifiziertes oder manipuliertes Image erreicht jemals den Handoff.
2. **Anti-Rollback.** Kein Downgrade auf einen bekannt-verwundbaren Stand — weder der Applikation noch des Bootloaders selbst (siehe Phase 7).
3. **Verfügbarkeit / Un-Brickbarkeit.** Das Gerät erreicht nach *jedem* Fehler oder Stromereignis einen wohldefinierten sicheren Zustand. Dies ist die **Master-Invariante** und der Grund, warum Verfügbarkeit hier ein Sicherheits- und nicht nur ein Reliability-Ziel ist: ein gebricktes Gerät ist im Feld nicht mehr patchbar und damit dauerhaft verwundbar.
4. **Vertraulichkeit der Geheimnisse.** Schlüsselmaterial und abgeleitete Secrets verlassen weder den vorgesehenen Speicher noch verbleiben sie nach Gebrauch im SRAM.
5. **Verifizierbare Identität.** Eine kryptografisch an die Hardware gebundene Geräteidentität (DICE) für Attestation gegenüber der Control-Plane.

### 1.1 Master-Invariante (das Top-Level-Sicherheitsprädikat)

Nach jeder Unterbrechung — Powerloss, Reset, Glitch, korrupter Persistenz, fehlgeschlagenem Update — endet der Boot in **genau einem** der definierten sicheren Endzustände. Die *verbotenen* Ausgänge sind präzise und nicht verhandelbar:

- **kein Brick** (das Gerät bleibt nie in einem nicht-bootfähigen Zustand stecken),
- **kein korruptes Image läuft** (ein durch Tearing/Korruption beschädigtes Image wird nie ausgeführt),
- **kein unverifiziertes Image läuft** (False-Accept == 0),
- **keine stille Akzeptanz** (jeder Verwurf/Rollback/Halt hinterlässt eine forensische Spur — siehe Phase 2).

Die zulässigen Endzustände (im HIL-Testplan abschließend als die *acht* sicheren Zustände enumeriert) umfassen u. a. Boot in die bestätigte App, Boot in eine tentative App mit offenem Confirm-Fenster, Rollback auf den letzten bekannt-guten Stand, Boot eines Recovery-Images, Eintritt in Stage 1.5 (Serial-Rescue), sicheres Terminal-Halt mit Breadcrumb sowie Wiederaufnahme eines unterbrochenen Updates aus dem Journal. Diese Enumeration ist im Testplan maßgeblich; die Sicherheitseigenschaft hier ist: *außerhalb dieser Menge gibt es keinen erreichbaren Zustand.*

---

## 2. Vertrauensmodell & Trust Anchors

Alles ruht auf einem kleinen, unveränderlichen Fundament. Wird ein Anker gebrochen, ist das gesamte Modell ungültig — diese Anker sind daher explizit und minimal gehalten.

### 2.1 Trust Anchors (unveränderliche Annahmen)

- **Stage 0 / ROM-Immutabilität.** Stage 0 ist nach der Fertigung nicht mehr veränderbar (ROM oder durch OTP write-protected Flash). Stage 0 ist die Wurzel der Verifikationskette und wird selbst nicht zur Laufzeit verifiziert — seine Integrität ist eine Hardware-Annahme.
- **OTP / eFuse-Integrität.** Die OTP hält den Root-Public-Key-Hash (Vertrauensanker für alle Signaturprüfungen) und die monotonen Counter (Anti-Rollback-Epochen). OTP-Bits sind hardware-seitig nur einmal brennbar und nicht dekrementierbar.
- **Hardware-Watchdog.** Der WDT ist nach Aktivierung nicht durch Software deaktivierbar (locked) und löst bei Starvation zuverlässig einen Reset aus. Dies macht „nicht-kicken“ zu einem belastbaren Fail-Secure-Primitiv (§4, §5).
- **TRNG.** Liefert echte, nicht vorhersagbare Zufallswerte zur Laufzeit (Grundlage der CFI-Token-Randomisierung und der Glitch-Delays).
- **Crypto-Primitive.** Ed25519 und der PQC-Algorithmus gelten als kryptografisch sound; das Brechen der Signaturmathematik ist kein betrachteter Angriff.

### 2.2 Trust-Boundaries

| Komponente | Status | Begründung |
|---|---|---|
| ROM / Stage 0 | vertraut (Anker) | unveränderlich, Hardware-garantiert |
| OTP / eFuse | vertraut (Anker) | hardware-monoton, write-once |
| Stage 1 (Core) | vertraut **nach** Verifikation durch Stage 0 | erst nach Signaturprüfung gegen Root-PK |
| HAL (Vendor-Implementierung) | **Trust-Boundary** | Reset-Reason-Mapping, Flash-Semantik, Counter-Verhalten sind ungetestet, bis die Conformance-Suite (Phase 7) sie bindet |
| Persistenz (WAL/TMR/KDM-Slots) | **untrusted Inhalt**, integritätsgeprüft | jeder gelesene Record wird per Quorum/CRC validiert, bevor er Entscheidungen treibt |
| Update-Payload (Envelope) | untrusted bis verifiziert | „Envelope-First“: Signaturprüfung vor jedem Parsen von Nutzinhalt |
| Netzwerk / Control-Plane / KDM-Kommandos | untrusted | jedes Kommando ist signiert und wird gegen Sequenz/Replay geprüft |
| Applikation / OS (nach Handoff) | untrusted | der Bootloader schützt sich selbst und die Persistenz gegen eine kompromittierte App |

### 2.4 HAL Isolation Contract

Der Bootloader-Core (`toobloader/core/` und `toobloader/stage0/`) darf zu keinem Zeitpunkt direkte Hardware-Interaktionen (MMIO-Zugriffe, volatile Hardware-Zeiger oder direkte Aufrufe herstellerspezifischer SDKs) ausführen.

- **Kapselung**: Jede physische Interaktion ist hinter den Zeiger-Interfaces (Traits) der `boot_platform_t` abstrahiert.
- **Vorteil für Tests & Verifikation**: Diese strikte Trennung erlaubt es uns, den gesamten Bootloader im Host-System zu mocken und zu testen (Record/Replay-Naht).
- **Automatisierte Validierung**: Ein Test-Script (`scripts/check_mmio_isolation.ps1`) analysiert die Codebasis und schlägt fehl, wenn direkte MMIO-Zugriffe (z. B. `(volatile uint32_t *)0x...`) außerhalb der HAL-Implementierung gefunden werden.

---

## 3. Angreifermodell (Capabilities & Tiers)

Vier Tiers nach steigender physischer Nähe. Für jedes Tier ist definiert, was es kann und was außerhalb des Geltungsbereichs liegt.

**A1 — Remote / Netzwerk.** Kann beliebige Update-Payloads und Control-Plane-Kommandos zustellen, alte Payloads/Kommandos erneut einspielen (Replay), Transport-Daten manipulieren (MITM). Kein physischer Zugriff. — *Voll in Scope.*

**A2 — Lokal / Logisch.** Hat physischen Port-Zugriff ohne Fault-Equipment: kann über Debug-Interfaces in Flash schreiben, Resets erzwingen, das Gerät beliebig power-cyclen (Tearing provozieren), Persistenzsektoren gezielt korrumpieren, eine kompromittierte App ausführen. — *Voll in Scope.*

**A3 — Physisch / Fault-Injection.** A2 plus Glitch-Equipment: Spannungs-, Takt- und EM-Glitches mit dem Ziel, einzelne Instruktionen zu überspringen, Verzweigungen zu verfälschen oder Werte zu korrumpieren. Kann Timing über Beobachtung (GPIO, Stromsignatur) approximieren. — *In Scope unter den Granularitätsannahmen in §4.*

**A4 — Invasiv / Seitenkanal.** Decap, FIB, Microprobing, vollständige Leistungs-/EM-Seitenkanalanalyse bis zur Schlüsselextraktion. — *Überwiegend Nicht-Ziel (§7); Timing-Seitenkanal teilweise adressiert (F7).*

---

## 4. Fault-Modelle (Kern des Dokuments)

Die Fault-Modelle definieren *präzise*, welche Fähigkeit ein A3-Angreifer hat. Diese Präzision ist der Grund, warum jede Primitive so und nicht anders aussieht — insbesondere entscheidet sie, ob „Bool cachen“ ausreicht oder ob der Ausdruck **neu evaluiert** werden muss, und ob ein einzelner Redundanz-Check genügt oder ob ein flussübergreifender **CFI-Akkumulator** nötig ist.

### 4.1 Gemeinsame Annahmen (binden alle Fault-Modelle)

- **Bounded Glitch-Budget.** Der Angreifer kann pro Boot-Durchlauf nur eine *beschränkte* Zahl K präzise getimter Glitches landen. Ein einzelner Glitch (K=1) ist die Standardannahme; K>1 wird als gehärtetes Ziel betrachtet (F2), perfekt getimtes unbeschränktes Multi-Glitch ist Nicht-Ziel.
- **Timing-De-Korrelation.** Eingestreute Zufallsverzögerungen (TRNG-gespeist) degradieren die Fähigkeit des Angreifers, denselben logischen Punkt zweimal exakt zu treffen. Doppelauswertungen mit Delay dazwischen sind genau deshalb wirksam.
- **OTP unzugänglich für A3.** Der Angreifer kann OTP/eFuse-Bits weder lesen-und-fälschen noch dekrementieren (das wäre A4). Er kann jedoch den *Lesevorgang* eines Counters glitchen (F6).
- **ROM/Stage-0 unveränderlich.** Auch unter Glitch bleibt der Verifikationsanker intakt; ein Glitch verändert keinen ROM-Inhalt, nur flüchtigen Kontrollfluss/Daten.

### 4.2 Die Fault-Modelle

Jedes Modell nach einheitlichem Schema: *Beschreibung · Primitiv & Granularität · Erfolg bedeutet · Adressiert durch · Restrisiko.*

---

**F1 — Single Instruction / Branch Skip.**
*Beschreibung:* Ein einzelner Glitch überspringt eine Instruktion oder kippt eine einzelne bedingte Verzweigung.
*Primitiv & Granularität:* genau ein präzise getimter Skip (K=1).
*Erfolg bedeutet:* ein `if (verified) jump` wird genommen, obwohl `verified` falsch ist; oder ein Bounds-Check wird übersprungen.
*Adressiert durch:* Double-Check-Shield (Ausdruck **neu** auswerten, Delay dazwischen), redundante Verzweigung, WDT-Fail-Secure als Auffangnetz.
*Restrisiko:* gering bei K=1; geht in F2 über, sobald der Angreifer zwei Auswertungen treffen kann.

**F2 — Multi-Glitch / wiederholter Skip.**
*Beschreibung:* Der Angreifer landet mehrere präzise Glitches und kann damit beide Auswertungen eines naiven Double-Checks überspringen.
*Primitiv & Granularität:* K>1, mit der Timing-Schwierigkeit, die durch Delays erhöht wird.
*Erfolg bedeutet:* ein einfacher Redundanz-Check wird beidseitig umgangen.
*Adressiert durch:* CFI-Akkumulator, der Zustand über den *gesamten* Pfad fädelt — das Überspringen mehrerer Checkpoints hinterlässt den Akkumulator in einem Zustand, der am Endabgleich nicht passt; Glitch-Delays zur Timing-Degradation.
*Restrisiko:* perfekt getimtes unbeschränktes Multi-Glitch bleibt offen — als Nicht-Ziel für die adressierte Angreiferklasse akzeptiert (§7, §8).

**F3 — Daten- / Wertkorruption.**
*Beschreibung:* Ein Glitch korrumpiert nicht den Kontrollfluss, sondern den *Wert*, auf dem eine Entscheidung ruht — in einem Register, auf dem SRAM-Bus oder im Speicher.
*Primitiv & Granularität:* einzelner Bit-/Wort-Flip am Datum.
*Erfolg bedeutet:* der Quellwert eines Vergleichs wird so verfälscht, dass die Entscheidung kippt — **ein gecachter Bool fängt das nicht**, weil er den korrumpierten Quellwert nicht erneut liest.
*Adressiert durch:* (a) Ausdruck neu auswerten statt Bool cachen (re-liest die zugrunde liegenden Werte); (b) High-Hamming-Distance-Sentinels: `BOOT_OK = 0x55AA55AA`, Gegenwert `0xAA55AA55` unterscheiden sich in allen 32 Bit, und beide liegen weit (je 16 Bit) von den natürlichen Korruptions-Attraktoren `0x00000000`/`0xFFFFFFFF` (Bus stuck-low/stuck-high) — ein zu Null oder Eins geglitchtes Register sieht nie wie `BOOT_OK` aus.
*Restrisiko:* eine Korruption, die exakt ein gültiges Sentinel erzeugt, ist extrem unwahrscheinlich, aber nicht null; durch Doppelauswertung weiter reduziert.

**F4 — Security-Gate-Bypass.**
*Beschreibung:* Der Spezialfall, in dem der Glitch genau den Moment `verify → branch → jump/commit` trifft (die sicherheitskritischste Stelle überhaupt).
*Primitiv & Granularität:* präziser Skip/Korruption am Verifikations-Entscheidungspunkt (F1/F3 an der heißesten Stelle).
*Erfolg bedeutet:* ein nicht-verifiziertes Image wird akzeptiert/ausgeführt — direkter Bruch von Schutzziel 1 (False-Accept).
*Adressiert durch:* alle obigen, plus Envelope-First-Reihenfolge (verify vor parse), plus die Invariante False-Accept == 0 als eigene HIL-Security-Kampagne.
*Restrisiko:* der zentrale Restrisiko-Posten; treibt die strengste Testabdeckung.

**F5 — Persistenz-Korruption (Tearing / Bit-Rot).**
*Beschreibung:* Powerloss mitten in einem Flash-Write (Tearing), oder Bit-Rot über Zeit, korrumpiert WAL/TMR/Counter/KDM-Slots.
*Primitiv & Granularität:* unterbrochener oder degradierter Speicherzustand; nicht zwingend ein aktiver Angriff, aber durch A2 (Power-Cycling) provozierbar.
*Erfolg bedeutet:* der Bootloader liest einen inkonsistenten Zustand und trifft eine falsche Entscheidung (z. B. ein halb-geschriebenes Image für gültig halten).
*Adressiert durch:* TMR-Quorum (Whole-Struct-Vote über ≥3 Slots), WAL als Append-Log mit Frontier-Scan, Read-Back-Verify nach jedem Write, monotone Sequenz-Disziplin.
*Restrisiko:* pathologisches Multi-Tearing, das das Quorum gleichzeitig über die Mehrheit der Slots verletzt — durch Slot-Anzahl und WAL-Redundanz beschränkt, nicht eliminiert.

**F6 — Counter-Glitch / Rollback-Bypass.**
*Beschreibung:* Der Angreifer glitcht den *Lesevorgang* des monotonen Counters/der Epoch, sodass ein niedrigerer Wert zurückgegeben wird.
*Primitiv & Granularität:* F1/F3 angewandt auf den Counter-Read (nicht auf den OTP-Inhalt selbst — der bleibt unverändert).
*Erfolg bedeutet:* ein Downgrade auf einen bekannt-verwundbaren Stand wird fälschlich zugelassen.
*Adressiert durch:* Counter-Read doppelt auswerten (F1/F3-Härtung), Hardware-Monotonie der eFuse als Anker, SVN-Gating in App **und** (ab Phase 7) Bootloader-Self-Anti-Rollback.
*Restrisiko:* siehe F1/F3; zusätzlich Restrisiko aus einer HAL, die Counter-Semantik falsch implementiert (bis Phase-7-Conformance gebunden).

**F7 — Timing-Seitenkanal-Leak.**
*Beschreibung:* Geheimnisabhängige Ausführungszeit (z. B. early-exit beim Vergleich von MAC/Hash/Schlüssel) leakt Information über das Geheimnis.
*Primitiv & Granularität:* passive Beobachtung der Ausführungszeit (A3/A4-Grenze).
*Erfolg bedeutet:* sukzessive Rekonstruktion eines Geheimnisses oder erleichtertes Forging.
*Adressiert durch:* Constant-Time-Vergleiche (`boot_ct_utils`) auf allen geheimnisabhängigen Pfaden; Secure-Zeroize gegen Residual-Secrets im SRAM.
*Restrisiko:* Leistungs-/EM-Seitenkanäle (nicht nur Timing) sind **Nicht-Ziel** dieser Revision (§7).

---

## 5. Defensive-Schichten-Matrix

Die Kern-Lieferung der Phase 0: jede im Code vorhandene Schicht mit benanntem Angriff, zugeordnetem Fault-Modell, der tragenden Annahme und dem Restrisiko. Spalte *Status*: `etabliert` = klarer Zweck; `Audit-Kandidat` = Zweck/Überlappung zu prüfen (siehe §6).

| Schicht | Adressierter Angriff | Fault-Modell | Tragende Annahme | Restrisiko | Status |
|---|---|---|---|---|---|
| **Double-Check-Shield** (Sentinel-Neuauswertung) | Übersprungene/verfälschte Sicherheitsverzweigung | F1, F3, F4 | Angreifer kann beide durch Random-Delay getrennten Auswertungen nicht zuverlässig treffen (K=1) | Beidseitiger Treffer bei K>1 → adressiert von CFI | etabliert |
| **High-Hamming-Sentinels** (`0x55AA55AA` / `0xAA55AA55`) | Wertkorruption Richtung 0/1 | F3 | Glitch zieht Register Richtung all-0/all-1, nicht exakt auf ein gültiges Sentinel | Korruption exakt auf ein Sentinel (extrem unwahrscheinlich, nicht null) | etabliert |
| **CFI-Akkumulator** (TRNG-abgeleitet, runtime) | Überspringen eines/mehrerer Checkpoints | F1, F2, F4 | Token ist zur Laufzeit zufällig → aus dem Binary nicht vorhersagbar, daher nach Skip nicht auf den erwarteten Endwert korrigierbar | Perfekt getimtes Multi-Glitch inkl. Akkumulator-Forging (Nicht-Ziel) | etabliert |
| **Glitch-Delay** (TRNG-Random) | Präzises Timing wiederholter Glitches | F1, F2 | Zufallsverzögerung de-korreliert Angreifer-Timing wirksam | Statistisch verbleibende Treffer über viele Versuche | etabliert |
| **WDT-Starvation-Fail-Secure** | Hänger/Skip im sicheren Pfad | F1, F4 (+ Liveness) | WDT ist hardware-locked, nicht per Software abschaltbar; Reset ist ein sicherer Zustand | Reset-Zustand selbst ausnutzbar (durch Master-Invariante adressiert) | etabliert |
| **Constant-Time-Vergleich** (`boot_ct_utils`) | Timing-Leak geheimnisabhängiger Vergleiche | F7 | Beobachtungskanal ist Timing; keine Aussage zu Power/EM | Power-/EM-Seitenkanal (Nicht-Ziel) | etabliert |
| **Secure-Zeroize** (`.S` + Host) | Residual-Secrets im SRAM nach Gebrauch | F7 / Vertraulichkeit | Compiler/HW eliminieren den Wipe nicht (memory-barrier-fest) | Secrets in nicht-erfassten Puffern/Caches | etabliert |
| **Envelope-First-Verify** (verify vor parse) | Parser-Angriffsfläche auf untrusted Bytes; Gate-Reihenfolge | F4 + logisch (A1) | Signatur deckt exakt die später geparsten Bytes ab (verify-what-you-parse, Phase 6) | Heute: signierte Region per `len−64` inferiert → Malleability bis Phase 6 | Audit-Kandidat |
| **Read-Back-Verify** (Flash nach Write prüfen) | Nicht gelandeter/getearter Write; übersprungener Write | F5, F1 | Rücklese-Pfad liest den physischen Flash, nicht einen Cache | Korruption nach Verify und vor Gebrauch | etabliert |
| **Anti-Replay / SVN-Counter** (eFuse-Epoch) | Downgrade/Replay alter Images & Kommandos | F6 + logisch (A1/A2) | eFuse hardware-monoton; Counter-Read glitch-gehärtet | Counter-Read-Glitch (F6); HAL-Fehlimplementierung bis Phase 7 | etabliert |
| **TMR-Quorum + WAL** | Persistenz-Korruption durch Tearing/Bit-Rot | F5 | Mehrheit der ≥3 Slots bleibt intakt; Append-Log + Frontier eindeutig | Multi-Tearing über die Mehrheit gleichzeitig | etabliert |
| **DICE-Identity** | Identitäts-Spoofing gegenüber Control-Plane | logisch (A1/A2) | Messkette ab Stage 0 unverändert; HW-UID vertrauenswürdig | Identitäts-Leak bei kompromittiertem oberen Layer | etabliert |
| **Software-MPU** (Multi-Image-Isolation) | Übergriff zwischen Images / kompromittierte App auf Bootloader-Region | logisch (A2) / Defense-in-Depth | Memory-Partitionierung wird korrekt durchgesetzt | Umgehung bei HW-MPU-Schwäche; reine SW-Durchsetzung | Audit-Kandidat |
| **Stage 1.5 — Serial-Rescue** | Un-Brickbarkeit / Recovery wenn Stage 1 nicht lädt | Verfügbarkeit (Master-Invariante) | Rescue-Pfad ist selbst minimal und robust; Eintritt ist gegated | Rescue-Pfad als zusätzliche Angriffsfläche (minimal halten) | etabliert |
| **Stage 0 / ROM** (Verifikationsanker) | gesamte Vertrauenskette | Trust Anchor (§2) | unveränderlich, Hardware-garantiert | Bruch invalidiert das gesamte Modell (Anker, nicht Schicht) | Anker |

---

## 6. Überlappungen & Audit-/Beschneidungs-Kandidaten

> **Regel.** Keine Schicht wird beschnitten, ohne dass diese Sektion (und die Matrix) die Redundanz begründet. Diese Liste *identifiziert* Kandidaten — sie ordnet keine Entfernung an.

- **CFI-Akkumulator ↔ Double-Check-Shield.** Beide adressieren die Skip-Klasse (F1/F2/F4). Verdacht: an manchen Stellen schützt der lokale Double-Check dieselbe Verzweigung, die der flussübergreifende CFI-Akkumulator ohnehin abdeckt. *Zu klären:* Welche Verzweigungen liegen *innerhalb* eines CFI-überspannten Abschnitts und tragen zusätzlich einen lokalen Shield? Dort ist der lokale Shield potenziell redundant (oder umgekehrt der Shield ausreichend und der Akkumulator-Schritt entbehrlich). Entscheidung erst nach Phase 2, wenn beide Mechanismen als *eine* auditierte Primitive vorliegen.
- **Software-MPU als reine SW-Durchsetzung.** Wert hängt davon ab, ob das Ziel-Silizium eine HW-MPU bietet, die der Bootloader stattdessen/zusätzlich konfigurieren kann. *Zu klären:* Pro Chip in der HAL-Matrix, ob die SW-MPU primärer Schutz oder reine Defense-in-Depth ist.
- **Envelope-First mit `len−64`-Inferenz.** Die Reihenfolge (verify vor parse) ist korrekt; die *Bestimmung* der signierten Region aus dem Pufferrand ist eine Malleability-Fläche. Kein Beschneidungs-, sondern ein Härtungs-Kandidat → Phase 6 (Decoder liefert die exakte signierte Region).
- **WDT-Starvation als Allzweck-Halt vs. Terminal-Halt.** Heute existieren mehrere Starvation-Loops mit unterschiedlichem Verhalten (mal mit `NULL`-Trap, mal ohne). *Zu klären:* nach Phase 2 ist `boot_terminal_halt` der einzige Halt-Pfad; die Frage ist dann nur noch, wo WDT-Starvation *zusätzlich* als unabhängiges Auffangnetz erwünscht ist.

---

## 7. Annahmen & Nicht-Ziele (explizit)

Ein Sicherheitsmodell ist nur so ehrlich wie seine Nicht-Ziele. Diese Klasse wird **nicht** verteidigt:

- **Invasive Silizium-Angriffe** (Decap, FIB, Microprobing, direktes OTP-Auslesen) — A4-Hardware außerhalb des Modells.
- **Power-/EM-Seitenkanal-Analyse** (über Timing hinaus). Constant-Time deckt den Timing-Kanal; Leistungs-/EM-Resistenz ist Nicht-Ziel dieser Revision.
- **Perfekt getimtes, unbeschränktes Multi-Glitch** mit beliebig vielen exakt platzierten Glitches pro Boot. Das bounded-K-Modell (§4.1) ist die bewusste Grenze.
- **Kompromittierung des Registry-Signatur-Privatschlüssels** (Registry-Trust-Domäne; On-Device-Restmitigation via Rotation + Epoch, §2.3).
- **Bruch der Crypto-Mathematik** (Ed25519/PQC gelten als sound).
- **Kompromittierung der ROM/Stage-0-Immutabilität** (Trust Anchor; ihr Bruch invalidiert das Modell).

---

## 8. Restrisiken-Register

Aggregat der Restrisiken aus §4/§5, mit Status. „Adressiert durch Phase X“ verweist auf den Strukturplan.

| # | Restrisiko | Fault-Modell | Status |
|---|---|---|---|
| R1 | Beidseitiger Glitch-Treffer auf einen Double-Check (K>1) | F2 | Mitigiert durch CFI + Delay; perfekt getimtes Multi-Glitch als Nicht-Ziel akzeptiert |
| R2 | Korruption exakt auf ein gültiges Sentinel | F3 | Akzeptiert (extrem niedrige Wahrscheinlichkeit, durch Doppelauswertung weiter reduziert) |
| R3 | Counter-Read-Glitch erlaubt Downgrade | F6 | Mitigiert durch Doppelauswertung; **Bootloader-Self-Anti-Rollback offen → Phase 7** |
| R4 | HAL implementiert Reset-Reason/Flash/Counter-Semantik falsch | F5/F6 + Trust-Boundary | **Offen → HAL-Conformance-Suite (Phase 7)** |
| R5 | Signierte Region via `len−64` → Malleability hinter der Signatur | F4 | **Offen → verify-what-you-parse (Phase 6)** |
| R6 | Multi-Tearing verletzt das TMR-Quorum über die Mehrheit | F5 | Mitigiert durch Slot-Anzahl + WAL; Restrisiko akzeptiert; Quorum-Konvergenz härtet KDM (Phase 4) |
| R7 | Residual-Secrets in nicht-erfassten Puffern/Caches | F7/Vertraulichkeit | Mitigiert durch Secure-Zeroize; vollständige Cache-Abdeckung als Restrisiko |
| R8 | Power-/EM-Seitenkanal | F7 (erweitert) | Nicht-Ziel dieser Revision (§7) |
| R9 | Stille Akzeptanz eines Verwurfs/Rollbacks nicht beobachtbar | Master-Invariante | **Adressiert durch Forensik-Breadcrumb (Phase 2)** |

---

## 9. Bezug zu EU CRA (Kurzverortung)

Dieses Modell stützt die für die CRA-Konformität relevante Posture, ohne sie zu ersetzen: ein verifizierter, manipulationsresistenter Boot- und Update-Pfad (sichere Updates), eine durchsetzbare Anti-Rollback-Disziplin (kein Re-Exponieren behobener Schwachstellen), die Un-Brickbarkeit als Voraussetzung dafür, dass Geräte *überhaupt* dauerhaft patchbar bleiben, sowie eine attestierbare Identität. Die forensische Beobachtbarkeit (Phase 2) und die HAL-Conformance (Phase 7) sind zugleich die Bausteine, die das Vulnerability-Handling über die Gerätelebensdauer auditierbar machen. Die abschließende Mapping-Tabelle auf die konkreten CRA-Essential-Requirements gehört in ein eigenes Compliance-Dokument.

---

## 10. Glossar / Referenz-Konstanten

- **`BOOT_OK = 0x55AA55AA`** — High-Hamming-Erfolgs-Sentinel. Gegenwert `0xAA55AA55` (alle 32 Bit verschieden). Beide je 16 Bit entfernt von `0x00000000`/`0xFFFFFFFF`.
- **CFI** — Control-Flow-Integrity. Hier: ein zur Laufzeit aus dem TRNG abgeleiteter Token, der über Checkpoints akkumuliert und am Ende abgeglichen wird (kein statischer Compile-Time-Wert mehr).
- **Double-Check-Shield** — geglitch-resistente Verzweigung durch zweimalige Auswertung *desselben, seiteneffektfreien* Ausdrucks mit Random-Delay dazwischen.
- **Envelope-First** — Signaturprüfung über den rohen Envelope *vor* jedem Parsen von Nutzinhalt.
- **TMR** — Triple-Modular-Redundancy: Whole-Struct-Quorum-Vote über ≥3 Persistenz-Slots.
- **WAL** — Write-Ahead-Log: Append-Log mit Frontier-Scan zur tearing-sicheren Intent-Persistenz.
- **SVN / Epoch** — Security-Version-Number bzw. monotone eFuse-Epoch als Anti-Rollback-Anker.
- **Master-Invariante** — nach jeder Unterbrechung genau einer von acht sicheren Endzuständen; verbotene Ausgänge: Brick, korruptes Image, unverifiziertes Image, stille Akzeptanz.
- **K (Glitch-Budget)** — beschränkte Anzahl präzise getimter Glitches pro Boot, die der Angreifer landen kann (Standardannahme K=1).