# Toob-Boot Core — Architektur an der Grenze

Ziel dieses Dokuments: nicht „Best Practices nachrüsten", sondern die Kernarchitektur dort
weiterdenken, wo sie heute an strukturelle Grenzen stößt. Grundlage ist die vollständige
Code-Review des Exports; alle Vorschläge sind auf den tatsächlichen Code bezogen, nicht generisch.

Epistemischer Hinweis vorweg: Die Konzepte 1–7 sind unterschiedlich spekulativ. Was erprobte
Technik aus anderen Feldern ist, was Extrapolation ist und was Hypothese, steht bei jedem Konzept
explizit dabei. Kein Produktions-Bootloader, den ich kenne, setzt alle sieben um — einige davon
setzt meines Wissens *keiner* um. Das ist der Punkt.

---

## 1. Erste Prinzipien — was der Core wirklich leisten muss

Wenn man alle Implementierungsentscheidungen abstreift, bleibt genau eine Aufgabe:

> Das Gerät führt nach jedem Neustart genau ein authentisches, freigegebenes, nicht-veraltetes
> Image aus — und konvergiert nach *jeder* Unterbrechung (Stromausfall, Flash-Verschleiß,
> Übertragungsabbruch, Hardwarefehler, gezielte Störung) selbstständig zurück in diesen Zustand.
> Mit konstantem RAM, minimalem Flash-Verschleiß, auf heterogenen MCUs.

Die heutige Architektur erfüllt das über fünf **implizite Grundannahmen**, die sich alle
hinterfragen lassen:

1. Korrektheit wird durch *imperative Prüfungen* behauptet — `BOOT_SECURE_REQUIRE`,
   CFI-Akkumulatoren, verstreute Bounds-Checks. Die Prüfung und die geprüften Daten sind
   getrennte Variablen; deshalb braucht es TOCTOU-Schilde, Double-Checks und Re-Reads.
2. Zustand liegt als *mutierbare Datensätze* im Flash, die bei jedem Boot vollständig gescannt,
   gevotet und rückwärts rekonstruiert werden.
3. Jedes Modul implementiert seine Querschnittssorgen selbst — CFI-Setup, Resume-Logik,
   Streaming-CRC, Buffer-Sandboxing existieren je zwei- bis dreifach.
4. Die Boot-Entscheidung wird jedes Mal aus Rohdaten neu berechnet, nie gecacht.
5. Die Ablaufsteuerung ist *in Code kompiliert* (1200-Zeilen-Funktion mit goto-Topologie),
   nicht *als Daten interpretiert* — und damit weder generierbar noch erschöpfend testbar.

Jede der sieben Ideen unten invertiert mindestens eine dieser Annahmen.

---

## 2. Analogien aus fremden Feldern

| Feld | Mechanismus | Transplantat für den Core |
|---|---|---|
| Datenbanken (Redo-Log) | Idempotente Effekt-Records: „nochmal ausführen" ist immer sicher | Ein einziger Flash-Transaktions-Executor statt drei bespoke Resume-Logiken (→ K3) |
| Verteilte Systeme (FoundationDB) | Deterministische Simulation: das ganze System läuft als reine Funktion über einem aufgezeichneten Ereignisband | Boot als replaybare Funktion; Stromausfall an *jeder* Schreibgrenze erschöpfend enumerieren statt probabilistisch am HIL-Rig testen (→ K5) |
| Capability-Systeme (seL4) / Rusts Typsystem | Ein Recht ist ein *unfälschbares Datum*, kein geprüftes Flag | Der Sprung ins Image verlangt ein versiegeltes Handle, das nur die Verifikation erzeugen kann (→ K1) |
| CRDTs / Verbandstheorie | Replikat-Zustand als Halbverband: Merge ist kommutativ, idempotent, ordnungsunabhängig | TMR-Voting und WAL-Rekonstruktion als formaler Fold über einer Ereignis-Algebra (→ K6) |
| Buchhaltung / Blockketten-Grundidee | Verkettete, geschlüsselte Historie: Ändern der Vergangenheit ist erkennbar | Journal-Einträge mit gerätegebundener Hash-Kette statt nur CRC (→ K4) |
| Luftfahrt (N-Version) / Compilerbau | Grammatikfreiheit im kritischen Pfad: feste Offsets statt Parser | Der Core parst kein CBOR mehr — das Manifest hat im Boot-Pfad ein kanonisches Festformat (→ K2) |
| Betriebswirtschaft (Admission Control) | Beginne keine Transaktion, deren Abschluss du nicht bezahlen kannst | Energie-/Verschleiß-Budget als Zulassungsprüfung *vor* dem Swap statt Brownout-Recovery *nach* dem Swap (→ K7) |

---

## 3. Invertierte Constraints

| Heutige Annahme | Inversion | Neue Designfrage |
|---|---|---|
| „Verifikation setzt ein Flag, der Kontrollfluss prüft es" | Verifikation *erzeugt ein Artefakt*, ohne das der Sprung physisch nicht funktioniert | Wie sieht ein Sprung-Primitiv aus, das nur mit gültigem Beweis-Datum arbeitet? (K1) |
| „Der Core muss das Manifest parsen" | Der Core liest nur feste Offsets aus einer kanonischen Form | Wer kanonisiert, und was deckt die Signatur ab? (K2) |
| „Jede Update-Strategie hat eigene Resume-Logik" | Es gibt genau *einen* Executor, alle Strategien sind Effekt-Listen | Was ist die minimale Effekt-Algebra für Swap, Revert, Multi-Image? (K3) |
| „CRC schützt das Journal" | Das Journal beweist seine eigene Unverändertheit | Woran wird die Kette verankert, damit auch Voll-Replays alter Zustände auffallen? (K4) |
| „Crash-Konsistenz wird argumentiert und am HIL stichprobenartig getestet" | Crash-Konsistenz wird *aufgezählt* | Wie klein kann das deterministische Ereignisband sein? (K5) |
| „Die State-Machine ist Code" | Die State-Machine ist eine Tabelle, der Code ein Interpreter | Was lässt sich aus derselben Tabelle noch generieren — Tests, CFI-Sollmengen, Doku? (K6) |
| „Stromausfall mitten im Swap ist ein Recovery-Fall" | Er ist ein Planungsfehler | Welche Kostenmetadaten braucht die HAL, um ihn zu verhindern? (K7) |

---

## 4. Schwache Signale — was gerade machbar wird

**Bounded Model Checking erreicht die Embedded-Praxis.** Werkzeuge wie CBMC sind reif, werden
aber in Bootloader-Projekten fast nie eingesetzt. Toob-Boot ist dafür ungewöhnlich gut geeignet:
kein Heap, alle Schleifen explizit begrenzt (`MAX_LOOP_GUARD` existiert bereits), HAL als einziger
Hardwarezugang. Die im Code als Kommentar behaupteten „mathematischen Beweise" (TMR-Quorum,
Underflow-Guards) sind in Reichweite, *tatsächlich maschinell geprüft* zu werden.

**Deterministische Simulation verlässt die Datenbank-Nische.** Was FoundationDB vor 15 Jahren
etabliert hat, wird gerade als allgemeine Testarchitektur wiederentdeckt. Für einen Bootloader,
dessen gesamte Außenwelt hinter einer schmalen HAL liegt, sind die Kosten historisch niedrig.

**Kanonische Kodierungen werden Standard-Denkweise.** Deterministische CBOR-Profile und
Festformat-Manifeste machen es erstmals plausibel, im kritischsten Codepfad *gar keine* Grammatik
mehr zu parsen, ohne die Cloud-Seite ihrer Ausdruckskraft zu berauben.

**Lineare-Typen-Disziplin sickert in C-API-Design ein.** Rusts Ownership-Modell lässt sich in C
nicht erzwingen, aber als API-Form nachbilden: Funktionen, die nur mit einem unfälschbaren
Ergebnis-Datum der Vorgängerfunktion aufrufbar sind. Das ist Konvention plus Kryptografie statt
Compiler — schwächer als Rust, aber deutlich stärker als Statuscodes.

---

## 5. Die sieben Konzepte

### K1 — Beweis-tragende Boot-Handles
*Der Sprung ins Image ist nur mit einem Datum möglich, das ausschließlich eine erfolgreiche Verifikation erzeugen kann.*

**Kernmechanismus.** Heute liefert die Verifikation `BOOT_OK`, und später — nach Deinit, nach
einem *erneuten* Flash-Read des Headers — springt `jump_to_payload(active_slot + hdr.entry_point)`.
Ergebnis und Sprungziel sind entkoppelt; genau diese Lücke füllen derzeit CFI-Akkumulatoren und
Double-Checks. Die Inversion: Verifikation gibt ein versiegeltes Handle zurück, das alle
sprungrelevanten Daten *enthält*:

```c
typedef struct {
  uint32_t image_addr;
  uint32_t image_size;
  uint32_t entry_point;     /* aus dem Header, der gehasht und signiert wurde */
  uint32_t svn;
  uint32_t seal[2];         /* Keyed-Checksum über alle Felder */
} boot_proof_t;
```

Der Siegel-Schlüssel ist ein pro Boot einmal aus dem TRNG gezogener Wert, der nur der
Verify-Übersetzungseinheit bekannt ist. `jump_to_payload(const boot_proof_t*)` rechnet das Siegel
nach und verweigert bei Abweichung. Damit gilt: Ein Störimpuls, der die Verifikation überspringt,
hinterlässt kein gültiges Handle — der Sprung schlägt mit überwältigender Wahrscheinlichkeit fehl,
*ohne dass irgendein Kontrollfluss-Check dafür laufen muss*. Die Absicherung wird von einer
Kontrollfluss-Eigenschaft zu einer Datenabhängigkeit. Nebeneffekt: Der ungeprüfte Header-Re-Read
in `stage0_main.c` (der Entry-Point wird heute nach der Verifikation nochmal roh aus dem Flash
gelesen) verschwindet strukturell — der Entry-Point lebt im Handle, das zum Zeitpunkt der
Hash-Berechnung befüllt wurde.

**Wurzel.** Capability-Systeme; Typestate. In C nachgebildet über „Konvention + MAC" statt Typsystem.

**Warum gibt es das nicht?** Mainstream-Bootloader (MCUboot, wolfBoot) sind älter als diese
Denkweise und tragen Statuscode-APIs als Erbe. Zudem wirkt es redundant, *wenn* man CFI-Akkumulatoren
hat — übersehen wird, dass das Handle stärker ist: Es koppelt nicht nur „Verifikation lief",
sondern „Verifikation lief *über genau diese Daten*".

**Minimale Form.** `boot_proof_t` nur zwischen `stage0_try_boot_bank` und `jump_to_payload`
einführen (drei Funktionen berührt). Danach dieselbe Form für `boot_state_run` → `boot_main`
(ersetzt `target_out->active_entry_point`). Die CFI-Akkumulatoren bleiben zunächst als zweite,
unabhängige Schicht bestehen — §5.1-Unabhängigkeitskriterium bleibt erfüllt.

**Upside.** Weniger Prüfcode bei stärkerer Garantie; die verbleibenden CFI-Checks schrumpfen auf
die Pfade, wo wirklich Ablauf- statt Datenintegrität gefragt ist.

---

### K2 — Der Core parst keine Grammatik
*Das Manifest hat im Boot-Pfad ein kanonisches Festformat; CBOR bleibt, wo ein volles OS läuft.*

**Kernmechanismus.** Der größte importierte Komplexitätsblock im kritischsten Codepfad ist der
zcbor-Parser samt seiner Folgekosten: 53 Voll-Ketten-Zugriffe, Pointer-Sandboxing gegen die Arena,
`is_buffer_within` in zwei Kopien. Die Inversion: Für den Bootloader wird ein Festformat definiert
(„TBM1" — versionierter Header, feste Feld-Offsets, definite Längen, keine optionalen Umsortierungen).
Der „Parser" degeneriert zu bounds-geprüften Feld-Reads mit konstanten Offsets — etwa 100 Zeilen,
vollständig durchprüfbar, keine rekursiven Strukturen, kein Zustandsautomat. Die Signatur deckt
die TBM1-Bytes ab. Die Registry erzeugt TBM1 direkt aus dem Build; auf Transport- und Cloud-Ebene
darf das Ganze weiterhin in CBOR/SUIT-Hüllen reisen — die Hülle ist unsigniert und wird vor dem
Staging von libtoob (das ein volles OS unter sich hat) abgestreift.

**Wurzel.** Grammatikfreiheit im kritischen Pfad (Luftfahrt-Denkweise) plus kanonische Kodierung.

**Warum gibt es das nicht?** SUIT/CBOR ist der Interop-Standard, und die Versuchung ist groß,
denselben Parser überall zu verwenden. Der Preis — ein Grammatik-Parser in der vertrauenswürdigsten
Komponente — wird selten explizit gemacht. Ehrlicher Trade-off: TBM1 kostet SUIT-Interop *auf
Geräteebene* (nicht auf Cloud-Ebene) und eine Migrationsphase mit Doppel-Support. Für ein Produkt,
dessen Kaufargument „auditierbarer, minimaler Core" ist, ist das eher ein Feature als ein Verlust —
„der Core enthält keinen Parser" ist ein Satz, der in einem Zertifizierungsgespräch trägt.

**Minimale Form.** TBM1-Spec (eine Seite), Encoder im Manifest-Compiler, 100-Zeilen-Reader im Core,
Feature-Flag `TOOB_MANIFEST_TBM1` parallel zum bestehenden Pfad. Messen: Diff der Codegröße und der
Zyklomatik von `stage_parse`/`stage_verify_envelope`.

**Upside.** Der Trusted-Core schrumpft um Tausende Zeilen Fremdcode; das komplette
Pointer-Sandboxing entfällt, weil es keine parser-generierten Pointer mehr gibt.

---

### K3 — Idempotente Effekt-Transaktionen
*Swap, Revert und Multi-Image sind keine drei Algorithmen, sondern drei Pläne für denselben Executor.*

**Kernmechanismus.** Heute implementieren `boot_swap.c`, `boot_rollback_trigger_revert` und
`boot_multiimage.c` jeweils eigene Schleifen mit eigener Checkpoint-/Resume-Logik
(`delta_chunk_id`, WAL-Checkpoints vor destruktiven Erases, Zero-Wear-Identity-Checks — dreimal
ähnlich, nie identisch). Die Inversion, direkt aus dem Datenbank-Redo-Log: Jede destruktive
Operation wird als idempotenter Effekt beschrieben:

```c
typedef struct {
  uint8_t  op;            /* ERASE | COPY */
  uint32_t src, dst, len;
  uint32_t post_crc;      /* Soll-Zustand von dst NACH dem Effekt */
} flash_effect_t;
```

Ein *Planner* (reine Funktion, schreibt nichts) übersetzt „Swap Staging→App" oder „Revert" in eine
Effekt-Liste; ein *Executor* ist der einzige Code im ganzen Core, der `erase`/`write` aufruft.
Seine Regel pro Effekt: Stimmt `post_crc` bereits — überspringen (schon passiert). Sonst ausführen
und per Read-Back gegen `post_crc` verifizieren. Recovery nach Stromausfall ist damit trivial:
*dieselbe Liste nochmal von vorn ausführen.* Idempotenz ersetzt drei Resume-Buchhaltungen durch
gar keine. Der bestehende Zero-Wear-Skip und der Phase-Bound-Read-Back sind im Executor genau
einmal implementiert. Die Region-Whitelist des Multi-Image-Pfads wird zweifach geprüft — im
Planner und im Executor — womit die geforderte Unabhängigkeit zweier Verteidigungslinien nicht
extra gebaut werden muss, sondern aus der Architektur herausfällt.

**Wurzel.** Redo-Logging; Konvergenz durch Idempotenz statt durch Positionszeiger.

**Warum gibt es das nicht?** MCUboots Swap-Status-Mechanik ist das nächste Verwandte, aber pro
Strategie handgestrickt. Die Verallgemeinerung scheitert historisch daran, dass Bootloader
gewachsen sind: erst Swap, dann Revert dazu, dann Multi-Image — jedes Mal war die lokale Kopie
billiger als die Abstraktion. Toob-Boot steht früh genug, um das zu drehen.

**Minimale Form.** Executor + Planner nur für den Revert-Pfad (der einfachste), Äquivalenztest
gegen die bestehende Implementierung über den deterministischen Replayer aus K5. Danach Swap,
zuletzt Multi-Image.

**Upside.** Eine einzige, kleine Komponente trägt die gesamte Crash-Konsistenz-Beweislast; K5 kann
sie erschöpfend durchleuchten. Geschätzt −400 bis −600 Zeilen bei *steigender* Garantie.

---

### K4 — Das Journal beweist seine eigene Geschichte
*WAL-Einträge werden gerätegebunden verkettet; Ändern oder Zurücksetzen der Historie ist erkennbar, nicht nur Zufallskorruption.*

**Kernmechanismus.** CRC-32 im WAL erkennt Bitfehler — aber der Bedrohungsannahme des restlichen
Systems (jemand kann externen Flash beschreiben, sonst bräuchte es keine Signaturen) hält das
Journal nicht stand: Fehlerzähler zurücksetzen, den Lock-Intent tilgen, die advisory SVN-Untergrenze
absenken — alles CRC-konform fälschbar. Die Inversion: Jeder Eintrag trägt
`tag_n = H(k_dev, entry_n ‖ tag_{n−1})` mit einem *pro Gerät individuellen* Schlüssel (abgeleitet
aus dem bereits vorhandenen Identitätsmaterial: Chip-UID + Fuse-Geheimnis via KDF). Der
Sektor-Header verankert den Kettenkopf, und bei jeder TMR-Rotation wird zusätzlich die aktuelle
eFuse-Epoche in die Kette eingebunden — damit fällt auch ein *Voll-Replay* eines komplett alten,
in sich konsistenten WAL-Abbilds auf, sobald die Epoche je fortgeschritten ist.

Ehrliche Grenzen: Innerhalb einer Epoche bleibt ein Voll-Replay unentdeckt (der eFuse-Zähler ist
der einzige monotone Anker, und er wird bewusst sparsam gebrannt). Und der Mechanismus setzt ein
gerätegebundenes Geheimnis voraus, das die HAL liefern muss — auf Chips ohne geschützten
Schlüsselspeicher degradiert die Kette zu einem Erkennungsmittel gegen Akteure ohne Codeausführung.
Beides gehört als Annahme in `security_model.md`, nicht unter den Teppich.

**Wurzel.** Verkettete, geschlüsselte Verlaufsprotokolle (Buchhaltungsprinzip).

**Warum gibt es das nicht?** Bootloader-Journale entstanden als Brownout-Schutz, nicht als
Manipulationsschutz; die Bedrohungsannahme wurde nie nachgezogen, als die Journale anfingen,
sicherheitsrelevante Größen (SVN-Floors, Lock-Zustände) zu tragen. Genau das tut Toob-Boot heute.

**Minimale Form.** Kette nur für die drei sicherheitstragenden Intents (LOCKED, SVN-relevante
TMR-Updates, CONFIRM) einführen; alle anderen Einträge bleiben CRC-only — das begrenzt die
Hash-Kosten pro Boot auf eine Handvoll Aufrufe.

**Upside.** Die im Stage-0-Kommentar heute ehrlich als „advisory" bezeichnete WAL-Untergrenze wird
zu einer belastbaren zweiten Verteidigungslinie neben der eFuse-Epoche — echte Unabhängigkeit im
Sinne von §5.1 statt zwei Checks, von denen einer weich ist.

---

### K5 — Boot als reine Funktion: aufzeichnen, abspielen, aufzählen
*Crash-Konsistenz wird nicht argumentiert, sondern enumeriert.*

**Kernmechanismus.** Die gesamte Außenwelt des Cores läuft bereits durch die HAL — die Architektur
erzwingt das. Der fehlende Schritt: eine Record/Replay-Schicht um die HAL. Im Record-Modus wird
jeder Aufruf samt Rückgabedaten auf ein Ereignisband geschrieben (am HIL-Rig oder im Host-Modell);
im Replay-Modus wird das Band bit-exakt zurückgespielt — inklusive TRNG-Werten, womit auch
CFI-Seeds reproduzierbar werden. Darauf baut der eigentliche Gewinn: der *Unterbrechungs-Enumerator*.
Ein nomineller Update-Boot enthält W Flash-Schreiboperationen. Für jedes i ∈ 1…W (plus
Torn-Write-Varianten: Präfix-Bytes des i-ten Writes): Band bei i kappen, resultierendes Flash-Abbild
festhalten, darauf einen frischen Boot laufen lassen, Invarianten prüfen — bootet; genau ein
konsistenter TMR-Zustand (alt *oder* neu, nie gemischt); kein Intent verloren. Was heute als
Kommentar dasteht („Mathematischer Beweis: Fällt der Strom nach [n+1] …"), wird zu einem
CI-Job, der *alle* Fälle durchrechnet statt drei am Rig zu stichproben. Ergänzend, wo die
Schleifen es hergeben: dieselben Invarianten als CBMC-Harness über dem Journal-Reducer —
der Code ist mit seinen expliziten Schleifengrenzen dafür ungewöhnlich gut konditioniert.

**Wurzel.** Deterministische Simulation (FoundationDB); Bounded Model Checking.

**Warum gibt es das nicht?** In Bootloadern historisch, weil die Hardware-Abstraktion selten
vollständig ist — irgendwo liest doch jemand ein Register direkt. Toob-Boot hat diese Disziplin
bereits bezahlt; der Ertrag wird nur noch nicht abgeholt.

**Minimale Form.** HAL-Shim (Record/Replay) + Host-Flash-Modell als Datei + Enumerator über den
Revert-Pfad. Ein Wochenende für den Shim, nicht für den Enumerator — der ist die eigentliche Arbeit.

**Upside.** Jede weitere Architekturänderung (K1–K4, K6) bekommt ein Sicherheitsnetz mit
Beweischarakter. Fürs Zertifizierungs-Narrativ (EN 18031, „Nachweis der Robustheit") ist ein
enumerierter Konsistenznachweis ein Alleinstellungsmerkmal, das kein Wettbewerber vorlegt.

---

### K6 — Zustandslogik als Daten: Intent-Algebra und Tabellen-Pipeline
*Eine Tabelle ist die einzige Quelle der Wahrheit; Reducer, Tests, CFI-Sollmengen und Doku werden aus ihr abgeleitet.*

**Kernmechanismus.** Zwei Umbauten mit demselben Prinzip. Erstens: Die Intent-Übergangslogik
(heute verteilt über `reconstruct_txn`-Sonderfälle, Step-2-Normalisierung, `_handle_update_result`-
Fehlertopologie) wird eine statische Tabelle `{intent, ereignis} → {folge_intent, aktion,
fehlerklasse}`. Der Runtime-Reducer interpretiert sie; ein Host-Test iteriert *alle* Paare und
beweist Totalität — kein undefinierter Übergang, keine „Intent-Amnesie" mehr als Bugklasse, weil
Vergessen jetzt ein Tabellenloch ist, das der Test findet. Zweitens: Die Update-Pipeline (P6 hat
die Stage-Zerlegung schon geschaffen) wird eine Stage-Tabelle `{fn, cfi_slot, fehlerpolitik}`;
der Driver läuft sie ab, und — entscheidend — die CFI-*Sollmenge* wird aus derselben Tabelle
aufgebaut statt aus handgepflegten `boot_cfi_add_expected`-Listen. Heute wird der PQC-Slot je nach
Zweig nachträglich zur Sollmenge addiert; das ist clever, aber genau die Sorte Kopplung, die bei
der nächsten Stage stillschweigend bricht. Aus der Tabelle generiert ein Build-Schritt zusätzlich
das Zustandsdiagramm für die Doku — Code, Test und Dokumentation können nicht mehr divergieren.

**Wurzel.** Interpreter-Muster; die Verbands-Sicht aus der CRDT-Welt für die kommutativen Anteile
(Wear-Zähler, Accums), bei denen Rekonstruktionsreihenfolge beweisbar egal ist.

**Warum gibt es das nicht?** Tabellengetriebene State-Machines gelten als „Enterprise-Overhead"
für 1-kB-Bootloader. Der Denkfehler: Die Tabelle kostet keinen RAM (rodata) und der Interpreter
ist kleiner als die heutige if-Kaskade — der Widerstand ist kulturell, nicht technisch.

**Minimale Form.** Nur die Fehlertopologie aus `_handle_update_result` in eine Tabelle ziehen
(Reject-Liste als Daten) plus den Totalitätstest. Danach die Stage-Tabelle.

**Upside.** `boot_state_run` fällt geschätzt von ~1200 auf ~400 Zeilen; die Review-Einheit für
einen Auditor wird „eine Tabelle plus ein 50-Zeilen-Interpreter".

---

### K7 — Energie-bewusste Zulassung: nichts beginnen, was man nicht beenden kann
*Brownout mitten im Swap ist kein Recovery-Fall, sondern ein vermeidbarer Planungsfehler.*

**Kernmechanismus.** Der Flash-HAL-Deskriptor wird um Kostenmetadaten erweitert (maximale
Erase-Zeit pro Sektor, Write-Zeit pro Page, optional `get_supply_mv()`). Der Planner aus K3
liefert ohnehin die vollständige Effekt-Liste — ihre Worst-Case-Kosten (Zeit, Energie, Erases)
sind damit vor dem ersten destruktiven Schreibzugriff bekannt. Eine Zulassungsprüfung vergleicht
mit dem verfügbaren Budget (Spannungslage, konfigurierter Margin, Rest-Erase-Zyklen aus den
TMR-Wear-Countern): Reicht es nicht, wird der Update-Intent per bestehendem
`WAL_INTENT_SLEEP_BACKOFF`-Mechanismus vertagt und das alte Image gebootet — der Brownout mitten
im Swap findet nicht statt, statt hinterher repariert zu werden. Die Recovery-Maschinerie bleibt
als zweite Linie vollständig erhalten; sie wird nur seltener gebraucht.

**Wurzel.** Admission Control; Transaktionsplanung.

**Warum gibt es das nicht?** Bootloader entstehen auf Dev-Boards am Netzteil; Batteriegeräte
erben sie. Kein verbreiteter Bootloader kennt den Ladezustand des Geräts, auf dem er läuft. Für
ein Unternehmen, dessen zweites Produkt eine Powerbank ist, liegt hier eine seltene Deckung von
technischer Substanz und Produktgeschichte: „Der Bootloader von Leuten, die Batteriegeräte bauen."

**Minimale Form.** Nur die Erase-Budget-Prüfung (Wear-Counter vs. `max_erase_cycles`, Daten sind
schon da) als Zulassungsgate vor `stage_swap`. Spannung als zweiter Schritt, wo die HAL es hergibt.

**Upside.** Messbar weniger Recovery-Läufe im Feld, längere Flash-Lebensdauer — und eine
Differenzierung gegenüber MCUboot/wolfBoot, die in keiner Feature-Matrix der Konkurrenz auftaucht.

---

## 6. Härtetest — was davon ist wirklich neu?

**K1** ist keine umbenannte Bestandstechnik: Kein verbreiteter Bootloader fusioniert
Verifikationsergebnis und Sprungdaten in ein versiegeltes Datum; das Nächstliegende sind
TOCTOU-Vermeidungsregeln in Coding-Guidelines. An einem Wochenende baubar — aber die Idee ist die
API-Form, nicht der Aufwand. Hält stand.

**K2** ist als Prinzip bekannt (Festformate), als Positionierung im Bootloader-Markt aber
unbesetzt — alle relevanten Wettbewerber parsen TLV oder CBOR im Core. Der Widerstand kommt vom
SUIT-Ökosystem; die Hybrid-Antwort (CBOR als Transport, TBM1 als signiertes Kernformat) ist der
Punkt, an dem das Konzept steht oder fällt. Hält stand, mit benanntem Trade-off.

**K3** ist teilweise derivativ — MCUbouts Swap-Status ist ein Spezialfall. Neu ist die
Verallgemeinerung auf *einen* Executor mit Idempotenz als einziger Recovery-Regel. Ehrlich
eingeordnet: Evolution mit hohem Wert, keine Revolution.

**K4** ist konzeptionell Standardtechnik aus anderen Feldern; die Neuheit ist moderat, der Wert
hoch, weil er eine real existierende weiche Stelle (advisory Floor) härtet. Bewusst als
„Wert > Neuheit" geführt.

**K5** ist in Datenbanken etabliert, in der Bootloader-Praxis meines Wissens ohne
Produktionsbeispiel. Die Voraussetzung (lückenlose HAL-Disziplin) ist hier bereits erfüllt —
das ist der seltene Fall, in dem die Barriere schon gefallen ist und es niemand gemerkt hat.
Stärkstes Konzept im Set.

**K6** riskiert, „nur" solides Engineering zu sein. Der Neuheitsanteil ist die Ableitung der
CFI-Sollmengen aus der Tabelle — das koppelt eine Störschutz-Eigenschaft an die
Ablaufbeschreibung selbst und ist mir aus keiner Codebasis bekannt. Bleibt drin.

**K7** ist echt selten. Wer würde sich sperren? Vendor-gebundene Ökosysteme, deren Geschäftsmodell
auf „unser Chip, unser Bootloader" beruht und die keinen Anreiz haben, HAL-Kostenmetadaten zu
standardisieren — was für einen vendor-neutralen Anbieter ein Argument *für* das Feature ist.

---

## 7. Reihenfolge und Abhängigkeiten

K5 zuerst — nicht weil es das spektakulärste ist, sondern weil es das Sicherheitsnetz für alles
Weitere spannt: Jeder folgende Umbau wird gegen aufgezeichnete Referenzläufe und den
Unterbrechungs-Enumerator verifiziert statt gegen Hoffnung. Danach K6 (Tabellen), weil es die
Fläche verkleinert, auf der K3 operiert. Dann K3 (Effekt-Executor), das von K6er-Struktur und
K5er-Netz gleichermaßen profitiert und K7 als billiges Anhängsel mitbringt. K1 (Handles) ist
davon unabhängig und kann parallel laufen — es berührt nur Schnittstellen, keine Algorithmen.
K4 (Journal-Kette) setzt die HAL-Schlüsselfrage voraus und gehört in denselben Planungsblock wie
die DICE/KDM-Arbeit. K2 (Festformat) zuletzt: höchster Koordinationsaufwand (Registry,
Manifest-Compiler, Migrationsfenster), größter Einzelgewinn an Core-Minimalität — das richtige
Finale, das falsche Fundament.

Ein letzter Maßstab, an dem sich jeder dieser Umbauten messen lassen sollte: Nach dem Umbau muss
ein externer Auditor *weniger* Code lesen, um *mehr* Garantien zu verstehen. K1, K2, K3 und K6
bestehen diesen Test unmittelbar; K4, K5 und K7 fügen Code hinzu, aber ausschließlich außerhalb
des Boot-Pfads oder in klar abgegrenzten, einzeln prüfbaren Komponenten.