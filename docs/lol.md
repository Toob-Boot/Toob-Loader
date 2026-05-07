Bitte dokumentiere mal in einer neuen .md in docs/ oder nahe an den passenden scripts, wie die Abhängigkeiten wie gehandhabt werden. Wir engineeren das jetzt hoch, weil ich kann mir diese Angst vor dem Ungewissen nicht ganz leisten, wenn wir nen funktionierenden Registry ähnlich zu package-Managern bauen wollen.

Denk einerseits an unsere Überlegungen und logischen Abhängigkeiten.

arch, vendor, toolchains -> Chip + Compiler + Core + CLI -> registry

Die Ebenen werden grob durch die "->" getrennt.

Hier möchte ich, dass du alle Datenmodelle dazu jeweils mappst (inklusive path und sonst was), so dass wir merken, was was auslösen sollte.

Und dann prüfen wir, wo ein Versions-Update (wo die SemVer Nummer zugewiesen wird) bei den einzelnen Datenpunkten unserer Schichten getriggert wird. Und welche das sonst noch triggert. Weil untere Dependencies sollten höhere Updates auch mit auslösen.

Und es sollte auch die Update-Typen mitausgelöst/vererbt werden. Bspw.:

Patches x.x.1.
Minor Changes x.1.x
oder Major/Breaking Changes 1.x.x

in einer der zugrundeliegenden Dependencies ausgelöst wurde.

Das muss alles nach oben vererben, aber nicht nach unten.

Dabei sollte für jeden Datenpunkt (arch/vendor/chip/registry/compiler/cli...) einzeln ein Update auslösbar sein. Immer ausgelöst durch Commits bzw. PR Merges (in Zukunft) die dann eine solche Kette auslösen entweder bei einzelnen oder mehreren einzelnen. und dann sollte immer der höchste Update-Typ gewertet werden für den Commit. Bspw. wenn ein minor change und ein Patch ankommen an 2 verschiedenen Stellen und vendor ist minor und chip ist nur nen patch, dann ist 1. der Chip-Change dennoch ein Minor Change weil der vendor (solange er eine dependency von IHM spezifisch ist) ein höherer Update Typ war als er. Und das geht dann hoch bis zur registry, die dann auch nen minor change Update bekommt. sprich x.+1.x hoch. Registry ist ganz oben und mit ihr wird dann immer nach und nach auch die compatibility matrix ausgefüllt. Durch die neue Hintergrund Matrix wissen wir, welche dann zu dem Zeitpunkt noch nicht gescannt wurden, aber welche soweit gescannt zumindest mal kompatibel sind. Diese Infos nutzen dann die CLIs um Builds im vorhinein zu verifizieren o.Ä..

Das will ich alles prüfen, ob das aktuell überall passt.

Prüfe mit mir den Ist Stand dieser Beschreibung und was besser/schlechter ist.

# Arbeitspakete:

Ich würde machen, dass wir probieren, auch den PR-Jail DIngern so viel zu geben, wie geht. AUßerdem musst du mir mal erklären: Ich hatte mir es so orgestellt, dass man

einen Orchestrator hat, der die ANDEREN Container orchestriert (worker.go) oder ein anderer. Dann haben wir die PR-JAils, die Act-Releases und die Nightly Tests für die Matrix. Die 3 haben jeweils eigene Container.

Der Orchestrator ist immer da und verwaltet IMMER die anderen Container und plant, hat ne Arbeits-Queue, die er optim,iert und priorisiert plant und auch die Queue quasi anhand der Trigger entgegennimmt.

Dabei gibt es erstmal verschiedene Aufgabenpakete, die sich auf PR-Tests, Releases und Eben Kompatibilitäts-Matrix-Tests verteilen. Die Kompatibilitätsmatrizen sind pro registry Version in ein Paket aufgeteilt und beinhalten dann alle Tests, die durch diese registry Version ausgelöst werden. So können wir priorisieren, welche test-Kombis zuerst geprüft werden müssen.

Unter Kompatibilitäts-Tests (niedrigste Prio an Paketen insgesamt) ist die Prio dann wie folgt:

- älteste Registry-Version zugeordnete Tests zuerst
- Dann in einer solchen Reihenfolge, dass gleiche Compiler-Container darin immer gespawned bleiben, um nicht den gleichen Containter 7x zu installieren oder so pro Arbeits-Paket.
- und dann eben einfach Stück für Stück abarbeiten und die, die noch nicht fehlgeschlagen sind zuerst.

Dann geht es in die höhere Prio an Paketen: Die PR-Test Pakete.

- hier wird irgendwie anhand eines Algorithmus die Kompatibilität getestet indem nur wenige ausgewählte aber so representativ verteilt wie Möglich stichweise Kombinationen aus historischen Daten neu kompiliert werden mit dieser Version an Änderungen eben
- Es bricht ab sobald 1 fehlschlägt, aber es wird sauber heruntergefahren und die Logs sind irgendwo hingeschickt dann (vermutlich github Commit oder so)
- ältere PR-Test-Pakete werden zuerst priorisiert
- Falls sinnvoll auch hier wieder die Compiler-Keeper Logik, so dass Compiler Container so wenig wie möglich hochgefahren werden müssen, sondern eben wenn verschiedene Kombos mit dem gleichen Compiler Image stattfinden sollen, die alle in Reihe im gleichen Container durchgeführt werden.

Dann geht es zu den Releases (höchste Priorität):

- Diese sollen immer so schnell wie möglich passeren. Sobald ein anderes Paket bzw dessen Subtasks sauber beendet wurde wird dann der Release Container gespawnt und arbeitet alles ab.

Es soll immer 2 Container geben, die arbeiten und immer den einen Orchestrator Container geben. Der Orchestrator übernimmt die Priorisierung und das Queueing wie gerade beschrieben und plant quasi immer den anhand der Aufgaben berechneten idealen durchführungszyklus. Dabei reagiert er auf Anpaassungen aber erst, wenn er alle Anpassungen (bspw. durch neue AUfgabenpakete oder weitere Tests in der Test-Queue) passt er das ganze an und released seinen jetzigen Stand, der auf jeden Fall von dem Stand ausgeführt werden kann, der ist, während er schreibt. Während er seinen Ausführungsplan optimiert dürfen andere Container zwar weiterlaufen und ihre Tasks beenden, aber keine neuen Kompilierungen anfangen bspw. oder nicht einfach gelöscht werden oder irgendwas machen. nur ihren Task beenden. Damit vom neu geplanten Weg immer der nächste Schritt genau da weitergeführt werden kann, wo aufgehört wurde - ohne Race-Conditions.

Bedenke auch, dass es nicht nur die Compiler-Images gibt sondern auch PR-Tests. Die sind zwar eigentlich auch nut Compiler alle, aber eben die PR-Jails sollen nochmal irgendwie sicherer sein. Oder wir machen die alle gleich sicher zu PR-Jails und so dass es passt. Nur das CLI-Release-Container Image ist ein anderes, weil es Go kompiliert für die CLI.

Soweit verständlich und wo sind wir im Vergleich dazu?

---

# Architektur-Dokumentation & Ist-Stand (Stand: Mai 2026)

## 1. Dependency Mapping & Vererbung

Die logische Kette der Abhängigkeiten ist im `registry.json` Schema (und den dazugehörigen Generator-Skripten) wie folgt verankert:

**Ebene 1: Architektur & Vendor & Toolchain**
- Dateien/Pfade: Definiert im `registry.json` als Root-Objekte (`"vendors"`, `"archs"`, `"toolchains"`).
- Diese Layer bilden die rohen Metadaten für das Zielsystem.

**Ebene 2: Chip + Compiler + Core SDK + CLI**
- Dateien/Pfade: Definiert unter `"chips"` im `registry.json`. Ein Chip bindet sich per `vendor`, `arch` und `compiler_prefix` an Ebene 1.
- Releases für Core SDK, Compiler und CLI werden per GitHub Actions als Tags erzeugt und vom `matrix_generator.go` dynamisch eingelesen.

**Ebene 3: Registry & Matrix**
- Dateien/Pfade: `registry.json` (Struktur) und `compatibility_matrix.json` (Ergebnisse).
- Dies ist die finale Schicht, die den Ist-Zustand aller validierten Kombinationen speichert.

### SemVer Update Propagation (Vererbungs-Logik)

Updates kaskadieren strikt von **unten nach oben** (von Ebene 1 zu Ebene 3), aber nie rückwärts:
- **Major (1.x.x)**, **Minor (x.1.x)**, **Patch (x.x.1)**
- Wenn eine Toolchain (Ebene 1) ein `Patch`-Update erhält, und zeitgleich ein Chip (Ebene 2) ein `Minor`-Update, so ist der auslösende Release für die Matrix mindestens ein **Minor** Update.
- Die Vererbung bedeutet: Die oberste Instanz (Registry/Matrix) übernimmt immer den **höchsten SemVer-Schweregrad** des auslösenden Sub-Moduls. So wird sichergestellt, dass bei einem Breaking Change in einem Submodul (Major) auch die resultierende Registry-Version als Major-Version gekennzeichnet wird, um Clients vor Inkompatibilitäten zu warnen.

## 2. Toob-CI Orchestrator v2 (Aktueller Stand)

Die Orchestrator-Architektur wurde exakt nach der oben beschriebenen Vision als **Container-Orchestrierungs-System** realisiert:

### Das Two-Queue System (Inbox & Planner)
- **Inbox (To-Be-Planned Queue):** Neue Events (PR-Webhooks, Matrix-Runs) landen chronologisch in einer threadsicheren Inbox. Das verhindert Race-Conditions.
- **Planner (Execution Queue):** Der `planningLoop` leert die Inbox, plant die Ausführung (Sortierung nach Priorität, Registry-Version und Compiler), und reicht die Pakete (WorkPackages) blockierungsfrei an die beiden Slots weiter.

### Compiler-Keeper Logik (`session.go`)
- Um Docker-Overhead zu vermeiden, bleiben Compiler-Container über eine "Session" am Leben (`sleep infinity`).
- Alle Tests, die denselben Compiler (z.B. `gcc-13.2`) benötigen, werden nacheinander per `docker exec` im selben Container abgearbeitet. Erst danach wird der Container sauber beendet.

### Intelligentes PR-Jail Sampling
PR-Tests prüfen nicht blind "alles" oder "nichts", sondern nutzen die Matrix für einen effizienten Schnitt:
1. **Latest 100%:** Die allerneueste Kombination aus CLI, Core und Compiler wird für *alle* bekannten Chips komplett durchgetestet. (Sichert ab, dass der neueste Stand fehlerfrei bleibt).
2. **Historisches Sample:** Aus der `compatibility_matrix.json` werden ältere, bereits verifizierte Kombinationen gelesen. Daraus wird ein randomisiertes Sample (z.B. 5 Kombinationen) gezogen, um sicherzustellen, dass Abwärtskompatibilität gewahrt bleibt, ohne Tausende historische Tests neu zu kompilieren.

### Memory Budgeting
Der Orchestrator läuft als reiner Scheduler (ca. 200MB RAM). Die zwei parallelen Worker-Slots und der Release-Runner (`act -j 1`) sind auf jeweils `1.5GB` RAM limitiert, um auf einer 4GB Instanz niemals Out-Of-Memory Fehler auszulösen.
