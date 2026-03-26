# Gap-Analysis V2: Toob-Boot Architektur-Synthese (Refined)

Nach der Implementierung der ersten Mitigationen (wie Recovery-Zustandsmaschine, WAL-Ringpuffer, WDT-Pflicht) wurde das aktualisierte Dokument `concept_fusion.md` einer erneuten, tiefergehenden Prüfung nach dem `@/gap-analysis` Workflow unterzogen. 

Dabei haben sich komplexere logische Risse "auf den zweiten Blick" offenbart, insbesondere was das Zusammenspiel von Hardware-Limitationen, Kryptografie und Edge-Cases beim Kaltstart angeht.

Hier sind die neu identifizierten Gaps und ihre optimalen Mitigationen:

### 1. Die Kaltstart-Falle beim uninitialisierten RTC-RAM Confirm-Flag (Logic Error / Reliability)
**Problem:** In Abschnitt 1A wird vorgeschlagen, das OS Confirm-Flag im uninitialisierten RTC-RAM abzulegen, um das OS vom Flash-Treiber zu entkoppeln. Wenn das Gerät nach dem ersten Booten der neuen Firmware regulär hochfährt, schreibt das OS das "OK" ins RTC-RAM. Zieht der Nutzer nun jedoch zufällig den Stecker (Kaltstart / Power Loss), ist der flüchtige RTC-RAM beim nächsten Boot gelöscht. Der Bootloader wacht auf, findet das Flag nicht, wertet dies fälschlicherweise als "App-Crash" und führt ungewollt einen **katastrophalen Rollback** der eigentlich intakten neuen Firmware durch.
**Mitigation:** Das RTC-RAM darf nur ein zwischenzeitlicher Signalgeber sein. Das OS schreibt `0xOK` ins RTC-RAM und triggert einen schnellen **Software-Reset**. Der Bootloader liest beim Warmstart das Flag aus dem RTC-RAM, schreibt den endgültigen `TXN_COMMIT` in seinen non-volatilen WAL (Flash) und löscht das RTC-RAM. Erst danach bootet er das OS endgültig. So ist das Flag stromausfallsicher im Bootloader-Flash verbucht, ohne dass das OS einen eigenen Flash-Treiber braucht.

### 2. Signatur-Bruch durch In-App-Flash Confirm-Flag (Security / Logic)
**Problem:** Als Alternative zum RTC-RAM wird in Abschnitt 1A vorgeschlagen, das Flag "am letzten rohen Sektor-Byte der App" (im Flash) zu setzen. Das modifiziert jedoch den physischen App-Slot (Slot A). Da das SUIT-Manifest das gesamte Image mittels Merkle-Tree oder Root-Hash absichert, **bricht diese Änderung sofort die kryptografische Signatur** der App. Beim nächsten Boot würde die Signaturprüfung fehlschlagen und das Gerät bricken oder fälschlich rollbacken.
**Mitigation:** Streiche die "Letztes App-Sektor-Byte"-Idee komplett aus dem Konzept. Das Confirm-Flag darf den App-Slot niemals verändern. Wenn ein Flash-basiertes Flag genutzt wird, muss es zwingend im dedizierten Journal/WAL verortet sein (via OS-zu-Bootloader Syscall oder der oben beschriebenen RTC_RAM+Reset Methode).

### 3. Key-Revocation in ROM führt zum irreparablen Brick (Hardware / Security)
**Problem:** Abschnitt 1A fordert für Stage 0 eine "Key-Revocation über Hardware-eFuses/OTP". eFuses sind Write-Once-Read-Many (WORM). Wenn man einen kompromittierten Public Key in Stage 0 "verbrennt", verliert die Immutable Core Stage 0 den Key. Wie aber soll Stage 0 einen *neuen* Key lernen, wenn der Code im ROM (Read-Only) festsitzt? Ein simples "Verbrennen" des Keys macht das Gerät zu einem Ziegelstein, da Stage 0 keine Stage 1 mehr validieren kann.
**Mitigation:** Das Konzept muss eine **Key Rotation Strategy via Key-Index** spezifizieren. In Stage 0 (ROM) oder in einem gesicherten eFuse-Array müssen von Haus aus *mehrere* Public-Key-Hashes (z.B. 4 Slots) vorgehalten werden. Ein "Key-Revocation"-Vorgang brennt ein Bit durch, wodurch der Hardware-Bootloader automatisch auf den 2., 3. oder 4. vorprogrammierten Key-Slot im ROM/eFuse ausweicht.

### 4. Delta-Patching (1-Sector-Swap) Logikfehler bei Stream-Abhängigkeiten (Data Loss Risk)
**Problem:** Abschnitt 3 erklärt den 1-Sector-Swap: `Diff im RAM -> Puffer Sektor -> WAL Commit -> Überschreibe App Slot A`. Wenn ein Delta-Patch angewandt wird, referenziert er oft Bytes des alten Images. Wenn man Slot A blockweise in-place überschreibt, vernichtet man potenzielle Referenzdaten (Originaldaten), die das Delta-Patch für einen *späteren* Block noch benötigen könnte. Standard-Delta-Ansätze (wie `bsdiff`) verlangen wahlfreien Zugriff auf das gesamte alte Image.
**Mitigation:** Das Konzept muss explizit vorschreiben, dass der Delta-Patcher strictly **Forward-Only, Non-Overlapping** arbeiten muss (z.B. spezielle In-Place Patch-Algorithmen wie `detools` im In-Place-Modus). Der Patcher muss vom Host-Compiler so generiert und validiert (Preflight-Report, Schicht 5) werden, dass er garantiert nur auf Source-Bytes zugreift, die physisch noch *nicht* vom 1-Sector-Swap überschrieben wurden.

### 5. Fehlende Delta-Patch Downgrade Protection (Security)
**Problem:** In Schicht 3 ist eine Anti-Rollback (SVN) Implementation beschrieben. Abschnitt 3 erlaubt Delta-Patches. Ein Angreifer könnte einen Delta-Patch senden, der die App von (z.B.) v5.0 auf eine anfällige v4.0 manipuliert. Wenn der Bootloader erst patcht und am Ende den neuen SVN prüft, hat das Gerät Ressourcen, Flash-Zyklen und RAM verschwendet, nur um den Patch dann abzulehnen.
**Mitigation:** Das SUIT-Manifest für den Delta-Patch muss zwingend `Target_Manifest_SVN` und `Source_Manifest_SVN` trennen. Der Bootloader muss *vor dem Starten* des Patch-Vorgangs prüfen: `if (Target_Manifest_SVN < Hardware_SVN) -> Reject`. 

### 6. Speicherüberlauf beim SUIT-Manifest Parsing (Efficiency / Maintainability)
**Problem:** Schicht 1 listet standardmäßig ein `malloc-frei` laufendes System auf. Schicht 3 fordert einen SUIT-Manifest-Parser (CBOR basiert). SUIT-Manifeste können stark variable Längen an URIs, Textbeschreibungen und Signaturen enthalten. Einen generischen CBOR-Tree ohne dynamische Allokation im winzigen RAM (Stage 1) zu entpacken, führt extrem schnell zu Buffer-Overflows oder Limitierungs-Fehlern.
**Mitigation:** Die Umsetzung darf keinen generischen CBOR-Parser nutzen, sondern benötigt einen **strikten Stream-Parser (z.B. zcbor)**, der Schema-vordefinierte, speicherbegrenzte C-Structs allokiert. Variable Felder (wie Text-URLs), die für den Boot-Ablauf irrelevant sind, müssen on-the-fly "discarded" (übersprungen) werden, um den RAM-Footprint für Kern-Features bei `~14 KB` halten zu können.

### 7. WAL Ring Buffer Garbage Collection / Erase-Phase (Efficiency / Logic)
**Problem:** Das verbesserte Konzept nennt "Mindestens 2 pre-erased Flash-Sektoren" für den WAL. Wenn Sektor 1 voll ist, wandert das WAL in Sektor 2. Wann genau wird Sektor 1 wieder gelöscht (Erase)? Geschieht dies sofort beim Übergang, geht bei einem exakt dann auftretenden Stromausfall das bisherige Journal verloren. Passiert es nie, ist der Buffer irgendwann voll.
**Mitigation:** Klare Definition der **WAL Garbage Collection**. Der Bootloader darf den alten, nun inaktiven WAL-Sektor erst dann asynchron löschen ("pre-erase"), nachdem der erste `TXN_COMMIT` im neuen Sektor erfolgreich in Stein gemeißelt ist ODER während der Update-Phase im "Idle"-Zustand zwischen zwei Netzwerkpaketen, um Spitzenlasten (Brownouts) vom Flash-Write zu separieren.

### 8. Lebenszyklus des Boot Failure Counters (Logic Gap)
**Problem:** In Abschnitt 4 heißt es zur Zustandsmaschine: `1 Crash: Rollback. Weitere Crashes: Recovery-OS`. Es fehlt die Spezifikation, wann dieser `Boot_Failure_Counter` jemals wieder auf 0 gesetzt wird. Ein Crash in 2024, erfolgreicher Betrieb, und ein zweiter Crash in 2026 würde das System fälschlicherweise unwiderruflich ins Recovery-OS schicken.
**Mitigation:** Der `Boot_Failure_Counter` muss **zwingend** auf `0` genullt werden, sobald das OS nach einem Boot das Confirm-Flag erfolgreich präsentiert hat. Die Erfassung eines stabilen Zustands resettet die Fehlerhistorie.
