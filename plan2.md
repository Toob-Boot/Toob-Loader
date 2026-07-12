Direkt vorweg: Das größte Problem ist nicht Performance, sondern dass drei Kernversprechen des Tools — Reproduzierbarkeit, Fail-Fast, ehrliche UX — im Build-Command selbst verletzt werden. Danach kommen die echten Speed-Wins.

## 1. Die Fake-Progress-Bar muss weg

```go
// Premium UX: Show initialization progress bar
for i := 0; i <= 100; i += 10 {
    pb.Update(i)
    time.Sleep(15 * time.Millisecond)
}
```

Das sind ~165ms künstliche Latenz bei *jedem* Build, die nichts initialisieren. Das ist genau die Art von "silent fake", die du in deinem eigenen Code sonst mit FATAL-Bannern bestrafst. Ersatzlos streichen.

## 2. Reproduzierbarkeit ist aktuell kaputt

**Der Lockfile-Pin wird ignoriert, sobald der Cache existiert.** In `runBuild`:

```go
if !cache.IsInitialized() {
    // ... SwitchVersion(lf.Registry.Commit)
}
```

Der Kommentar sagt "Enforce lockfile registry version", aber enforced wird nur beim allerersten Sync. Hat der Entwickler global rev 42 aktiv und das Projekt lockt rev 40, baut er gegen 42. Fix: immer `HeadCommit()` gegen den Lock vergleichen und bei Mismatch `SwitchVersion()`. Zusatzproblem: `active_version` ist global in `~/.toob/registry` — zwei Projekte mit unterschiedlichen Lock-Versionen überschreiben sich gegenseitig den Marker bei jedem Build. Der Build sollte die Version für den Prozess auflösen, nicht global persistieren.

**Core SDK "latest" driftet.** `getLatestCoreSDKTag()` macht bei jedem Build ein `git ls-remote` (blocking, ohne Timeout — kann bei kaputtem Netz ewig hängen) und das Ergebnis wird nirgends gepinnt. Ironie: `Lockfile.Environment.CoreSDK` existiert bereits, wird im Docker-Pfad gelesen, aber im Native-Build weder gelesen noch geschrieben. Die Mechanik ist halb implementiert — resolved Version nach erfolgreichem Build ins Lockfile schreiben, beim nächsten Build daraus lesen, `ls-remote` nur bei explizitem Update.

**Downloads sind nicht atomar.** Drei Stellen mit demselben Muster:
- Core-SDK-Clone: bricht `git clone` mittendrin ab, existiert `~/.toob/core/<ver>` trotzdem und wird beim nächsten Build als valide durchgewunken (`os.Stat`-Check).
- `fetchPackage`: partielle Tarball-Extraktion → `destPath` existiert → "already fetched".
- `checkoutAPI`: `registry.json` wird direkt geschrieben, nicht tmp+rename — Crash mittendrin ergibt `IsInitialized() == true` mit korruptem JSON.

Du machst tmp+rename bereits korrekt in `Lockfile.Save` und `regcheck.writeCache`. Dasselbe Muster überall: in Temp-Verzeichnis laden, dann `os.Rename`.

## 3. Inkrementelle Builds: der größte Wall-Clock-Win

**Mtime-Churn durch unconditional writes.** `generated_boot_config.h`, `boot_layout.h`, `toob_config.cmake`, die Linker-Scripts und alle vier zcbor-Outputs werden bei jedem Build neu geschrieben — auch wenn der Inhalt identisch ist. Ninja arbeitet mtime-basiert, also recompiled jeder Build alles, was von diesen Headern abhängt (vermutlich: fast alles) plus Re-Link. Ein `writeFileIfChanged`-Helper löst das:

```go
func writeFileIfChanged(path string, data []byte, perm os.FileMode) error {
    if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
        return nil
    }
    return os.WriteFile(path, data, perm)
}
```

Das ist vermutlich der Unterschied zwischen 30s- und 2s-Inkrementalbuilds.

**CMake-Configure überspringen.** Ihr ruft `cmake -G Ninja` bei jedem Build auf. Wenn `build.ninja` bereits existiert, kann der Configure-Schritt komplett entfallen — Ninja hat eine generierte Regel, die CMake selbst re-configured, wenn sich CMakeLists oder includierte Configs ändern. Zusammen mit write-if-changed ist Configure dann nur noch nötig, wenn sich wirklich etwas geändert hat.

**zcbor-Codegen parallelisieren und cachen.** Die vier Kommandos sind unabhängig → `errgroup`, fertig. Besser noch: Hash der CDDL-Dateien merken und den Schritt komplett skippen, wenn unverändert.

**ccache im Native-Build fehlt.** Im Docker-Pfad mountet ihr ccache, nativ nicht. `-DCMAKE_C_COMPILER_LAUNCHER=ccache` (wenn vorhanden) ist eine Zeile.

**VerifyMacroUsage** liest bei jedem Build jede .c/.h-Datei des gesamten Trees. Zwei billige Fixes: Early-Exit sobald alle Makros gefunden sind (Counter statt Map-Scan am Ende), und Worker-Pool über die Dateien. Ein Cache keyed auf Header-Hash + Tree-State wäre die Vollversion, aber die zwei Fixes bringen schon viel.

## 4. Fail-Fast-Verstöße

- `exec.Command("docker", "pull", ...).Run()` — Fehler zweimal komplett verschluckt. Wenn Pull fehlschlägt und das Image lokal fehlt, kriegt der User einen kryptischen `docker run`-Fehler, und `checkProtocolVersion` meldet vorher noch irreführend "handshake skipped". Pull-Fehler + fehlendes Image = harter Abbruch mit klarer Meldung.
- `json.Unmarshal(data, &cm)` — im ersten Pfad `err == nil`-guarded (Parse-Fehler → stiller Fallthrough zu "invalid chip manifest", falsche Diagnose), im Registry-Fallback-Pfad komplett ignoriert. Kaputtes `chip_manifest.json` muss als solches gemeldet werden.
- **`suit.Generate` mit `fmt.Scanln` ist im CI ein stiller Auto-Yes**: bei EOF bleibt `response == ""`, die Bedingung `response != "" && ...` greift nicht → Docker-Fallback wird bestätigt, ohne dass jemand gefragt wurde. Interaktive Prompts haben in einer Build-Pipeline nichts verloren — Non-TTY erkennen und deterministisch entscheiden (oder `--yes`-Flag).
- `flagSkipChecks` wird in dieser Datei deklariert und benutzt, aber in `init()` nie registriert. Falls das nicht in `root.go` als Persistent Flag passiert, ist `--skip-checks` tot.

## 5. Timeouts & Nebenläufigkeit

Der async Combination-Check mit 3s-Timeout ist gut gemacht — aber inkonsistent: `git ls-remote`, `git clone`, `docker pull` und `cache.Sync` laufen alle ohne Bound. `exec.CommandContext` mit vernünftigen Timeouts überall, sonst hängt "latest"-Resolution den ganzen Build. Der `docker pull latest` bei jedem Docker-Build gehört außerdem entweder async mit kurzem Timeout oder nur bei fehlendem/altem Image.

`regcheck.checkChipCompatibility` macht serielle API-Calls pro Chip (je 3s Timeout möglich) — läuft zwar async, aber trivial parallelisierbar.

## 6. Kleinkram, der auffiel

- `chipDir` wird bis zu dreimal via `cache.ChipSourcePath(chip)` aufgelöst (hwJSON-Fallback, cmPath-Fallback, ReadFile-else). Einmal auflösen, weiterreichen.
- `lfPath := filepath.Join(root, "toob.lock")` statt `paths.LockfilePath(root)` — ihr habt das paths-Package genau dafür.
- Die `expectedVersion`-Resolution in Schritt 8 steht zweimal identisch da (vor `findToolchainBin` und nochmal im Auto-Provision-Branch) — der zweite Block kann nichts Neues produzieren.
- `findPythonScriptsBin` fragt `os.path.join(sys.prefix, 'Scripts')` ab — das ist Windows-only, auf Linux/macOS heißt es `bin`. Cross-platform: `sysconfig.get_path('scripts')`.
- Image-Repo-Inkonsistenz: Docker-Build nutzt `mannomannx/toob-compiler:<lockfileTag>`, der SUIT-Fallback `repowatt/toob-compiler:v<cliVersion>`. Zwei verschiedene Repos *und* zwei verschiedene Versionsquellen für "den Compiler" — das gehört in den ports-Contract konsolidiert, sonst divergieren die zwei Pfade irgendwann still.
- `CheckBudget` parst device.toml ohne Strict-Mode (direkt `toml.DecodeFile` statt `ParseToml`) und hat Default-Budgets (16384/28672), obwohl `Compile` dieselben Felder als mandatory erzwingt. Widersprüchliche Policies für dieselbe Datei.
- Allocator: `GetSectorSizeAt` matcht writable Regions nur über `SectorSize × Count` — eine writable Region, die nur mit `Size` definiert ist, wird nie gefunden und fällt erst zur Laufzeit mit "does not fall within any writable region" auf. Schema beim Laden validieren: writable ⇒ `sector_size` und `count` mandatory, sonst FATAL.
- `os.Setenv("PATH", ...)` mutiert global den Prozess — sauberer ist `cmd.Env` pro exec, gerade wenn ihr später mal Builds parallelisiert.

## Priorisierung

Wenn du nur drei Dinge machst: (1) write-if-changed für alle generierten Dateien plus Configure-Skip — dominiert die Inner-Loop-Zeit komplett, (2) Lockfile-Pin-Enforcement + Core-SDK-Pinning fixen — das ist die Kernaussage eures Produkts, (3) atomare Downloads — die Halb-Clone-Bugs sind die Sorte, die ein Kunde einmal trifft und nie wieder vergisst.