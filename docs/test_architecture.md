# Toob-Registry — Live-Integration & E2E Test-Backlog

> **Zweck:** Vollständiger Bedienungszyklus-Test gegen einen **live laufenden API-Server** in einem isolierten Dev-Environment (eigene DB, Object Storage, Vault). Es werden **echte HTTP-Requests** gegen reale Endpoints abgesetzt — keine Unit-Tests, kein Mock des Servers.
>
> **Format:** Backlog mit abhakbaren Stories. Jede Story beschreibt das **Was** (Rolle, Endpoint, Ablauf, Schnittstellen, Cases, Timing, Assertions) — nicht das konkrete **Wie** der Implementierung.
>
> **Notation:** `☐` = offene Story · jede Story hat eine stabile ID (`AUTH-01` …). Status-Codes, `error_code`-Werte, Header- und Feldnamen entsprechen exakt dem Backend-Verhalten und dienen als Assertions.

---

## Inhaltsverzeichnis

|
 Epic 
|
 Thema 
|
 Doku-Bezug 
|
|
---
|
---
|
---
|
|
**
E0
**
|
 Test-Harness, Fixtures & Voraussetzungen 
|
 §11 DB, §12 Security 
|
|
**
E1
**
|
 Health, Readiness & Observability 
|
 §5 Control Plane 
|
|
**
E2
**
|
 Authentifizierung & Session-/Token-Management 
|
 §5, §12 
|
|
**
E3
**
|
 Publish Write-Path (Upload, 6-Gate-Pipeline) 
|
 §5, §8 
|
|
**
E4
**
|
 Promotion & Package-Lifecycle (Simulated Worker) 
|
 §4, §6, §13 
|
|
**
E5
**
|
 Registry Read-Path & Caching 
|
 §5, §13 
|
|
**
E6
**
|
 Organisationen, Rollen & Scopes 
|
 §4, §5 
|
|
**
E7
**
|
 Admin & Release-Lifecycle 
|
 §5, §10 
|
|
**
E8
**
|
 Worker-API / Zero-Trust (mTLS) 
|
 §6, §12 
|
|
**
E9
**
|
 Webhooks (PR / Push / Release) 
|
 §5, §13 
|
|
**
E10
**
|
 Notifications & Security-Advisories 
|
 §12, §13 
|
|
**
E11
**
|
 Cross-Cutting Middleware 
|
 §5, §12 
|
|
**
E12
**
|
 Resilienz & Hintergrund-Jobs 
|
 §6, §11 
|
|
**
E13
**
|
 End-to-End Golden Paths (Rollen-Kombinationen) 
|
 §13 
|
|
**
E14
**
|
 Full-Stack / Real-Worker (optional, langsam) 
|
 §6, §7, §9, §10 
|

---

## E0 — Test-Harness, Fixtures & Voraussetzungen

> Diese Epic erzeugt keine Produkt-Assertions, sondern definiert die **Setup-Verträge**, ohne die der Rest nicht ausführbar ist. Kritische Erkenntnisse aus dem Code, die das Test-Design prägen:

### Harness-Fähigkeiten (Pflicht)

- [ ] **E0-01 — HTTP-Client (public)**: Klartext-HTTPS-Client gegen den öffentlichen Port (`PORT`, default 8080), folgt Redirects **wahlweise** (für Download-Tests muss `Location` auch ohne Follow inspizierbar sein).
- [ ] **E0-02 — mTLS-Worker-Client**: Separater HTTPS-Client gegen den internen Port (`WORKER_PORT`, default 8443) mit **Client-Zertifikat aus der Vault-PKI**, dessen `Subject.CN = worker.global.nomad` ist. Ohne dieses Zertifikat ist die gesamte Worker-API (E8) nicht erreichbar.
- [ ] **E0-03 — Direkter S3-PUT**: Fähigkeit, an eine **presigned URL** ein beliebiges Byte-Blob per `PUT` hochzuladen (für simulierte Worker-Uploads in E4/E8). Kein S3-Credential nötig — die presigned URL trägt die Autorisierung.
- [ ] **E0-04 — DB-Seeding-Kanal**: Direkter DB-Zugriff (oder ein Dev-Only-Seed-Tool). **Begründung:** Es existiert *kein* API-Endpoint, um (a) einen Publisher anzulegen ohne echten GitHub-OAuth, oder (b) die Rolle `core` zu vergeben (`role` defaultet auf `contributor`, `set-plan` ändert nur `plan_tier`). Admin-Tests (E7) und das Bootstrappen von Test-Identitäten **erfordern** daher DB-Seeding.
- [ ] **E0-05 — Webhook-HMAC-Signierer**: Fähigkeit, einen Request-Body mit `HMAC-SHA256(WebhookSecret)` zu signieren und als `X-Hub-Signature-256: sha256=<hex>` zu setzen (für E9).
- [ ] **E0-06 — Zeit-/Polling-Helper**: Helper für *eventual consistency* (Download-Counter, Cache-Sync via `NOTIFY`, Reaper) mit konfigurierbarem Poll-Intervall + Timeout.
- [ ] **E0-07 — Vault-Erreichbarkeit**: Dev-Vault läuft, Transit-Key `toob-package-signing` existiert, KV-Secrets (`database`, `s3`, `github-app`, `github-oauth`, `webhook`, `cloudflare`, `oauth-aes`, `dockerhub`) sind befüllt — sonst startet der Server gar nicht (`config.Load` ist fail-closed).

### Seed-Identitäten (Fixtures)

- [ ] **E0-10 — Core-Admin `core-admin`**: Publisher mit `role = core`, bekannter API-Key (`toob_v1_<uuid>_<secret>`). Deckt alle `PermAdmin*`/`PermRegistry*`-Pfade.
- [ ] **E0-11 — Contributor A `alice`** und **E0-12 — Contributor B `bob`**: zwei normale Publisher mit bekannten Keys, für Isolations- und Race-Tests.
- [ ] **E0-13 — Suspendierter Publisher `mallory`**: `suspended_at != NULL` → muss bei jeder Authentifizierung `401` erhalten (Test `AUTH-09`).
- [ ] **E0-14 — Plan-Varianten**: `alice` auf `free`, ein Publisher auf `enterprise` (via `set-plan`), um die `min(plan, host-cap)`-Logik (PUB-06) zu prüfen.
- [ ] **E0-15 — GitHub-IDs**: jeder Seed-Publisher hat eine eindeutige `github_id`; zusätzlich eine **nicht-registrierte** GitHub-ID für Opt-In-Webhook-Test (HOOK-04).

### Beispiel-Tarballs (gültig & bösartig)

- [ ] **E0-20 — Gültige Pakete je Kategorie**: je ein `.tar.gz` mit korrektem Manifest für `chip`, `driver`, `crypto`, `arch`, `toolchain`, `integration`, `soc` — jeweils mit `name`/`version`/`author`, gültiger SemVer (`X.Y.Z`, keine führenden Nullen), Manifest auf Root- oder erster Ebene.
- [ ] **E0-21 — Promote-fähiges Paket**: Manifest enthält `reference_build_context` mit `chip`, `core_sdk_version`, `toolchain_version` (Pflicht für `/publish/promote`).
- [ ] **E0-22 — Bösartige Tarballs** (Negativ-Fixtures für PUB-Gate-Tests): Path-Traversal (`../`), absoluter Pfad, Symlink-/Hardlink-Eintrag, Binärdatei (`.o`/`.elf`), verbotene Extension, fehlendes Manifest, doppeltes Manifest, Manifest-Name mit Großbuchstaben, Version mit führender Null, Datei > 1 MiB, > 128 Dateien, Pfadtiefe > 8, Quell-Datei mit `system(`/Inline-ASM/hoher Entropie/langem Base64.
- [ ] **E0-23 — Typosquat-Kandidat**: Paketname mit Levenshtein-Distanz ≤ 2 zu einem bereits in `staging`/`stable` existierenden Namen (für Warnings in PUB-07 / WRK-04).

### Reset-Strategie

- [ ] **E0-30 — Isolierte Läufe**: Vor/nach jedem Epic-Run wird der DB-/S3-Zustand wiederhergestellt (Truncate + Re-Seed **oder** dedizierte Namespaces je Lauf), damit Quoten, Name-Claims und Revisions deterministisch sind. **Achtung:** Der Stage-Transition-Trigger (Migration 020) verbietet beliebiges „Zurücksetzen" von Stages per UPDATE — Reset bevorzugt über `DELETE`/Truncate, nicht über Stage-Downgrade.

---

## E1 — Health, Readiness & Observability

- [ ] **HEALTH-01 — Liveness ohne Auth**
  **Endpoint:** `GET /health` · **Erwartung:** `200`, Body `{"status":"alive"}`, Header `Cache-Control: no-store`. Kein Auth nötig.

- [ ] **HEALTH-02 — Readiness-Aggregat**
  **Endpoint:** `GET /ready` · **Erwartung:** `200` wenn `db=ok`, `s3=ok`, `vault=ok`; Body-Felder `ready,db,s3,vault,worker`. `healthy` ist **nur** db∧s3∧vault — `worker` ist informativ und beeinflusst den Status-Code nicht.

- [ ] **HEALTH-03 — Worker-Heartbeat-Zustände**
  **Vorbedingung:** kein Worker hat je gepingt → `worker="no_heartbeat"`. Nach Heartbeat (E8) innerhalb 30 s → `worker="ok"`; älter als 30 s → `worker="stale_heartbeat"`. **Timing:** 30-s-Schwelle.

- [ ] **HEALTH-04 — Shutdown-Drain-Verhalten**
  **Ablauf:** Während des 15-s-Graceful-Drain (SIGTERM) liefern `/health` und `/ready` → `503` mit `status:"shutting_down"`. (Erfordert kontrollierten Shutdown des Dev-Servers; sonst als Doku/Manual-Test markieren.)

- [ ] **HEALTH-05 — Metrics-Endpoint (interner Port, mTLS)**
  **Endpoint:** `GET /metrics` am internen Port · **Erwartung:** Prometheus-Exposition, enthält `toob_build_info`, `toob_http_requests_total`, `toob_db_pool_*`, `toob_queue_depth{type="validation"|"publish"}`. **Negativ:** ohne mTLS-Cert nicht erreichbar.

- [ ] **HEALTH-06 — Pfad-Normalisierung der Metriken**
  Nach Requests auf `/api/v1/package/{name}/{version}` und `/api/v1/package/@scope/name/version` darf `toob_http_requests_total` **nur** die Routen-Templates als `route`-Label tragen (keine konkreten Namen/Versionen → keine Kardinalitätsexplosion). Unbekannte Routen → `route="unknown"`.

- [ ] **HEALTH-07 — Empty-State-Readiness**
  **Vorbedingung:** frisches Environment, keine Pakete, keine Revisionen, keine Publisher (außer Seeds). `GET /ready` → `200` mit `db=ok`, `s3=ok`, `vault=ok`. **Sinn:** Sicherstellen, dass der Readiness-Check nicht an leeren Tabellen scheitert (z. B. `SELECT max(revision)` auf leerer `revisions`-Tabelle muss `NULL` tolerieren, nicht paniken).

- [ ] **HEALTH-08 — Queue-Depth bei leeren Queues**
  `GET /metrics` → `toob_queue_depth{type="validation"}` und `toob_queue_depth{type="publish"}` sind jeweils `0`, nicht absent. **Sinn:** Prometheus-Alerting auf Queue-Tiefe braucht einen konstant existierenden Metrik-Key, auch wenn die Queue leer ist.

---

## E2 — Authentifizierung & Session-/Token-Management

- [ ] **AUTH-01 — OAuth-Redirect-Aufbau**
  `GET /api/v1/auth/github?state=…&code_challenge=…&redirect_uri=http://localhost/callback` → `302` zu `github.com/login/oauth/authorize`, setzt `oauth_state`-Cookie (HttpOnly, MaxAge 300). **Negativ:** fehlende Query-Parameter → `400`; `redirect_uri` außerhalb Loopback/`oob` → `400` „unauthorized redirect_uri".

- [ ] **AUTH-02 — PKCE Token-Exchange (Erfolg)**
  `POST /api/v1/auth/token` mit korrektem `code` + `code_verifier` (dessen SHA256-Base64URL = gespeicherter `code_challenge`) → `200` mit `publisher_id,login,role,has_api_key` (+ `api_key` falls neu/rotiert). *Erfordert vorgelagerten OAuth-Callback — siehe E14, oder DB-Seed einer `oauth_sessions`-Zeile.*

- [ ] **AUTH-03 — PKCE-Mismatch**
  Token-Exchange mit falschem `code_verifier` → `403` „invalid PKCE verifier" (constant-time-Vergleich).

- [ ] **AUTH-04 — OAuth-Session-Einmaligkeit & Grace-Window**
  Zweimaliger `/auth/token` mit gleichem `code`: erster Aufruf konsumiert (`exchanged_at` gesetzt), zweiter → `400` „invalid or expired authorization code". **Timing:** 5-min-TTL der Session, 10-s-Grace für konkurrierende Retries.

- [ ] **AUTH-05 — Bearer-Format-Validierung**
  Geschützter Endpoint (`GET /api/v1/me`) ohne `Authorization` → `401`. Mit Müll-Token (kein `toob_…_…_…`-4-Teiler) → `401` „invalid token format". Falscher Präfix → `401`.

- [ ] **AUTH-06 — Session-Token (`toob_v1_`) gültig**
  `GET /api/v1/me` mit gültigem Session-Key → `200`, liefert `id,github_login,role,plan,orgs`. Plan-Limits korrekt aufgelöst (`ResolvePlan`).

- [ ] **AUTH-07 — CI-Token Lebenszyklus**
  `POST /api/v1/tokens` (Session, Body `name`+`scopes`) → `200` mit `token` (`toob_ci_<id>_<secret>`). `GET /api/v1/tokens` listet (ohne `token_hash`). `DELETE /api/v1/tokens/{id}` → `200`; danach ist der Token bei Nutzung `401`. **Negativ:** Create ohne `scopes` → `400`; Delete unbekannte ID → `404`.

- [ ] **AUTH-08 — Scope-Prefix-Semantik**
  CI-Token mit Scope `publish` darf `POST /api/v1/publish/promote` (verlangt `publish:promote`) aufrufen (Prefix-Match). Token mit Scope `read` → `403` „insufficient scope" auf Promote. Token mit `*` → alles erlaubt. **Endpoint-Scopes:** `publish` (Publish), `publish:promote` (Promote), `read` (Job-Status, mine, Package-GET).

- [ ] **AUTH-09 — Suspendierter Publisher**
  Mit Key von `mallory` (`suspended_at` gesetzt) → jeder geschützte Endpoint `401` (`IsActive()==false`).

- [ ] **AUTH-10 — Token-Cache vs. bcrypt-DoS**
  Wiederholte gültige Auth mit gleichem Key → schnell (Cache-Hit, 60 s TTL). Flood mit *falschem* Secret für gültige UUID → wiederholt `401`, ohne dass gültige Einträge verdrängt werden (Double-Buffer, Rotation bei 2500 Einträgen). **Charakter:** Verhaltens-/Performance-Smoke, nicht exakt messbar — als „keine Auth-Regression unter Last" formulieren.

- [ ] **AUTH-11 — `last_used_at`-Update-Drossel**
  CI-Token mehrfach in < 5 min nutzen → `last_used_at` wird höchstens einmal pro 5-min-Fenster aktualisiert (verifizierbar via `GET /api/v1/tokens` oder DB).

- [ ] **AUTH-12 — Logout invalidiert Key**
  `POST /api/v1/auth/logout` (Session) → `200`; danach ist derselbe Session-Key `401` (api_key_hash geleert). **Hinweis:** Re-Seed nötig, um die Identität danach weiter zu verwenden.

- [ ] **AUTH-13 — Admin verlangt Session-Token**
  CI-Token mit Scope `*` gegen einen Admin-Endpoint (`GET /api/v1/admin/status`) → `403` „administrative actions require a session token" (RequireSessionToken vor RequirePermission).

- [ ] **AUTH-14 — Permission-Gate für Nicht-Core**
  `alice` (contributor) gegen `GET /api/v1/admin/status` mit **Session**-Token → `403` „forbidden" (fehlende `PermAdminDashboard`).

- [ ] **AUTH-15 — Malformed JSON am Auth-Endpoint**
  `POST /api/v1/auth/token` mit Body `{invalid json` → `400` mit aussagekräftiger Fehlermeldung (nicht 500/Panic). Ebenso: `POST /api/v1/tokens` mit leerem Body → `400`. **Sinn:** Sicherstellen, dass JSON-Parsing-Fehler sauber abgefangen werden und keine Stack-Traces leaken.

- [ ] **AUTH-16 — CI-Token mit abgelaufenem `expires_at`**
  CI-Token erstellen mit `expires_at` in der Vergangenheit (oder via DB-Inject). Auth-Versuch → `401` „token expired". **Sinn:** Ablauf-Datum wird tatsächlich geprüft, nicht nur dekorativ gespeichert.

- [ ] **AUTH-17 — Falsche HTTP-Methode auf Auth-Endpoints**
  `GET /api/v1/auth/token` (erwartet POST) → `405 Method Not Allowed` (oder `404`, je nach Router-Verhalten). `DELETE /api/v1/auth/github` → analog. **Sinn:** Keine unbeabsichtigte Endpoint-Erreichbarkeit über falsche Methoden.

---

## E3 — Publish Write-Path (Upload & 6-Gate-Pipeline)

> Endpoint `POST /api/v1/publish` (multipart, Feld `tarball`). Reihenfolge der Gates: Quota → Multipart-Limit → Tarball lesen → Ingestion-Validierung (6 Gates) → Scope-Authz → SHA256 → Dedup → DB-Insert (dev) → S3-Upload → Vault-Sign → Metadata-Finalize.

- [ ] **PUB-01 — Happy Path (dev)**
  `alice` lädt ein gültiges Chip-Tarball → `201` mit `status:"published", id, name, version, category, stage:"dev", tarball_sha, signature`. Danach erscheint es in `GET /api/v1/packages/mine` mit `stage:"dev"`. S3-Objekt existiert unter `packages/<cat>/<name>/<name>-v<ver>-<8hex>.tar.gz`.

- [ ] **PUB-02 — Permission `package:publish`**
  Publisher ohne Publish-Permission → `403 FORBIDDEN`. (Contributor/Core haben sie; relevant falls künftig restriktivere Rollen.)

- [ ] **PUB-03 — Duplikat-Tarball (SHA256)**
  Identisches Tarball ein zweites Mal (auch unter anderem Namen) → `409` `CONFLICT_TARBALL_EXISTS` mit Hinweis auf bereits existierendes `name@version`.

- [ ] **PUB-04 — Versions-Konflikt**
  `alice` lädt `name@1.0.0` zweimal mit *unterschiedlichem* Inhalt (anderer SHA) in dev → zweiter Insert `409` `VERSION_CONFLICT` (Per-Publisher-Unique-Index dev/testing).

- [ ] **PUB-05 — Dev-Quota (TOCTOU-frei genug)**
  `alice` (`free`, MaxDev=10, Host-Cap 10) füllt 10 dev-Pakete → 11. Upload `429` `QUOTA_EXCEEDED` „max 10". **Variante:** Nach `unpublish` eines dev-Pakets ist wieder ein Slot frei.

- [ ] **PUB-06 — Plan- vs. Host-Cap (`min`-Logik)**
  Publisher auf `enterprise` (MaxDev=200) bleibt dennoch durch Host-`MAX_DEV_PACKAGES` gedeckelt → effektives Limit = `min(plan, host)`. Test: setze Host-Cap niedrig, Plan hoch → Host-Cap greift.

- [ ] **PUB-07 — Heuristik-Warnings sind nicht-blockierend**
  Tarball mit `system(`+`stdlib.h` bzw. Inline-ASM außerhalb `arch` → `201`, aber `ingestion_warnings` im Response **und** im persistierten Manifest (`ingestion_warnings`-Key) für Staging-Review.

- [ ] **PUB-08 — Gate: Path-Traversal / absolute Pfade**
  Tarball mit `../etc/x` oder `/abs/path` → `400` `INVALID_MANIFEST`/Reject-Meldung „path traversal" / „absolute path". (SafeWalk prüft `..` *vor* `Clean`.)

- [ ] **PUB-09 — Gate: Symlink/Hardlink/Device**
  Tarball mit Symlink-, Hardlink- oder Device/FIFO-Eintrag → Reject „symlink/hardlink" bzw. „device/fifo".

- [ ] **PUB-10 — Gate: Binär-/Extension-Allowlist**
  `.o`/`.elf`/`.bin` → „binary file forbidden" (Security-Scan). Unbekannte Extension (z. B. `.py`) → „file extension not allowed". Extensionlose Datei außerhalb `LICENSE`/`Kconfig` → Reject.

- [ ] **PUB-11 — Gate: Größen-/Anzahl-/Tiefen-Limits**
  Datei > 1 MiB → Reject; > 128 Dateien → „file count limit"; Pfadtiefe > 8 → „max depth"; Gesamt-Decompress > 20 MiB → „total decompressed size".

- [ ] **PUB-12 — Gate: Manifest-Pflichtfelder & Format**
  Fehlt `name`/`version`/`author` → Reject. `name` nicht `[a-z0-9-]` (mit optionalem `@scope/`) → Reject. `version` keine gültige SemVer / führende Null → Reject. Mehr als ein Manifest → „multiple manifests". Kein Manifest → „no manifest found".

- [ ] **PUB-13 — Gate: Manifest-Position**
  Manifest tiefer als erste Verzeichnisebene (`maxManifestDepth=2`) → Reject „must be at root or first directory level".

- [ ] **PUB-14 — Gate: Binär-Content-Heuristik in Quelldateien**
  `.c`/`.h` mit > 80 % Nicht-ASCII → Reject „appears to be binary".

- [ ] **PUB-15 — Multipart-Limit (5 MiB)**
  Tarball > `maxMultipartSize` (5 MiB) → `400` `INVALID_MULTIPART` „file too large". Fehlendes `tarball`-Part → `400` `INVALID_MULTIPART` „missing tarball part".

- [ ] **PUB-16 — Body-Limit-Anhebung am Publish-Pfad**
  Multipart bis 10 MiB ist durch das Body-Limit-Middleware zugelassen (Pfad `/api/v1/publish`), während der Handler selbst auf 5 MiB begrenzt — beide Grenzen konsistent prüfen (10 MiB → Handler-Reject, nicht Middleware-Reject).

- [ ] **PUB-17 — Unauth**
  `POST /api/v1/publish` ohne Token → `401 UNAUTHORIZED`.

- [ ] **PUB-18 — Content-Type-Mismatch**
  `POST /api/v1/publish` mit `Content-Type: application/json` statt `multipart/form-data` → `400` mit klarer Fehlermeldung (nicht 500). Ebenso: fehlender `Content-Type`-Header → `400`. **Sinn:** Publish ist der einzige Multipart-Endpoint — Verwechslung mit JSON ist wahrscheinlichster Nutzerfehler.

- [ ] **PUB-19 — Package-Name-Randfälle**
  - Maximale Namenslänge (was ist das Limit? `validPackageNamePattern` prüfen) → Grenze testen (grenzwertig gültig vs. 1 Zeichen darüber).
  - Name nur aus Bindestrichen `---` → `400` (Pattern `^(@[a-z0-9-]+/)?[a-z0-9-]+$` erlaubt es technisch — sollte es?).
  - Name mit Großbuchstaben `MyDriver` → `400`.
  - Name mit Sonderzeichen/Unicode `treiber_ö` → `400`.
  - SQL-Injection-Versuch als Name: `'; DROP TABLE packages;--` → `400` (vom Pattern abgefangen, nicht erst von der DB).

- [ ] **PUB-20 — Version-Randfälle**
  - `0.0.0` → `201` (gültige SemVer). 
  - `999.999.999` → `201` (keine Obergrenze).
  - `1.0.0-beta.1` (Pre-Release-Tag) → Verhalten klären: akzeptiert oder `400`? (SemVer erlaubt es, `validSemVer` im Code prüfen.)
  - `v1.0.0` (führendes `v`) → `400` (kein `v`-Prefix in SemVer).
  - `1.0` (unvollständig) → `400`.
  - Leere Version `""` → `400`.

- [ ] **PUB-21 — Leeres Tarball (0 Bytes)**
  `POST /api/v1/publish` mit leerem `tarball`-Part (0 Bytes) → `400` „no manifest found" (nicht 500 durch gzip-Dekompression leerer Daten). **Sinn:** Sicherstellen, dass `SafeWalk` auf einem leeren Stream nicht panikt.

---

## E4 — Promotion & Package-Lifecycle (Simulated Worker)

> **Schlüssel-Pattern „Simulated Worker":** Die Worker-Komponente ist selbst nur ein HTTP-Client der Worker-API. Für vollständige Lifecycle-Tests **ohne echte Firecracker-VM** agiert der Test-Harness als Worker (mTLS, E0-02): er *claimt* den Compile-Job und *completet* ihn mit fabriziertem `PASSED`/`FAILED` — dadurch wird die komplette serverseitige Zustandsmaschine (testing→staging bzw. testing→dev) real durchlaufen.

- [ ] **LIFE-01 — Promote dev → testing**
  `POST /api/v1/publish/promote` (Body `name`,`version`) auf ein eigenes dev-Paket mit `reference_build_context` → `202` `status:"testing"`, `job_id`, Meldung „compile validation queued". Paket-Stage = `testing`. Ein `publish_jobs`-Eintrag (`QUEUED`) existiert.

- [ ] **LIFE-02 — Promote ohne reference_build_context**
  Manifest ohne `reference_build_context` → `400` „must contain a 'reference_build_context'". Mit unvollständigem Context (z. B. fehlendes `chip`) → `400`.

- [ ] **LIFE-03 — Promote nur aus dev**
  Promote eines Pakets, das nicht in `dev` ist (z. B. bereits `testing`) → `409` „package is in \"…\" stage (must be dev)".

- [ ] **LIFE-04 — Promote-Idempotenz**
  Zweiter Promote desselben dev-Pakets während ein aktiver (`QUEUED`/`COMPILING`) Job existiert → **kein** Duplikat; der bestehende Job wird zurückgegeben.

- [ ] **LIFE-05 — Testing+Staging-Quota (TOCTOU im Transaktions-Scope)**
  `alice` (`free`, kombiniert max 5 testing+staging) auf Limit; weiterer Promote → `409` „testing+staging quota exceeded". **Race-Variante:** zwei *gleichzeitige* Promotes am Limit — nur die erlaubte Anzahl passiert (Quota-Check läuft *innerhalb* der `PromoteAndEnqueue`-Transaktion).

- [ ] **LIFE-06 — Simulated Worker: PASS → staging**
  Harness als Worker: `POST /api/v1/worker/publish-claim` → erhält `PublishClaimedJob` (job_token, tarball_key) → `POST /api/v1/worker/publish-jobs/{id}/complete` mit `status:"PASSED"` → `200` `status:"promoted_to_staging"`. Paket-Stage = `staging`, `staging_status = pending`. Job-Status = `PASSED`, Job-Token invalidiert.

- [ ] **LIFE-07 — Simulated Worker: FAIL → dev mit Feedback**
  Complete mit `status:"FAILED"` + `compiler_log`/`error` → `200` `status:"reverted_to_dev"`. Paket-Stage = `dev`, `staging_feedback` = Fehlertext. In `GET /api/v1/packages/mine` sichtbar (`error_summary` aus Log extrahiert).

- [ ] **LIFE-08 — Deferred Name Claiming (der Kern-Race)**
  `alice` und `bob` publishen **denselben** `name@version` nach dev → **beide** `201` (Per-Publisher-Index). Beide promoten → **beide** `202` testing. Simulated Worker completet **beide** mit PASS:
  - Erster `complete` → `promoted_to_staging`.
  - Zweiter `complete` → `409` `status:"name_claimed"` *und* das Paket wird automatisch nach `dev` zurückgesetzt mit Feedback „name and version claimed by another publisher while in testing".

- [ ] **LIFE-09 — Ownership-Guard beim Promote**
  Existiert `name` bereits in `staging`/`stable` von `alice`, versucht `bob` denselben `name` (unscoped) zu promoten → `403` „package name … already owned by another publisher" (`AuthorizeNameClaim`). **Scoped-Variante:** Org-Mitglied darf trotzdem (siehe E6).

- [ ] **LIFE-10 — SSE Job-Stream**
  `GET /api/v1/publish/jobs/{id}/stream` (Session, Scope `read`) → `Content-Type: text/event-stream`, initialer Keep-Alive, dann `event: status`-Frames bei jedem Statuswechsel (via Postgres `NOTIFY publish_job_updates`). Stream endet bei `PASSED`/`FAILED`. **Timing:** 15-s-Keep-Alive-Heartbeat; harte Obergrenze 15 min. **Komprimierung:** SSE wird **nicht** gzip-komprimiert (Accept `text/event-stream`).

- [ ] **LIFE-11 — Job-Status & Authz**
  `GET /api/v1/publish/jobs/{id}` als Ersteller → `200` Job-Objekt. Als fremder `bob` (kein Org-Bezug, kein Admin) → `403 FORBIDDEN`. Unbekannte ID → `404 JOB_NOT_FOUND`. Nicht-numerische ID → `400 INVALID_JOB_ID`.

- [ ] **LIFE-12 — Unpublish nur dev**
  `DELETE /api/v1/package/{name}/{version}` auf eigenes **dev**-Paket → `200`, S3-Objekt gelöscht. Auf Paket in `testing`/`staging`/`stable` → `409` (DeleteDevPackage matcht nur `stage='dev'`). Fremdes Paket → `404`.

- [ ] **LIFE-13 — Stage-Transition-Trigger (DB-Invariante)**
  Indirekter Nachweis, dass die API **niemals** illegale Übergänge erzeugt (z. B. dev→stable direkt). Direkt-Provokation per DB-UPDATE (dev→stable) muss die Trigger-Exception (Migration 020) auslösen — bestätigt, dass die Invariante serverseitig hart ist.

- [ ] **LIFE-14 — Promote nach Logout/Re-Auth**
  `alice` published dev-Paket, dann Logout (AUTH-12), dann Re-Seed-Key, dann Promote mit neuem Key → `202`. **Sinn:** Key-Rotation während aktivem Lifecycle unterbricht den Paket-Zustand nicht.

- [ ] **LIFE-15 — `packages/mine` auf leerem Account**
  Frischer Contributor ohne jegliche Pakete → `GET /api/v1/packages/mine` → `200` mit `packages: []` (leere Liste, nicht `404`). **Sinn:** Frontend/CLI braucht ein deterministisches Verhalten bei leerem Zustand.

---

## E5 — Registry Read-Path & Caching

- [ ] **REG-01 — Revision (leer & befüllt)**
  `GET /api/v1/registry/revision` ohne jegliche Revision → `200 {"revision":0}`. Nach erstem Release → `200` mit `revision,format_version,commit_sha,signature,created_at`. **Assertion:** `signature` ist nicht leer (Vault-Transit), und ändert sich bei neuer Revision.

- [ ] **REG-02 — Index + ETag/304**
  `GET /api/v1/registry/index` → `200`, Header `X-Registry-Signature`, `ETag: W/"rev-<rev>"`, Edge-Cache-Header (`public, max-age=60, s-maxage=86400`). Zweiter Request mit `If-None-Match: <ETag>` → `304` ohne Body.

- [ ] **REG-03 — Index-Signatur-Caching**
  Zwei aufeinanderfolgende Index-Requests bei *gleicher* Revision liefern **identische** `X-Registry-Signature` (kein Re-Sign). Nach Release (neue Revision) ändert sich die Signatur.

- [ ] **REG-04 — Sync seit Revision**
  `GET /api/v1/registry/sync?since=N&limit=M` → `200` mit `since,revisions,count,has_more`. `since` fehlt → `400`. `since` nicht-numerisch → `400`. `limit` > 1000 wird auf Default 100 begrenzt. `has_more=true` wenn mehr als `limit` Revisions vorhanden.

- [ ] **REG-05 — Resolve Chip / Matrix / Integrations / Registry / Combination**
  - `GET /api/v1/resolve/chip?name=…` → Manifest des neuesten stable Chips; unbekannt → `404`. `name` fehlt → `400`.
  - `GET /api/v1/resolve/matrix` (optional `?chip=`) → Matrix-Einträge.
  - `GET /api/v1/resolve/integrations` → Liste.
  - `GET /api/v1/resolve/registry?version=latest` → `{"version": <commit_sha>}` (Bridge-Format).
  - `GET /api/v1/resolve/combination?chip=&chip_version=&cli=` → `{compatible,status}`; ohne `chip`/`chip_version` → `400`; Header `Cache-Control: public, s-maxage=3600`; unbekannte Kombi → `{compatible:false,status:"UNKNOWN"}`.

- [ ] **REG-06 — Package-GET Sichtbarkeit (Namespace-Probing-Schutz)**
  `GET /api/v1/package/{name}/{version}`:
  - `stable` → `200` öffentlich (auch anonym).
  - `dev`/`staging` als **Eigentümer** → `200`; als **Fremder/anonym** → **`404`** (uniformes 404, *nicht* 403 — verhindert Existenz-Leak).
  - `yanked` (`YankedAt != NULL`) → `410 Gone` mit `name`,`version`.
  - Scoped-Route `/{scope}/{name}/{version}` korrekt rekonstruiert (`@robin/uart`).

- [ ] **REG-07 — Download-Redirect + Counter**
  `GET /api/v1/package/{name}/{version}/download` (stable) → `302` zu presigned S3-URL (15-min-Expiry). Sichtbarkeits-/Authz-Filter wie REG-06 (dev/staging fremd → `404`). **Counter:** nach N Downloads steigt `download_count` (in `search`/`packages/mine` sichtbar) **eventual** — Buffer 256, Best-Effort. **Timing:** Polling nötig; bei Server-Shutdown 3-s-Flush-Fenster.

- [ ] **REG-08 — Suche (Full-Text)**
  `GET /api/v1/search?q=…` → `200` `{results,has_more}`, nur `stable`, gefilterte Felder (kein `tarball_key`/Signatur). Leeres `q` → `200` leere Liste. `limit` > 100 gedeckelt. Ranking via `ts_rank`.

- [ ] **REG-09 — Ecosystem-Release-Download**
  `GET /api/v1/releases/{component}/{version}/download/{filename}`:
  - gültig & `published` & nicht `yanked` → `302` presigned (15 min), Pfad `releases/<s3Folder>/<version>/<filename>`.
  - `yanked` → `410 Gone` (+ Reason).
  - nicht `published` (CLI-Draft) → `404` „not yet published".
  - veraltete Patch-Version derselben Minor-Serie → `200`-Redirect **mit** `X-Toob-Warning` + `Warning: 299`.
  - explizit `deprecated` mit Custom-Warning → `X-Toob-Warning` = Custom-Text.
  - **Negativ:** unbekannte `component` → `400`; `version` verletzt `versionPattern` → `400`; `filename` mit `/`,`\`,`..` → `400`.

- [ ] **REG-10 — Cache-Sync nach Release (Single-Node)**
  Nach `POST /api/v1/admin/release` triggert `pg_notify('registry_index_update')` einen lokalen Cache-Rebuild → `GET /api/v1/registry/index` spiegelt die neue Revision/Pakete **eventual** wider. **Timing:** asynchron, Polling.

- [ ] **REG-11 — Optional-Auth am Package-Pfad**
  Package-GET/Download akzeptieren *optional* Auth: ohne Token funktioniert public-stable; mit gültigem Token werden zusätzlich eigene dev/staging-Pakete sichtbar. Ungültiger Token (vorhanden, aber falsch) → `401`.

- [ ] **REG-12 — Empty-State: Index ohne stable-Pakete**
  Auf einem frischen System (keine Revision, keine Pakete): `GET /api/v1/registry/index` → `200` mit leerem Index (alle Kategorie-Arrays leer: `chips:[], drivers:[], crypto:[], ...`), `X-Registry-Signature` trotzdem gesetzt. **Sinn:** CLI darf bei leerem Index nicht crashen; die Signatur muss auch über leere Daten gültig sein.

- [ ] **REG-13 — Empty-State: Suche ohne stable-Pakete**
  `GET /api/v1/search?q=esp32` → `200` `{results:[], has_more:false}`. Keine Pakete in dev/testing/staging werden angezeigt, auch nicht bei exakter Namensübereinstimmung. **Sinn:** Suchindex ist auf `stable` eingeschränkt; ein leeres System darf keine dev-Pakete leaken.

- [ ] **REG-14 — Empty-State: Resolve-Endpoints ohne Daten**
  - `GET /api/v1/resolve/chip?name=nonexistent` → `404`.
  - `GET /api/v1/resolve/matrix` → `200` mit leerer Matrix (nicht 500).
  - `GET /api/v1/resolve/integrations` → `200` mit leerer Liste.
  - `GET /api/v1/resolve/registry?version=latest` → Verhalten bei fehlendem Commit → klären: `404` oder `200` mit `version:null`.
  - `GET /api/v1/resolve/combination?chip=nope&chip_version=1.0.0` → `{compatible:false, status:"UNKNOWN"}`.
  **Sinn:** Alle Resolve-Endpoints müssen auf einem leeren System sauber antworten.

- [ ] **REG-15 — Download eines nicht-existierenden Pakets**
  `GET /api/v1/package/nonexistent/1.0.0/download` → `404` (nicht 500). Ebenso: `GET /api/v1/package/existing-name/99.99.99/download` (existierender Name, falsche Version) → `404`. **Sinn:** Uniform-404 auch im Download-Pfad, kein Informationsleak über existierende Namen.

- [ ] **REG-16 — Search-Query-Injection**
  `GET /api/v1/search?q=' OR 1=1--` → `200` leere Liste (kein SQL-Error). `q` mit 1000 Zeichen → `200` leere Liste (kein Timeout/Crash). `q` mit Sonderzeichen `%`, `_`, `\` → korrekt escaped. **Sinn:** Parameterisierte Queries in `ts_rank` und `to_tsquery` müssen Input-sicher sein.

---

## E6 — Organisationen, Rollen & Scopes

> Org-Rollen: `owner` (alles), `maintainer` (Members verwalten, keine Owner), `member` (publishen unter Scope). Scoped-Paketname: `@<org>/<name>`.

- [ ] **ORG-01 — Org anlegen & Quota**
  `POST /api/v1/orgs` (Session, `PermOrgCreate`) → `201` Org; Ersteller wird automatisch `owner`. **Quota:** `free` MaxOrgs=1 → zweite Org `403` „organization limit reached". **Validierung:** Name-Regeln (3–30, `[a-z0-9-]`, keine doppelten/führenden Bindestriche, nicht reserviert wie `admin`/`api`) → `400`. Duplikat-Name → `409`.

- [ ] **ORG-02 — Org-Lookup & eigene Orgs**
  `GET /api/v1/orgs/{name}` → `200`/`404`. `GET /api/v1/orgs/mine` → Memberships mit Rolle.

- [ ] **ORG-03 — Mitglied hinzufügen (Rollen-Autorität)**
  `owner` fügt `bob` als `member` hinzu → `200`. `maintainer` darf `member` adden, aber **nicht** `owner`/`maintainer` zuweisen → `403` „only owners can assign owner or maintainer roles". Ungültige Rolle → `400`.

- [ ] **ORG-04 — Mitglied entfernen (Hierarchie)**
  `maintainer` entfernt `member` → `200`; `maintainer` entfernt `owner` → `403` „maintainers cannot remove owners". `member` entfernt sich selbst → `200`. **Letzter Owner** entfernt sich selbst → `409` „cannot remove the last owner". Nicht-Mitglied entfernen → `404` „member not found".

- [ ] **ORG-05 — Mitglieder listen (nur Member)**
  `GET /api/v1/orgs/{name}/members` als Mitglied → `200` Liste. Als Nicht-Mitglied/anonym → `403`/`401`.

- [ ] **ORG-06 — Scoped Publish (Eigentum via Login)**
  Publisher `alice` darf `@alice/...` publishen (Scope == GitHub-Login) → `201`. `@otherorg/...` ohne Mitgliedschaft → `403 SCOPE_FORBIDDEN`.

- [ ] **ORG-07 — Scoped Publish (Eigentum via Mitgliedschaft)**
  `owner` legt Org `acme` an, fügt `bob` als `member` hinzu. `bob` publisht `@acme/widget` → `201`. Nach Entfernen aus der Org → erneuter `@acme/...`-Publish `403 SCOPE_FORBIDDEN`.

- [ ] **ORG-08 — Scoped Job-Visibility**
  Org-Mitglieder dürfen den Publish-Job eines scoped Pakets (`@acme/...`) via `GET /api/v1/publish/jobs/{id}` einsehen, auch wenn nicht Ersteller (`AuthorizePublishJobAction` → Scope-Claim). Nicht-Mitglied → `403`.

- [ ] **ORG-09 — Org löschen (Owner/Admin)**
  `DELETE /api/v1/orgs/{name}` als `owner` → `200`. Als `member` → `403`. **Admin-Bypass:** Core-Admin (Nicht-Mitglied) darf löschen → `200` *und* es wird ein Audit-Log-Eintrag „performed via admin override bypass" geschrieben (DB-Verifikation).

- [ ] **ORG-10 — Org-Quota nach Plan-Upgrade**
  Nach `set-plan` auf `pro` (MaxOrgs=5) kann der Publisher weitere Orgs anlegen; `enterprise` praktisch unbegrenzt (999).

- [ ] **ORG-11 — `orgs/mine` ohne Mitgliedschaften**
  Publisher ohne jegliche Org-Mitgliedschaft → `GET /api/v1/orgs/mine` → `200` mit leerer Liste (nicht `404`). **Sinn:** Deterministisches Empty-State-Verhalten für CLI.

- [ ] **ORG-12 — Doppeltes Mitglied-Hinzufügen**
  `owner` fügt `bob` als `member` hinzu → `200`. Erneuter `POST` (gleicher Publisher, gleiche Rolle) → `409 CONFLICT` (oder `200` idempotent?). Klären und dokumentieren. **Sinn:** Idempotenz-Verhalten für Retry-Szenarien festlegen.

- [ ] **ORG-13 — Org-Name-Reservierungen**
  Org-Erstellung mit reservierten Namen: `admin`, `api`, `system`, `www`, `help`, `support` → `400` „reserved name". **Sinn:** Namespace-Squatting kritischer Namen verhindern.

---

## E7 — Admin & Release-Lifecycle

> Alle Admin-Endpoints: `RequireAuth` → `RequireSessionToken` → `RequirePermission(<perm>)`. Tests mit `core-admin` (Session). Negativfälle aus E2 (AUTH-13/14) decken Token-/Permission-Gates ab.

- [ ] **ADM-01 — Staging-Review-Workflow**
  Vorbedingung: ein Paket in `staging` (`pending`) via E4. `GET /api/v1/admin/staging` → listet *accepted*-Pakete (anfangs leer). `POST /api/v1/admin/accept` (`name`,`version`) → `200 accepted`; danach erscheint es in `/admin/staging`. `POST /api/v1/admin/reject` (`name`,`version`,`reason`) → `200 rejected`; **Seiteneffekt:** Stage geht zurück auf `dev` (verhindert Unique-Index-Deadlock), `staging_feedback` gesetzt. Unbekanntes Paket → `404`.

- [ ] **ADM-02 — Release-Batch (staging → stable)**
  Mehrere `accepted` Pakete → `POST /api/v1/admin/release` → `200` mit `revision_id`, `count`, `mirror_status:"queued"`. Effekte: Pakete = `stable`, neue `revisions`-Zeile mit deterministischem `commit_sha` (SHA256 über Inhalt) und Changelog (`action:"promoted"`). `GET /api/v1/registry/index` spiegelt sie (eventual, REG-10). **Leerfall:** keine accepted Pakete → `400` „no accepted packages to release".

- [ ] **ADM-03 — Dashboard-Status**
  `GET /api/v1/admin/status` → `StagingDashboard`: `staging_packages`, `pending_prs`, `validation_jobs_stats`, `publish_jobs_stats` (jeweils Queued/Running/Passed/Failed/Total + FailureRate). Werte stimmen mit zuvor erzeugten Jobs überein.

- [ ] **ADM-04 — Format-Version-Bump**
  `POST /api/v1/admin/bump-format-version` → `200` mit erhöhtem `format_version`; neue Revision angelegt. Index zeigt neuen `FormatVersion`.

- [ ] **ADM-05 — Matrix-Update**
  `POST /api/v1/admin/matrix-update` (`chip`,`chip_version`,`combo_key`,`status`) → `200 updated`; neue Revision. `GET /api/v1/resolve/combination` reflektiert Status. Fehlende Felder → `400`. Unbekannte Kombi → `404`.

- [ ] **ADM-06 — Cache-Purge**
  `POST /api/v1/admin/cache-purge` → `200 cache_purged` (Cloudflare-Aufruf). In Dev ggf. gegen Test-Zone/Stub; bei fehlenden CF-Credentials → `500` (dokumentieren).

- [ ] **ADM-07 — Set-Plan**
  `POST /api/v1/admin/set-plan` (`publisher_id`,`plan_tier`,`overrides?`) → `200 plan_updated`. `GET /api/v1/me` des Ziels zeigt neuen Plan/Limits. Ungültiger Tier → `400`. Unbekannter Publisher → `404`. **Override-Test:** `overrides.max_dev_packages` setzt individuelles Limit (kombiniert mit Host-Cap, PUB-06).

- [ ] **ADM-08 — Revoke + Advisory-Kette**
  Vorbedingung: ein `stable` Paket. `POST /api/v1/admin/revoke` (`name`,`version`,`severity`,`title`,`description`) → `200` mit `advisory_id`, `affected_revisions`, `affected_publishers`, `mirror_status`. Effekte: Stage=`revoked`, S3-Objekt gelöscht (Download danach `404`/`410`), `advisories`-Zeile erzeugt, Notifications für betroffene Sync-Publisher (→ E10). Fehlende Pflichtfelder → `400`. Unbekanntes Paket → `404`.

- [ ] **ADM-09 — Archive**
  `POST /api/v1/admin/archive` (`name`,`version`) auf `stable` → `200 archived` (Stage=`archived`, `yanked_at` gesetzt). Auf Nicht-stable → `404`.

- [ ] **ADM-10 — Mirror-Push (manuell)**
  `POST /api/v1/admin/mirror-push` → `200 mirror_push_started` (async). **Erfordert echtes Test-GitHub** (Git-Data-API) → in reinen API-Tests gegen Test-Org oder als E14 markieren; hier nur „Request akzeptiert, kein Server-Fehler".

- [ ] **ADM-11 — Release-Lifecycle (Ecosystem)**
  - `GET /api/v1/admin/releases` → gruppiert nach Component.
  - `POST /api/v1/admin/releases/trigger` (`component`,`tag_name`,`commit_sha`) → `202 queued`, `job_id`; Audit-Eintrag `release.trigger`.
  - `POST /api/v1/admin/release-jobs/{id}/cancel` → `200 cancelled`; Nicht-stornierbar → `409`.
  - `POST /api/v1/admin/releases/yank` (`component`,`version`,`reason`) → `200 yanked`; danach Download `410` (REG-09).
  - `POST /api/v1/admin/releases/unyank` → `200 unyanked`; Download wieder `302`.
  - `POST /api/v1/admin/releases/deprecate` (`deprecated`,`warning`) → `200`; Download trägt `X-Toob-Warning`.
  - `POST /api/v1/admin/releases/{id}/publish` (Draft→published) → `200` (GitHub-abhängig, ggf. E14).
  Jeweils Pflichtfeld-Validierung → `400`; jeweils Audit-Eintrag (DB-Verifikation der `audit_log`-Zeile, da kein Lese-Endpoint existiert — **Gap notieren**).

- [ ] **ADM-12 — Audit-Log-Integrität (DB-Verifikation)**
  Nach jeder Admin-Aktion (revoke, release, accept, reject, set-plan, archive, bump-format-version) → direkte DB-Abfrage auf `audit_log`: Eintrag existiert mit korrektem `action`, `actor_id`, `target_id`, `details` (JSON), Timestamp innerhalb der letzten Sekunde. **Sinn:** Da kein Lese-API für Audit-Logs existiert (Gap aus ADM-11), muss die DB direkt verifiziert werden.

- [ ] **ADM-13 — Admin-Dashboard: Empty-State**
  `GET /api/v1/admin/status` auf frischem System → `200`, `staging_packages: 0`, `pending_prs: 0`, alle Stats-Zähler auf `0`, `failure_rate: 0.0` (kein Division-by-Zero-Fehler bei `0/0`). **Sinn:** Dashboard darf bei leeren Tabellen nicht crashen.

- [ ] **ADM-14 — Release ohne vorigen Accept**
  Direkt `POST /api/v1/admin/release` ohne vorheriges `/admin/accept` → `400` „no accepted packages to release" (bereits im Leerfall von ADM-02 erwähnt, hier als dedizierter Story isoliert). **Sinn:** Sicherstellen, dass der Release-Batch nie versehentlich 0 Pakete promotet oder eine leere Revision erzeugt.

---

## E8 — Worker-API / Zero-Trust (mTLS)

> Interner Port, **nur** mit Client-Cert `CN=worker.global.nomad` erreichbar. Diese Epic testet die Worker-Schnittstelle direkt (Harness = Worker). Validierungs-Ingestion ist hier *ohne* VM vollständig testbar: claim → upload-request → presigned PUT eines echten Tarballs → complete → serverseitige Ingestion (Checksum, Tarball-Validierung, Vault-Sign, DB→staging).

- [ ] **WRK-01 — mTLS-Identitätszwang**
  Worker-Endpoint **ohne** Client-Cert → `401` „client certificate required". Mit Cert aus der PKI, aber `CN != worker.global.nomad` → `403` „invalid certificate identity". (Cert mit falschem CN ggf. via Test-PKI erzeugbar; sonst als Doku-/Manual-Test.)

- [ ] **WRK-02 — Validation-Claim → leer / Job**
  `POST /api/v1/worker/claim` ohne wartenden Job → `204 No Content`. Mit gequeueter Validation-Job (via Webhook/Mock, E9) → `200` `ClaimedJob` (`id,pr_number,repo,head_sha,diff_url,job_token`). Job-Status → `RUNNING`, `worker_id`/`started_at` gesetzt. **Seiteneffekt:** GitHub-Commit-Status `pending` (Best-Effort).

- [ ] **WRK-03 — Upload-Request (presigned)**
  `POST /api/v1/worker/jobs/{id}/upload-request` (Header `X-Job-Token`) mit `packages[]` → `200` presigned PUT-URLs (Pfad `packages/<cat>/<name>/<name>-v<ver>-<jobID>.tar.gz`, 5-min-Expiry). **Validierung:** ungültiger Paketname/Version/Kategorie → `400`. **Auth:** falscher/fehlender Job-Token → `401`.

- [ ] **WRK-04 — Complete PASS → Ingestion → staging**
  Harness lädt das Tarball per PUT an die presigned URL (mit *passendem* SHA256), dann `POST /api/v1/worker/jobs/{id}/complete` `status:"PASSED"`, `packages[]` (inkl. `sha256`). Server: holt Objekt aus S3, prüft Checksum, validiert+scant Tarball, Typosquat-Check (Warning, kein Block), signiert via Vault, schreibt Paket nach **`staging`** (Publisher = Contributor). **Negativ-Pfade:**
  - SHA-Mismatch → Job `FAILED` (Server bricht Ingestion ab), Response Fehler.
  - Objekt nicht in S3 → `409`-artiger Ingest-Fehler.
  - Tarball > 50 MiB → 413-artiger Fehler.
  GitHub-Commit-Status `success` (Best-Effort). Job-Token invalidiert.

- [ ] **WRK-05 — Complete FAIL (Validation)**
  `status:"FAILED"` → Job `FAILED`, kein Ingest, GitHub-Status `error`. Job-Token invalidiert.

- [ ] **WRK-06 — Job-Token-Lebenszyklus**
  Token validiert **nur** solange Job `RUNNING`/`COMPILING`. Nach `complete` (invalidiert) → erneuter Worker-Call mit selbem Token → `401`. Falscher Token → `401`.

- [ ] **WRK-07 — Publish-Claim & Download**
  `POST /api/v1/worker/publish-claim` → `PublishClaimedJob` (mit `tarball_key`). `GET /api/v1/worker/packages/{id}/download` → streamt das dev-Tarball (`application/gzip`). Unbekannte ID → `404`.

- [ ] **WRK-08 — Heartbeat & Cancel-Signale**
  `POST /api/v1/worker/heartbeat` (`worker_id`) → `200` `{status:"ok", cancel_jobs:[...]}`. Aktualisiert `system_status` (`worker:<id>`). Nach `cancel` eines Release-Jobs (ADM-11) für diesen Worker erscheint dessen ID in `cancel_jobs`. **Readiness-Kopplung:** frischer Heartbeat → HEALTH-03 `worker="ok"`.

- [ ] **WRK-09 — Release-Claim (Capability-Filter)**
  `POST /api/v1/worker/release-claim` mit leeren `capabilities` → kein Job. Mit passender Capability (z. B. `["semver"]`) und gequeuetem semver-Job → `200` `ReleaseClaimedJob`. Compiler-Jobs liefern zusätzlich `Env` (Docker/S3-Credentials) — verifizieren, dass diese **nur** für `component=compiler` gesetzt werden.

- [ ] **WRK-10 — Release-Complete Idempotenz + Token-Grace**
  Release-Job `complete` (`PASSED`/`FAILED`). **Idempotenz:** zweiter `complete`-Retry mit demselben Token innerhalb **5 min** nach Abschluss → `200` (idempotent, kein Re-Processing). Bereits terminaler Job → Status wird unverändert zurückgegeben. **Artifact-Namespace-Guard:** `Artifacts[].ObjectKey` außerhalb `releases/<component>/<version>/` → Job wird auf `FAILED` gesetzt.

- [ ] **WRK-11 — Release-Upload-Request & Log-Chunk**
  `POST /api/v1/worker/release-jobs/{id}/upload-request` → presigned PUT-URLs (Filename-Sanitizing wie WRK-03). `POST /api/v1/worker/release-jobs/{id}/log-chunk` → hängt Log-Chunk an (`build_log`). Leerer Chunk → `400`; Chunk > 256 KB wird abgeschnitten.

- [ ] **WRK-12 — Compiler-Job-Deferral**
  Wird ein `compiler`-Release-Job geclaimt, dessen CLI-Abhängigkeit (aus `compiler_manifest.json`) noch **nicht published** ist → Server re-queued den Job (`204 No Content` an den Worker), bis die CLI-Version published ist. (Erfordert Test-GitHub für `GetFileContent` → ggf. E14.)

- [ ] **WRK-13 — Body-Limits intern**
  Worker-Claims mit überlangem Body → durch `MaxBytesReader` (1 KB/2 KB je Endpoint) begrenzt → `400`. Log/Complete bis `maxLogSize` (5 MiB), darüber abgeschnitten.

- [ ] **WRK-14 — Claim ohne wartende Jobs (alle drei Typen)**
  Auf leerem System: `POST /api/v1/worker/claim` → `204`. `POST /api/v1/worker/publish-claim` → `204`. `POST /api/v1/worker/release-claim` → `204` (bzw. `204` mit leeren Capabilities). **Sinn:** Worker-Polling auf leerem System produziert keine Fehler, nur leere Antworten.

- [ ] **WRK-15 — Worker-Complete mit manipuliertem Paket-Pfad**
  `complete` mit `packages[].name` oder `packages[].category` die nicht zum geclaimten Job gehören → Server erkennt Diskrepanz und lehnt Ingestion ab (oder loggt Warning). **Sinn:** Ein kompromittierter Worker darf nicht ein fremdes Paket in die Registry injizieren.

---

## E9 — Webhooks (PR / Push / Release)

> Alle Webhook-Routen sind durch `VerifyWebhookSignature(WebhookSecret)` geschützt (HMAC, E0-05). Für PR-Validierung *ohne* echtes GitHub steht im Dev-Environment (`TOOB_ENV != production`) der `mock-webhook`-Endpoint zur Verfügung, der die `ListPRFiles`-GitHub-Abhängigkeit umgeht (Dateien werden im Body übergeben).

- [ ] **HOOK-01 — HMAC-Zwang**
  `POST /webhook/pr` ohne `X-Hub-Signature-256` → `403` „missing signature". Falsches Format (`sha1=…`) → `403`. Falsche Signatur → `403`. Korrekte Signatur → Verarbeitung.

- [ ] **HOOK-02 — Event-Typ-Filter**
  `X-GitHub-Event != pull_request` an `/webhook/pr` → `200 ignored`. Analog `/webhook/push` und `/webhook/release`.

- [ ] **HOOK-03 — PR opened/synchronize → Job (Mock)**
  `POST /api/v1/admin/mock-webhook` (Core, Dev-only) mit `action:"opened"`, `files:[chips/...]`, gültiger `github_user_id` (registriert) → `202 queued`, `job_id`. Ein `validation_jobs`-Eintrag (`QUEUED`) entsteht → durch Simulated Worker (E8) weitertestbar.

- [ ] **HOOK-04 — Opt-In-Login (echte PR-Route)**
  `POST /webhook/pr` (signiert) mit `pull_request.user.id` = **nicht registriert** → `403` `status:"rejected"`, Grund „unregistered user". (Verhindert Auto-Account.)

- [ ] **HOOK-05 — Path-Guard**
  PR mit Datei außerhalb erlaubter Präfixe (`chips/`,`drivers/`,`crypto/`,`arch/`,`toolchains/`,`integrations/`) → über Mock-Webhook `status:"rejected"`, Grund „forbidden path: …" — **keine** VM/Job-Erzeugung. Traversal/absoluter Pfad in Dateiname → ebenfalls Reject.

- [ ] **HOOK-06 — PR closed → Cancel**
  `action:"closed"` → `200 cancelled`; vorhandene `QUEUED`/`RUNNING`-Jobs des PR werden `FAILED` („Cancelled: PR closed").

- [ ] **HOOK-07 — Push auf main → SemVer-Job**
  `POST /webhook/push` (signiert), `ref:"refs/heads/main"`, `after:<sha>` → `202 queued` (component `semver`). **Bot-Loop-Schutz:** Commit mit `[skip ci]` → `200 ignored`; Autor `registry-bot@the-toob.com` → `200 ignored`. Tag-Push (`refs/tags/...`) → `200 ignored` („releases must be triggered by the internal SemVer oracle"). Anderer Branch → `200 ignored`.

- [ ] **HOOK-08 — Release published → Ecosystem-Promotion**
  `POST /webhook/release`, `action:"published"`, Repo == `CLIReleaseRepo`, `tag_name:"cli/vX.Y.Z"` → `200 published`, CLI-Release wird `published=true` (REG-09 Download danach erlaubt). Anderes Repo → `200 ignored`. `action != published` → `200 ignored`.

---

## E10 — Notifications & Security-Advisories

> Kette: Publisher synct Revision (`/registry/ack`) → Sync-Log → Admin revoked Paket dieser Revision → Advisory + Notifications → Publisher liest/acked.

- [ ] **NOTIF-01 — Sync-Ack protokolliert**
  `POST /api/v1/registry/ack` (Session, `revision_id`,`client_info`) → `200 recorded` + (leere) `advisories`. `revision_id <= 0` → `400`. Doppelter Ack derselben Revision → upsert (kein Fehler).

- [ ] **NOTIF-02 — Revoke erzeugt zielgerichtete Notification**
  `alice` published+released `pkg@1.0.0` (Revision R). `bob` synct R (NOTIF-01). Admin revoked `pkg@1.0.0` (ADM-08) → Advisory für die betroffenen Revisions. `bob`s `GET /api/v1/notifications` → enthält die Advisory (`count >= 1`). Ein nicht-synchronisierter Publisher erhält **keine** Notification.

- [ ] **NOTIF-03 — In-Band-Delivery via Ack**
  Nach Revoke liefert ein erneuter `POST /api/v1/registry/ack` von `bob` die offenen Advisories im Response mit (`advisories` nicht leer).

- [ ] **NOTIF-04 — Acknowledge**
  `POST /api/v1/notifications/ack` (`advisory_ids:[…]`) → `200 acknowledged`; danach `GET /api/v1/notifications` → die Advisory nicht mehr enthalten (`delivered=true`). Leere ID-Liste → `400`.

- [ ] **NOTIF-05 — Auth-Zwang**
  Notifications-Endpoints ohne Token → `401`.

---

## E11 — Cross-Cutting Middleware

- [ ] **MW-01 — Rate-Limit (public)**
  Burst > 100 / Rate 50 req/s von einer IP → `429` mit `Retry-After: 10` und `error:"too many requests"`. Nach Cooldown wieder `200`. **Hinweis:** IP-Ermittlung respektiert `CF-Connecting-IP`/`X-Forwarded-For` nur von Trusted-Proxies (privat/Loopback) — direkter Client nutzt `RemoteAddr`.

- [ ] **MW-02 — Body-Limit (Standard)**
  Auf einem Nicht-Publish-JSON-Endpoint Body > 256 KB → `400`/`413`. (Publish/Complete/Webhook bis 10 MiB — siehe PUB-16.)

- [ ] **MW-03 — Kompression**
  Request mit `Accept-Encoding: gzip` auf JSON-Antwort → `Content-Encoding: gzip` + `Vary: Accept-Encoding`. SSE-Request (`Accept: text/event-stream`) → **nicht** komprimiert (LIFE-10).

- [ ] **MW-04 — Timeout vs. SSE**
  Standard-Endpoints unterliegen 30-s-Write-Deadline; `/.../stream`-Routen sind ausgenommen (Langläufer). Verifizieren, dass ein offener SSE-Stream nicht nach 30 s abgeschnitten wird.

- [ ] **MW-05 — Request-ID & Logging**
  Jede Antwort trägt `X-Request-ID` (übernommen aus Request oder generiert). (Logging selbst per Log-Inspektion optional.)

- [ ] **MW-06 — Panic-Recovery**
  Ein Handler-Panic (falls provozierbar, z. B. via gezielt fehlerhaftem Input, der einen `panic` triggert) → `500` `{"error":"internal server error"}`, Server bleibt erreichbar (nächster Request `200`).

- [ ] **MW-07 — Interner Rate-Limit**
  Worker-API hat eigenen, großzügigeren Limiter (100/200). Exzessive Worker-Calls → `429`, ohne dass legitime Heartbeats dauerhaft blockiert werden.

- [ ] **MW-08 — Rate-Limit-Recovery**
  IP überschreitet Rate-Limit → `429` mit `Retry-After: 10`. Nach Warten von `Retry-After`-Sekunden → nächster Request `200`. **Sinn:** MW-01 prüft nur, dass geblockt wird — dieser Test prüft, dass das System sich **erholt** und der Client-Wiedereintritt funktioniert.

- [ ] **MW-09 — Rate-Limit-IP-Isolation**
  IP-A überschreitet Rate-Limit → `429`. Gleichzeitig: IP-B (anderer Client) → `200` ungestört. **Sinn:** Sicherstellen, dass der per-IP-Limiter nicht versehentlich global wirkt (z. B. durch fehlerhafte `getIP`-Logik bei fehlenden Proxy-Headern).

- [ ] **MW-10 — Unbekannte Route**
  `GET /api/v1/nonexistent/endpoint` → `404` (oder `405` wenn nur die Methode falsch ist). Response-Body: JSON-Format (`{"error":"not found"}`), nicht HTML. **Sinn:** API-Konsistenz — auch unbekannte Routen liefern strukturierte Fehler.

- [ ] **MW-11 — Falsche HTTP-Methode**
  `GET /api/v1/publish` (erwartet POST) → `405` (oder `404` je nach Router). `DELETE /api/v1/registry/index` → analog. **Sinn:** Keine unbeabsichtigte Endpoint-Erreichbarkeit.

- [ ] **MW-12 — Malformed JSON auf JSON-Endpoints**
  `POST /api/v1/publish/promote` mit Body `{name: invalid}` (kein gültiges JSON) → `400` mit lesbarer Fehlermeldung. Leerer Body `""` → `400`. Body `null` → `400`. Body `[]` (Array statt Objekt) → `400`. **Sinn:** Jeder JSON-Endpoint muss Parsing-Fehler abfangen, ohne 500 zu werfen.

- [ ] **MW-13 — HEAD-Request-Verhalten**
  `HEAD /health` → `200` ohne Body, aber mit korrekten `Content-Length`/`Content-Type`-Headern. `HEAD /api/v1/registry/index` → `200` mit `ETag`/`X-Registry-Signature`-Headern. **Sinn:** HEAD muss die gleichen Header wie GET liefern, aber keinen Body — relevant für Monitoring-Probes (Cloudflare LB-Monitor).

- [ ] **MW-14 — CORS-Verhalten**
  `OPTIONS /api/v1/registry/index` mit `Origin: https://example.com` → Response prüfen: kein `Access-Control-Allow-Origin` (API ist nicht für Browser-Clients gedacht) **oder** korrekt konfiguriert falls doch. **Sinn:** Unbeabsichtigte CORS-Freigabe kann Credential-Leaks ermöglichen.

- [ ] **MW-15 — Doppel-Slash und Trailing-Slash URL-Normalisierung**
  `GET /api/v1//registry/index` und `GET /api/v1/registry/index/` → entweder identisch zu `GET /api/v1/registry/index` (`200`) oder konsistentes `404`. **Sinn:** Pfad-Normalisierung im Router darf keine unbeabsichtigten Bypass-Pfade öffnen.

---

## E12 — Resilienz & Hintergrund-Jobs

> Diese Tests sind **timing-sensitiv** (Reaper-Intervalle) und teils nur über DB-Injektion eines „hängenden" Zustands praktikabel. Klar als langsame/optionale Suite kennzeichnen.

- [ ] **BG-01 — Publish-Job-Reaper**
  Inject: `publish_jobs` in `COMPILING`, `started_at` älter als 10 min, ohne frischen Worker-Heartbeat. Erwartung nach Reaper-Lauf (Intervall 2 min): Reset auf `QUEUED` (`retry_count++`) solange `< 3`; danach `FAILED` **und** zugehöriges Paket `testing`→`dev` mit Feedback „compile validation timed out". **Heartbeat-Schutz:** mit frischem `worker:<id>`-Heartbeat (< 30 s) wird **nicht** gereapt.

- [ ] **BG-02 — Release-Job-Reaper (Heartbeat-basiert)**
  Inject: `release_jobs` `RUNNING`, `COALESCE(last_heartbeat, started_at)` älter als 20 min → Requeue (`< 3` Retries) bzw. `FAILED`. Mit regelmäßigem `last_heartbeat` (via `UpdateHeartbeat`) wird ein langlaufender Build **nicht** vorzeitig gereapt.

- [ ] **BG-03 — Validation-Job-Cancel bei PR-close**
  Bereits in HOOK-06; hier zusätzlich: Cancel während Job `RUNNING` (Worker hält Token) → Job `FAILED`; nachfolgender Worker-`complete` mit altem Token → `401` (Token via Cancel/Invalidate ungültig).

- [ ] **BG-04 — OAuth-Session-Cleanup**
  Inject: abgelaufene `oauth_sessions` → nach Cleaner-Lauf (Intervall 1 min) gelöscht. (DB-Verifikation.)

- [ ] **BG-05 — Cache-Sync horizontal (Single-Node-Approx.)**
  `pg_notify('registry_index_update', <rev>)` (z. B. durch Release oder direkten Notify) → lokaler Cache-Rebuild, `GET /registry/index` zeigt neue Revision. (Mehr-Node-Variante nur in E14 mit zwei API-Instanzen sinnvoll.)

- [ ] **BG-06 — Graceful-Shutdown-Flush**
  Bei SIGTERM: 15-s-Drain (Health=503), dann Shutdown; Download-Count-Worker flusht innerhalb 3 s gepufferte Increments (REG-07). Verifizieren, dass kurz vor Shutdown ausgelöste Downloads gezählt werden. (Kontrollierter Shutdown nötig.)

- [ ] **BG-07 — S3-Orphan-Cleanup**
  Inject: S3-Objekt ohne zugehörige `packages`-Zeile, `LastModified` älter als 2 h → nach Cleanup-Cron (24 h, +5 min Startup) gelöscht. Neu hochgeladene (< 2 h) Objekte werden **nicht** gelöscht. (Langsam/optional; ggf. Cron-Trigger manuell anstoßen.)

- [ ] **BG-08 — Vault-Kurzzeitausfall (Transit-Signierung)**
  Während eines Publish-Requests wird Vault (oder die Transit-Engine) temporär unerreichbar → `500` mit aussagekräftigem Fehler (nicht Panic). Nach Vault-Wiederherstellung → nächster Publish funktioniert (`201`). **Sinn:** Sicherstellen, dass Vault-Fehler nicht den Server in einen inkonsistenten Zustand versetzen (Paket in DB, aber nicht signiert). Ggf. via Vault-Token-Revoke simulierbar.

- [ ] **BG-09 — S3-Kurzzeitausfall (Upload)**
  Während eines Publish-Requests ist S3 unerreichbar → der Request muss **atomar** scheitern: kein Paket in der DB ohne zugehöriges S3-Objekt. Status: `500` oder `503`. **Sinn:** Die Reihenfolge DB-Insert → S3-Upload → Finalize muss bei S3-Fehler rückgerollt werden.

- [ ] **BG-10 — Audit-Log-Retention**
  Inject: `audit_log`-Einträge mit `created_at` älter als 2 Jahre → nach `runAuditLogRetention` (täglicher Cleanup) gelöscht. Einträge jünger als 2 Jahre bleiben erhalten. **Sinn:** Expliziter Test der 2-Jahres-Retention-Logik, nicht nur Vertrauen auf den Hintergrund-Job.

---

## E13 — End-to-End Golden Paths (Rollen-Kombinationen)

> Vollständige, narrative Szenarien, die mehrere Epics verketten. Diese sind die „Bedienungszyklen", die der Auftrag fordert.

- [ ] **E2E-01 — Solo-Contributor Happy Path**
  `alice` (Session): Publish dev → Promote → **Simulated Worker** PASS → Paket `staging`. `core-admin`: accept → release. Ergebnis: Paket `stable`, in `GET /registry/index`, per `GET /search` auffindbar, per Download (`302`) ladbar, `download_count` steigt. Revision/Signatur konsistent (REG-01/02).

- [ ] **E2E-02 — Org-Kollaboration & Entzug**
  `owner` legt Org `acme` an → fügt `bob` (`member`) hinzu. `bob` publisht `@acme/widget` → Promote → Worker PASS → staging → admin release → stable. `bob` und `owner` sehen das Paket. `owner` entfernt `bob`. `bob`s nächster `@acme/...`-Publish → `403 SCOPE_FORBIDDEN`. Org-Job-Visibility (ORG-08) für `owner` weiterhin gegeben.

- [ ] **E2E-03 — Name-Claim-Race (kompetitiv)**
  `alice` und `bob` publishen denselben unscoped `name@version` nach dev (beide `201`), beide promoten (beide `202`). Simulated Worker completet beide PASS: erster → staging (Claim), zweiter → `409 name_claimed` + Auto-Revert nach dev mit Feedback (LIFE-08). Anschließend kann nur der Claim-Inhaber releasen.

- [ ] **E2E-04 — Revocation & Advisory (cross-publisher)**
  `alice` published+released `pkg@1.0.0` (Revision R). `bob` synct R (`/registry/ack`). `core-admin` revoked `pkg@1.0.0` (severity `critical`). Ergebnis: Stage `revoked`, S3-Objekt weg (Download `404`/`410`), Advisory erzeugt, `bob`s `/notifications` zeigt sie → `bob` acked → Liste leer. Index reflektiert die Entfernung (eventual).

- [ ] **E2E-05 — CI-Token-Pipeline (Scopes)**
  `alice` (Session) erstellt CI-Token mit Scopes `publish:promote`,`read`. Mit dem CI-Token: Publish (`publish`-Prefix erfüllt) + Promote funktionieren; `GET /admin/status` → `403` (Session erforderlich, AUTH-13). `alice` revoked den Token → nachfolgende CI-Calls `401`.

- [ ] **E2E-06 — Validation-Ingestion über Webhook→Worker**
  `core-admin` enqueued PR-Job via `mock-webhook` (Dateien unter `drivers/...`, registrierte `github_user_id` von `bob`). **Simulated Worker**: claim → upload-request → presigned PUT eines gültigen Driver-Tarballs (SHA passend) → complete PASS. Server ingestet das Paket nach `staging` (Publisher = `bob`). `core-admin`: accept → release → stable. Typosquat-Warning erscheint, wenn ein ähnlicher Name existiert (E0-23), blockiert aber nicht.

- [ ] **E2E-07 — Anonymer Nutzer-Pfad**
  Ohne jegliche Auth: `/health` ✓, `/registry/index` ✓ (mit ETag/Signatur), `/search` ✓, Download eines `stable` Pakets ✓ (`302`). Zugriff auf fremdes dev/staging → `404`. Publish/Promote/Admin → `401`.

- [ ] **E2E-08 — Fresh-System-Exploration (Zero-Content-Pfad)**
  **Auf einem komplett frischen System** (nur Seed-Publisher, keine Pakete, keine Revisionen): anonymer Client durchläuft alle öffentlichen Read-Pfade: `/health` → `200`. `/ready` → `200`. `/registry/revision` → `{revision:0}`. `/registry/index` → `200` (leerer Index, gültige Signatur). `/search?q=anything` → `200` `{results:[]}`. `/resolve/matrix` → `200` leer. `/package/foo/1.0.0` → `404`. `/package/foo/1.0.0/download` → `404`. **Sinn:** Der allererste Test nach Deployment — beweist, dass der Server auf einem leeren System nicht crasht und konsistente, nicht-leere JSON-Responses liefert.

- [ ] **E2E-09 — Full-Lifecycle mit Plan-Wechsel**
  `alice` (free, MaxDev=10): published 10 dev-Pakete → 11. scheitert. `core-admin` setzt Plan auf `pro` → `alice` published 11. bis 25. → `429` erst bei Pro-Limit (50). **Sinn:** Plan-Wechsel wirkt sofort auf die Quota-Prüfung, ohne dass bestehende Pakete invalidiert werden.

- [ ] **E2E-10 — Concurrent-Publish-Race (gleicher Publisher)**
  `alice` sendet **gleichzeitig** (parallel) 3 Publish-Requests für verschiedene Pakete → alle 3 erhalten `201` (keine DB-Deadlocks, keine Race-Condition bei Quota-Zählung). **Sinn:** Unter Last darf es keine DB-Serialisierungsfehler geben, die dem Publisher als 500 durchschlagen.

---

## E14 — Full-Stack / Real-Worker (optional, langsam, infrastrukturabhängig)

> Diese Epic erfordert reale Abhängigkeiten, die in einer leichten API-Test-Suite nicht abbildbar sind: KVM-fähige Worker-Hosts (Firecracker), ein Test-GitHub-Org (Git-Data-API, Commit-Status, Releases), ggf. Hetzner-API + Nomad (Autoscaler). Hier wird der Simulated-Worker durch einen **echten** Worker ersetzt.

- [ ] **FS-01 — Echte Compile-Validierung (Promote→VM→staging)**
  Realer Worker claimt Publish-Job, lädt Tarball, startet Firecracker-VM (`vmrunner`), kompiliert Quelldateien mit toolchain-Präfix, schreibt `result.json`. Bei Erfolg → Paket `staging`. Test: gültige vs. nicht-kompilierende Quelldatei → `PASSED`/`FAILED` Pfade. Sicherheits-Guard: `compiler_prefix` mit `/`,`\`,`.` → Build-Fehler.

- [ ] **FS-02 — SemVer-Oracle (Push→main)**
  Echter Worker mit Monorepo-Checkout führt SemVer-Oracle-VM aus (ABI-Symbol-Diff via `nm`, Header-Diff, Go-AST-`ports.go`-Diff, Compiler-Manifest-7-Dimensionen). Verifizieren: PATCH/MINOR/MAJOR-Klassifikation, ProtocolVersion-Pflichtbump bei BREAKING, korrekte `tags_to_push`, automatische Folge-Job-Enqueues. Ancestry-Check verhindert Reverse-Diff bei out-of-order Commits.

- [ ] **FS-03 — CLI-Release-Cross-Compile**
  Worker baut Windows/Linux/macOS-Binaries, packt (zip/tar.gz), holt presigned URLs, lädt nach S3, completet. Bei Teil-Upload-Fehler → Draft-Release wird gelöscht (Atomic-Rollback). Danach `webhook/release published` → Ecosystem `published`.

- [ ] **FS-04 — Core-SDK-Mirror**
  Worker baut Core-SDK, packt managed Pfade, completet → Server mirror-pusht in Public-Repo (Tree-Diff gegen `mirror_manifest.json`, Fast-Forward-Only, Tag). Advisory-Lock verhindert konkurrierende Mirrors.

- [ ] **FS-05 — Mirror-Push (Release-Batch)**
  `POST /api/v1/admin/release` löst echten Mirror-Push der stable Pakete + `registry.json` + `compatibility_matrix.json` in den Public-Mirror aus (Git-Data-API). Tarball-Extraktion in den Tree mit Zip-Bomb-Limits.

- [ ] **FS-06 — Autoscaler**
  Bei steigender Queue-Tiefe provisioniert der Autoscaler Hetzner-Worker (wrapped Vault SecretID, cloud-init), bei Leerlauf > IdleTimeout drained er Nomad-Knoten und löscht die VM. Verifizieren: Wait-Time-Heuristik, Cooldown (2 min), Min/Max-Worker-Grenzen, kein doppeltes Scale-Down (`drainingNodes`). **Nur** mit realem Nomad+Hetzner-Sandbox.

- [ ] **FS-07 — Vault-Token-Renewal & Rotation**
  Langläufer-Test: Server erneuert Vault-Token bei 50 % TTL; Transit-Signaturen bleiben über die Renewal-Grenze hinweg gültig (REG-01-Signatur nach simulierter Renewal weiterhin korrekt).

---

## Anhang A — Kritische Timings (Assertion-Referenz)

|
 Mechanismus 
|
 Wert 
|
 Relevante Stories 
|
|
---
|
---
|
---
|
|
 Presigned GET/Download-Expiry 
|
 15 min 
|
 REG-07, REG-09 
|
|
 Presigned PUT-Expiry 
|
 5 min 
|
 WRK-03, WRK-11 
|
|
 OAuth-Session-TTL / Exchange-Grace 
|
 5 min / 10 s 
|
 AUTH-02/04 
|
|
 Worker-Heartbeat-Freshness (Readiness) 
|
 30 s 
|
 HEALTH-03, WRK-08 
|
|
 Job-Token-Grace (Release-Complete) 
|
 5 min 
|
 WRK-10 
|
|
 Publish-Reaper Intervall / MaxAge / Retries 
|
 2 min / 10 min / 3 
|
 BG-01 
|
|
 Release-Reaper Intervall / MaxAge / Retries 
|
 2 min / 20 min / 3 
|
 BG-02 
|
|
 OAuth-Cleaner / Audit-Retention 
|
 1 min / 24 h (2 J) 
|
 BG-04 
|
|
 Rate-Limit public / intern 
|
 50 r/s (b100) / 100 (b200) 
|
 MW-01, MW-07 
|
|
 Auth-Cache-TTL / Generation-Rotation 
|
 60 s / 2500 
|
 AUTH-10 
|
|
 SSE Heartbeat / Max-Stream 
|
 15 s / 15 min 
|
 LIFE-10 
|
|
 Graceful-Drain / Shutdown / Flush 
|
 15 s / 10 s / 3 s 
|
 HEALTH-04, BG-06 
|
|