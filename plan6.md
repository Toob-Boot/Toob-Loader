# Toob Identity — Endpunktliste, Listener-Topologie und Enforcement-Zuordnung

**Zweck:** Die eine Tabelle, gegen die Permission-Katalog (POL-05 / T-6.6), Ratenbegrenzung (T-5.8.3), Datenbankrollen (T-9.5) und Enforcement-Montage geprüft werden.
**Stand der Codebasis:** Bezug ist der letzte mir vorliegende Export (2026-08-07). Der Anhang dieser Anfrage kam leer an — wo ich unten Codezustände beschreibe, können einzelne davon inzwischen behoben sein. Als **[prüfen]** markiert sind Stellen, bei denen das den Vorschlag ändern würde.

**Nachtrag 2026-08-12:** Alle `[prüfen]`-Marker, die **Codezustände** betreffen, sind gegen den aktuellen Baum aufgelöst und im Text an Ort und Stelle beantwortet. Offen bleibt allein der Marker in § 4.2 — er ist eine Produktfrage an Zitadel, kein Codebefund, und steht als P1 in § 11. Die Übersicht steht in § 0.5. Kurzfassung: **neun der Codebefunde sind erledigt**, einer ist teilweise erledigt und verschiebt seine Begründung, sieben stehen unverändert. Die **Struktur des Dokuments ändert sich dadurch nicht** — Listener-Topologie, Endpunktliste, Rollenmodell und Wellenplan bleiben, wie sie sind.

---

## 0. Zustimmung, Widerspruch, Ergänzung

Die Analyse des Entwicklers trägt. Drei Punkte davon sind uneingeschränkt richtig und sollten nicht mehr diskutiert werden:

- **ClientAuth ist eine Listener-Eigenschaft, keine Route-Eigenschaft.** Damit ist die Listener-Zahl technisch determiniert, nicht Geschmackssache.
- **Nach Aufrufer gruppieren, nicht nach Feature.** Der Aufrufer bestimmt die Authentifizierung, die Authentifizierung bestimmt Kette, Ratenlimit und DB-Rolle.
- **Datenbankkonten und Ratenlimits pro Oberfläche jetzt trennen.** Prozesse lassen sich später zusammenlegen; ein gemeinsames DB-Konto nachträglich aufzuteilen heißt, jede Rechtezuweisung neu zu begründen.

**Ein Widerspruch:** drei Listener reichen nicht, es sind **vier**. Der Entwickler fasst SCIM und den Zitadel-Hook zu „IdP-zugewandt" zusammen, hat aber im selben Absatz das Argument geliefert, warum das nicht geht: *„ein SCIM-Schub frisst das Latenzbudget des Hooks."* Das gilt auch bei getrennten Ratenlimits, weil beide dieselbe Accept-Queue, denselben Goroutine-Scheduler und denselben DB-Pool teilen. Dazu kommt ein zweiter, härterer Unterschied: SCIM kommt aus dem öffentlichen Internet, der Hook kommt aus **unserer eigenen Zelle** über WireGuard. Ein Endpunkt, der auf dem Login-Pfad liegt und unauthentifizierte Bytes liest, gehört nicht ins öffentliche Netz, wenn er dort nicht hin muss.

**Eine Ergänzung:** Die Frage „ein Binary oder drei?" ist nachrangig — aber die Naht, die reißen wird, ist nicht die zwischen Hook und Rest, sondern die zwischen **Login-Pfad und allem anderen**. Alles mit 500-ms-Budget in eine Deploy-Einheit, alles ohne in eine andere. Das ist L4 gegen L1–L3.

---

## 0.5 Prüfung gegen den aktuellen Code (2026-08-12)

Zwischen dem Export vom 07.08. und heute liegen die Abschnitte § 5.2–5.8, § 6, § 7, § 9 und die Tickets T-6.4.1, T-9.2, T-9.6 und T-9.7. Was davon dieses Dokument berührt:

### Erledigt — die Begründung im Text ist überholt, die Empfehlung bleibt

| Stelle | Behauptung im Text | Heute |
|---|---|---|
| § 2, L4 | Hook liest den Body **unbegrenzt** vor der HMAC-Prüfung | `MaxWebhookBodyBytes = 64 KiB` und `http.MaxBytesReader` **vor** `io.ReadAll`. Die Netzwerkgrenze bleibt richtig, ist aber nicht mehr die einzige Schutzschicht |
| § 3 | `dpop_middleware.go` prüft „wenn Header da ist", umgehbar | Die Datei existiert nicht mehr. `enforce/dpop_gate.go` folgt dem Token: *„if the verified principal carries a cnf.jkt"* — genau die geforderte Regel |
| § 4.8 | `ExtractPrincipalFromCertificate` setzt pauschal `TrustLevelL3` | Setzt `TrustLevelL1`, mit der Begründung im Code: Kanalbindung ist Authentifizierung, nicht Authenticator-Assurance |
| § 4.9 (1) | Kein `{tenant}` im SCIM-Pfad, globaler E-Mail-Index | `parseSCIMPath` zerlegt `/scim/v2/{tenant}/Users[/{id}]`; der Tenant ist die Quelle für Token, Store und URN |
| § 4.9 (3) | PATCH dekodiert PatchOp in ein `SCIMUser` ⇒ **Datenverlust** | `scim/patch.go` ist ein echter Operationsparser; `PatchUser` lädt, patcht eine entkoppelte Kopie und schreibt zurück. Deny-by-default für unbekannte `op`/Pfade |
| § 4.9 (4) | Authentifizierung optional, Vergleich nicht konstantzeitig | `NewSCIMHandler(provider, tokens TokenVerifier)` verlangt den Verifier, `WithAuthToken` gibt es nicht mehr, Vergleich über `subtle.ConstantTimeCompare` |
| § 6 | Zwei konkurrierende `WriteProblemDetails` plus Inline-Schreiber | Nur noch `shared/errors`. `enforce/interceptor_http.go` und `enforce/pipeline.go` existieren nicht mehr |
| § 9 | `FleetPolicyRegistry` keyt auf `perm.Resource` ⇒ zufälliges Trust-Level | Keyt auf die Permission-ID (`Get(permissionID string)`) |
| D6, § 8 | Migration 009 vergibt Rechte für `identity_app`, **ohne die Rolle zu erzeugen** ⇒ nicht ausführbar | 009 erzeugt die Rolle in einem `DO`-Block. Die Migration läuft — nachgewiesen gegen echtes PostgreSQL 18 |

### Teilweise erledigt — Empfehlung bleibt, Grund verschiebt sich

**D5.** Kritikalität kommt bereits lokal aus der Regel: `critical := req.IsCritical || IsCriticalRule(RuleNameOf(&req))`. Der beschriebene Angriff — durch Weglassen von `is_critical` auf Fail-Open schalten — ist damit zu. **Aber `RuleNameOf(&req)` liest `req.HookType`, also weiterhin aus dem Body.** Wer `post-authentication` behauptet, bekommt weiter Fail-Open für einen Pre-Auth-Hook. Ein Pfad pro Hook-Typ bleibt also richtig — nur ist das Argument jetzt „**HookType** gehört in die Route", nicht mehr „IsCritical schaltet Fail-Closed ab".

### Unverändert offen

| Stelle | Status |
|---|---|
| D1 | `token/exchange.go` hat weiter `signingKey *rsa.PrivateKey` und den Default-Issuer `https://id.the-toob.com`. Die Entscheidung steht aus — und sie hat weiterhin keinen Produktivaufrufer, ist also billig |
| § 4.9 (2) | `GET /Users` mit `filter=` fehlt. Der Handler kennt nur POST ohne ID und GET/PUT/PATCH/DELETE **mit** ID. **Der einzige verbliebene blockierende SCIM-Befund** |
| § 4.4 | `explain.go:89` prüft hartkodiert `Permission: "can_manage"` |
| § 4.5 | `ActivateBreakGlass(ctx, req)` nimmt weiter beide URNs in einem Aufruf entgegen |
| § 4.6 | `approval/governance.go` hält Freeze-Windows im Prozessspeicher |
| § 6 | `IdempotencyMiddleware` reicht bei fehlendem `Idempotency-Key` still durch |
| § 10 (D4) | `cmd/fga-admin` konstruiert `NewTupleRebuilder(nil,nil,nil)`, verwirft ihn mit `_ =` und meldet „REBUILD APPLIED SUCCESSFULLY"; `cmd/cell-admin` meldet ebenfalls Erfolg |

### Was der Export nicht kennen konnte — und was es für § 8 bedeutet

Seit dem 07.08. sind entstanden: `identity/dbtx` mit einem lesefähigen Transaktionsinterface, `identity/outbox`, `audit.PostgresLedgerWriter` als erster echter Schreiber, `sync.PostgresOutboxStore`, und ein Integrationsharness, der die Migrationen gegen echtes PostgreSQL 18 fährt (26 Tests).

Drei Konsequenzen für dieses Dokument:

1. **`identity_sync` aus § 8 existiert bereits — unter dem Namen `identity_outbox_worker`** (Migration 011). Sie liest tenant-übergreifend über zwei Policies (`FOR SELECT`, `FOR UPDATE`, beide `USING (true)`) statt über `BYPASSRLS`, und darf **nicht** einfügen. Der Grund deckt sich mit § 7: der Dispatcher ist Infrastruktur und handelt für keinen Tenant. Bei der Umsetzung von § 8 bitte diese Rolle übernehmen statt eine zweite anzulegen.
2. **Der Befund hinter § 8 ist inzwischen als T-9.5 belegt:** `identity_app` hat Rechte auf **genau einer von zehn Tabellen** (`audit_ledger`). Nicht „die Migration ist nicht ausführbar", sondern „die Rechtelage ist nur für eine Tabelle beschrieben". Das Sechs-Rollen-Modell ist die richtige Antwort darauf.
3. **Fünf Tabellen aus § 8 existieren nicht:** `bff_sessions`, `scim_users`, `scim_groups`, `device_certificates`, `bootstrap_invalidations`. Vorhanden sind `token_families`, `consumed_tokens`, `tenant_members`, `tenant_directory`, `revocation_entries`, `release_approvals`, `impersonation_sessions`, `outbox_events`, `processed_events`, `audit_ledger`, `idempotency_keys`, `audit_chain`. Die Rollenmigration kann also erst nach den Tabellenmigrationen laufen — oder muss ihre Grants in derselben Migration erteilen, in der die Tabelle entsteht. Zweiteres ist sauberer: eine Tabelle ohne Rechtezuweisung ist genau der Zustand, den T-9.5 beschreibt.

---

## 1. Sechs Entscheidungen, die diese Liste erzwingt

Diese kommen zuerst, weil sie die Liste selbst verändern. Vier davon lassen sich heute treffen, ohne eine Zeile zu schreiben.

### D1 — Wer signiert Tokens? → **Ausschließlich Zitadel.**

`token/exchange.go` signiert heute mit einem eigenen `*rsa.PrivateKey` und setzt `iss: "https://id.the-toob.com"` — Zitadels Issuer. Damit existieren zwei Signierer für einen Issuer, und das JWKS unter diesem Issuer enthält unseren Schlüssel nicht. Ein so ausgestelltes Token ist von keinem Verifizierer prüfbar; `token/exchange_test.go` funktioniert nur, weil derselbe Schlüssel über `staticKeyProvider` auch zum Verifizieren übergeben wird.

Zwei Auswege:

| | Konsequenz |
|---|---|
| **(a) Zitadel stellt aus** ✅ | `token/exchange.go` wird Client von Zitadels `/oauth/v2/token` mit `grant_type=token-exchange`. Kein JWKS-Endpunkt bei uns, ein Issuer, ein Vertrauensanker. Der `act`-Claim kommt von Zitadel. |
| (b) Eigener Issuer | Wir brauchen `GET /.well-known/jwks.json`, `GET /.well-known/openid-configuration`, Schlüsselrotation, und **jeder** Verifizierer im Konzern muss zwei Issuer akzeptieren. |

Empfehlung (a). Ergebnis für die Liste: **`/.well-known/*` und JWKS erscheinen nicht.** Das ist der erste Endpunkt, den wir *nicht* bauen, weil die Liste die Frage erzwungen hat.

### D2 — Ist Autorisierung Bibliothek oder Dienst? → **Bibliothek.**

Die Zielarchitektur legt E3 als Go-Bibliothek fest, Enforcement nah am Request. Ein zentraler `POST /api/v1/authz/check` würde daraus einen Policy-Decision-Point mit Netzwerk-Hop pro Request machen — und die 15 %-AuthZ-Latenzbudget-Regel aus ENF-09 sofort verletzen.

Ergebnis: **kein `/authz/check`.** Sehr wohl aber `/authz/explain` — das ist ein menschenzugewandter Debug-Pfad mit einstelliger Aufrufrate, kein Hot Path.

### D3 — Wo lebt „darf dieses Release deployen"? → **Identity besitzt den Datensatz, exponiert einen schmalen internen Read.**

Der Freigabe-Datensatz ist das kryptografische Artefakt (2-of-N-Signaturen, Soak-Fenster) und gehört zum Audit-Ledger. Der Update-Service braucht die Antwort, nicht die Daten.

→ `GET /internal/v1/releases/{id}/deployable` auf L4, aufgerufen vom Update-Service mit Zell-CA-Workload-Zertifikat. Ein Feld Antwort, cachebar bis zum Ende des Soak-Fensters.

### D4 — Plattform-Operationen als HTTP oder CLI? → **CLI, aber über dasselbe Ledger.**

Zelle exportieren, Tenant umziehen, FGA-Store rebuilden, Modellversion promoten: sieben Operationen, die im ersten Halbjahr zusammen vielleicht zwanzigmal laufen. Eine HTTP-Oberfläche dafür ist Angriffsfläche ohne Gegenwert — und genau das Muster, das in § 5 sieben tote Konstrukte erzeugt hat.

Bedingung: die CLIs schreiben ihre kritischen Audit-Einträge in **dasselbe** `audit_ledger` über dieselbe Bibliothek, nicht per `fmt.Println`. Heute melden `cmd/fga-admin` und `cmd/cell-admin` Erfolg, ohne etwas zu tun. **[geprüft 12.08.: unverändert.** `fga-admin` baut `NewTupleRebuilder(nil,nil,nil)`, verwirft ihn mit `_ =` und druckt „REBUILD APPLIED SUCCESSFULLY".**]**

### D5 — Kritikalität eines Hooks kommt aus der **Route**, nicht aus dem Body.

`target/handler.go` liest `req.IsCritical` aus dem JSON-Payload und entscheidet daran zwischen Fail-Closed und Fail-Open. Wer den Payload kontrolliert — eine fehlkonfigurierte Zitadel-Action, ein Replay, eine geänderte Zitadel-Version — schaltet damit Fail-Closed ab.

**[geprüft 12.08.: halb erledigt, Empfehlung bleibt.** Der Handler entscheidet inzwischen lokal: `critical := req.IsCritical || IsCriticalRule(RuleNameOf(&req))` — das Feld aus dem Body kann nur noch **eskalieren**, nicht abschalten. Der beschriebene Angriff ist damit zu. Aber `RuleNameOf` liest `req.HookType`, also weiter aus dem Body: wer `post-authentication` behauptet, bekommt Fail-Open für einen Pre-Auth-Hook. Ein Pfad pro Hook-Typ bleibt richtig — das Argument lautet jetzt „**der Hook-Typ** gehört in die Route", nicht mehr „IsCritical schaltet Fail-Closed ab".**]**

→ Ein Pfad pro Hook-Typ, Kritikalität als serverseitige Konstante der Route:

| Route | Kritisch | Verhalten bei Ausfall |
|---|---|---|
| `/internal/v1/hooks/zitadel/pre-authentication` | ja | Fail-Closed (403) |
| `/internal/v1/hooks/zitadel/pre-token-creation` | ja | Fail-Closed |
| `/internal/v1/hooks/zitadel/pre-user-creation` | ja | Fail-Closed |
| `/internal/v1/hooks/zitadel/post-authentication` | nein | Fail-Open (200) |

Nebeneffekt: Zitadels Action-Konfiguration wird selbstdokumentierend, und pro Route lässt sich ein eigenes Timeout setzen.

### D6 — Eigene DB-Rolle und eigenes Ratenlimit pro Oberfläche. → **Ja, ab Tag 1.**

Vollständiges Rollenmodell in § 8. Der Punkt des Entwicklers ist richtig und die Kosten sind heute null: Migration 009 muss ohnehin neu geschrieben werden, weil `identity_app` dort Rechte bekommt, ohne je angelegt zu werden. **[geprüft 12.08.: die Prämisse stimmt nicht mehr.** 009 erzeugt die Rolle in einem `DO`-Block und läuft gegen echtes PostgreSQL. Der Änderungsgrund bleibt aber bestehen und ist als **T-9.5** belegt: `identity_app` hat Rechte auf genau **einer von zehn** Tabellen. Die Migration muss nicht repariert, sondern erweitert werden.**]** Wenn die Rolle jetzt entsteht, entsteht sie gleich als sechs.

---

## 2. Listener-Topologie

| # | Listener | Bind | TLS | AuthN | Aufrufer | Deploy-Einheit |
|---|---|---|---|---|---|---|
| **L1** | öffentlich / BFF | `127.0.0.1:8443`, hinter Caddy | Caddy terminiert (CF Origin CA) | Session-Cookie + CSRF · DPoP-Bearer | Browser, CLI | A |
| **L2** | Flotte | `0.0.0.0:8444`, direkt | `RequireAndVerifyClientCert`, Pool = Tenant-CAs der Zelle | mTLS, SAN-URI → Principal | Geräte | A |
| **L3** | Partner | `127.0.0.1:8445`, hinter Caddy | Caddy terminiert | Bearer pro Tenant | Kunden-IdP (Okta, Entra) | A |
| **L4** | intern | `10.x:8446`, WireGuard-Interface | eigenes Zertifikat | HMAC (Hook) · mTLS Cell-CA (S2S) | Zitadel, Update-Service, Prometheus | **B** |

Zwei Deploy-Einheiten, nicht drei und nicht eine. Die Trennlinie ist das Latenzbudget: **B** enthält alles, worauf Zitadel synchron wartet, **A** den Rest. Beide starten aus demselben Binary mit unterschiedlichem `--listeners`-Flag — das hält den Schritt von 0 auf 2 klein und die Naht sauber.

### Was daraus folgt

**L2 kann nicht hinter Cloudflare stehen.** Ein Proxy, der TLS terminiert, vernichtet das Client-Zertifikat. Die Flotte braucht einen eigenen DNS-Namen mit deaktiviertem CF-Proxy (grauer Wolke), z. B. `fleet.the-toob.com` → API-Node direkt. Das ist eine Terraform-/Cloudflare-Änderung, die heute nicht existiert.

**L2 und L4 sind beide mTLS, aber mit disjunkten Trust-Pools.** L2 vertraut den Tenant-CAs, L4 der Zell-CA. Ein gemeinsamer Pool würde bedeuten, dass eine kompromittierte Tenant-CA ein „Workload"-Zertifikat ausstellen kann — genau die Isolation, die die 3-Tier-Hierarchie herstellen soll, wäre wieder weg.

**L4 ist nicht öffentlich routbar.** Der Hook-Handler liest heute den Body **unbegrenzt und vollständig, bevor** die HMAC-Signatur geprüft wird (`io.ReadAll` in `target/handler.go`). Solange das so ist, ist die Netzwerkgrenze die eigentliche Schutzschicht. Unabhängig davon gehört ein `http.MaxBytesReader` davor. **[geprüft 12.08.: erledigt** — `MaxWebhookBodyBytes = 64 << 10` und `http.MaxBytesReader` stehen vor dem `io.ReadAll`. Die Schlussfolgerung „nicht öffentlich routbar" bleibt: unauthentifizierte Bytes auf dem Login-Pfad gehören auch begrenzt nicht ins offene Netz.**]**

---

## 3. Enforcement-Ketten pro Oberfläche

`enforce.Stage1Chain` existiert; die Gates existieren. Zu klären ist nur die Zusammensetzung und die Reihenfolge.

### Reihenfolge-Regel

Zwei Ratenlimit-Punkte, nicht einer:

```
[RL-pre: pro IP, ohne Identität]  →  TokenGate  →  KillSwitchGate  →  DPoPGate
   →  TenantGate  →  TrustGate  →  StepUpGate  →  ImpersonationGate
   →  [RL-post: pro Token/Tenant/Permission, Kosten aus Katalog]
   →  Idempotency  →  Handler  →  Stage-2 (FGA)
```

Zwei Abweichungen zur heutigen Testreihenfolge in `enforce/gate_test.go`:

- **KillSwitch direkt nach TokenGate**, nicht als letztes Gate. Ein widerrufener Principal soll nicht erst durch Trust-, Step-up- und Impersonation-Prüfung laufen; der Kill-Switch ist die billigste und dringlichste Ablehnung, und der einzige Grund, warum er nicht Gate 1 sein kann, ist, dass er die URN aus dem Token braucht.
- **DPoPGate ist token-getrieben, nicht routen-getrieben.** Regel: *enthält das Token `cnf.jkt`, ist ein gültiger Proof Pflicht.* Nicht: „prüfe, wenn ein DPoP-Header da ist" — das ist die heutige Bedingung in `middleware/dpop_middleware.go` und durch Weglassen des Headers umgehbar. **[geprüft 12.08.: erledigt.** Die Datei existiert nicht mehr; `enforce/dpop_gate.go` folgt dem Token — *„The decision follows the token, not the request: if the verified principal carries a cnf.jkt"*. Die Reihenfolge-Regel oben bleibt gültig, diese Abweichung ist keine mehr.**]**

### Kette pro Oberfläche

| Oberfläche | Kette |
|---|---|
| **L1 Browser** | `SessionGate` (Cookie, Idle 15 min / Absolut 12 h) → `CSRFGate` (nur unsichere Methoden) → **`Authorization`-Header verwerfen** → Bearer injizieren → Standardkette ab TokenGate |
| **L1 CLI** | Standardkette ab RL-pre; DPoPGate aktiv, sobald `cnf.jkt` im Token |
| **L2 Flotte** | `CertGate` (Kettenprüfung + SAN-URI + Tenant-Scope) → `DeviceKillSwitchGate` → RL-post (pro Tenant) → Handler |
| **L3 SCIM** | `TenantBearerGate` (konstantzeitiger Vergleich, Tenant aus dem Pfad) → RL (Klasse `bulk`, pro Tenant) → Idempotency → Handler, als Tenant-Service-Principal |
| **L4 Hook** | `BodyLimitGate` (64 KiB) → `HMACGate` + Replay-Fenster → Kritikalität aus der Route → Evaluator. **Keine Stage-2** — der Hook *ist* die Policy. |
| **L4 S2S** | `CertGate` (Zell-CA-Pool) → Stage-2 |

Der Punkt „`Authorization`-Header verwerfen" ist kein Detail: `HTTPProxyMiddleware` setzt den Header mit `r.Header.Set`, was zwar überschreibt — aber wenn die BFF-Middleware bei fehlendem Cookie durchreicht (und das muss sie, damit CLI-Requests auf dieselben Routen kommen), muss klar sein, dass ein Browser-Request mit Cookie *und* mitgeschicktem Bearer nicht zwei Identitäten mischt.

---

## 4. Die Endpunktliste

**Spalten:** **M** = verändert Zustand · **T** = tenant-gebunden (⇒ RLS-Scope) · **LP** = Login-Pfad (⇒ Latenzbudget) · **TL** = minimales Trust-Level (`+SU` = Step-up erforderlich) · **W** = Welle.

**Querschnittsregeln, die deshalb nicht in Spalten stehen:**
- Jeder Endpunkt mit **M = ja** verlangt `Idempotency-Key` und antwortet auf Wiederholung aus `idempotency_keys`.
- Jeder Endpunkt mit **T = ja** setzt `set_config('app.tenant_id', …, true)` in der Transaktion.
- Audit-Klasse und Ratenlimit-Kosten kommen aus dem generierten Katalog über die Permission-ID — nicht aus dem Handler.

---

### 4.1 L1 — Browser (Session-Cookie + CSRF)

**Aufrufer:** Konsolen-Frontend. **Ratenlimit-Klasse:** `authn` für `/bff/*`, sonst wie die Zielroute.

| Endpunkt | M | T | LP | Permission | TL | W |
|---|---|---|---|---|---|---|
| `GET /bff/login` | ja¹ | nein | **ja** | — | — | 1 |
| `GET /bff/callback` | ja | abgeleitet | **ja** | — | — | 1 |
| `GET /bff/session` | nein | ja | nein | — | L1 | 1 |
| `POST /bff/logout` | ja | ja | nein | — | L1 | 1 |
| `GET /activate` | nein | nein | ja | — | L2 | 1 |
| `POST /activate` | ja | ja | ja | `identity.device.approve` | L2 | 1 |

¹ setzt State-/PKCE-Cookie, kein DB-Schreibzugriff.

`/activate` ist die Gegenseite des CLI-Device-Flows: der Nutzer gibt den User-Code im Browser ein und bestätigt. `device.ApproveUserCode` / `DenyUserCode` existieren; die Route existiert nicht.

---

### 4.2 L1 — CLI (DPoP-gebundenes Bearer-Token)

**Ratenlimit-Klasse:** `authn`, dimensioniert pro IP **und** pro `client_id`.

| Endpunkt | M | T | LP | Permission | TL | W |
|---|---|---|---|---|---|---|
| `POST /oauth/device_authorization` | ja | nein | ja | — | — | 1 |
| `POST /oauth/token` | ja | ja | **ja** | — | — | 1 |

`/oauth/token` bedient drei Grant-Types: `urn:ietf:params:oauth:grant-type:device_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:token-exchange`.

Unter **D1** ist dieser Endpunkt ein **Proxy**, kein Aussteller: er nimmt den Request entgegen, ergänzt die DPoP-Bindung (`cnf.jkt` aus dem Proof), reicht an Zitadel weiter und gibt dessen Antwort zurück. Der einzige Grund, ihn nicht wegzulassen, ist genau diese Bindung — Zitadel kennt unseren DPoP-Proof nicht.

▸ Falls Zitadel v4 DPoP nativ unterstützt, entfällt auch dieser Endpunkt und die CLI spricht direkt mit Zitadel. **[prüfen]** — das wäre der sauberste Zustand und würde `identity/device` vollständig überflüssig machen.

**[Anmerkung 12.08.]** Dieser Marker bleibt offen: es ist eine Produktfrage an Zitadel, kein Codebefund, und er steht als P1 in § 11. Zur Namensgebung: das Paket heißt seit § 8.3 `identity/deviceflow` — `identity/device` bezeichnete den OAuth-Grant und einen clientseitigen DPoP-Schlüsselspeicher zugleich; letzterer liegt jetzt als `dpop.SecureKeyStore` in `identity/dpop` und wäre von einem Wegfall des Grants **nicht** betroffen.

Alle folgenden `/api/v1/*`-Routen sind **von beiden L1-Aufrufern** erreichbar: der Browser über die BFF-Middleware, die CLI mit eigenem Bearer. Identische Kette ab TokenGate, unterschiedliche Credential-Präsentation.

---

### 4.3 L1 — Tenant- und Mitgliederverwaltung

| Endpunkt | M | T | LP | Permission | TL | W |
|---|---|---|---|---|---|---|
| `POST /api/v1/tenants` | ja | nein² | nein | `admin.tenant.create` | L2 | 1 |
| `GET /api/v1/tenants/{id}` | nein | ja | nein | `admin.tenant.read` | L1 | 1 |
| `PATCH /api/v1/tenants/{id}` | ja | ja | nein | `admin.tenant.update` | L2 | 1 |
| `POST /api/v1/tenants/{id}/upgrade` | ja | ja | nein | `admin.tenant.upgrade` | **L3+SU** | 2 |
| `GET /api/v1/tenants/{id}/members` | nein | ja | nein | `admin.member.list` | L1 | 1 |
| `POST /api/v1/tenants/{id}/members` | ja | ja | nein | `admin.member.invite` | L2 | 1 |
| `DELETE /api/v1/tenants/{id}/members/{userId}` | ja | ja | nein | `admin.member.remove` | L2 | 1 |
| `PUT /api/v1/tenants/{id}/members/{userId}/role` | ja | ja | nein | `admin.role.assign` | **L3+SU** | 1 |

² erzeugt den Scope, existiert also noch nicht. Läuft über die Onboarding-SAGA (`celldir.OnboardingSagaEngine`) mit Quota- und Namensprüfung **vor** dem ersten externen Aufruf.

`PUT .../role` ist der Endpunkt, an dem `policy/rules/elevation.yaml` greift — die einzige Stelle, an der die generierte `ValidateRoleElevation` einen Aufrufer bekommt.

---

### 4.4 L1 — Autorisierungs-Introspektion

| Endpunkt | M | T | LP | Permission | TL | W |
|---|---|---|---|---|---|---|
| `POST /api/v1/authz/explain` | nein | ja | nein | `admin.authz.explain` | L2 | 2 |

~~`GET /api/v1/permissions`~~ — **gestrichen 13.08.** Der Plan hat die Bedingung selbst genannt: „Wenn das Frontend stattdessen zur Buildzeit generiert wird, entfällt der Endpunkt." Genau das ist entschieden. `policygen` schreibt den Katalog als `docs/permissions.json`; die Konsole baut ihn in ihr Bundle ein und rendert Menüs daraus. Zur Laufzeit wandert nur noch die *Identität* des Katalogs mit — der Header `Toob-Catalog-Version` auf jeder Antwort der öffentlichen API (`middleware.CatalogVersion`, Wert aus `spolicy.CatalogVersion`).

Der Grund für diesen Zuschnitt ist die Entkopplung der Deployment-Zyklen: die Konsole soll rendern können, wenn die Identity-API gerade nicht antwortet, und ein Endpunkt, den das Frontend beim Start abrufen *muss*, macht sie genau davon abhängig. Ein Katalog im Bundle kann dafür veralten — der Header ist der Kanal, über den die Konsole das erfährt, und er kommt auch auf der Ablehnung mit, die sie sich *wegen* des veralteten Katalogs einfängt.

`/authz/explain` prüft heute die Selbstautorisierung des Aufrufers hartkodiert gegen die Relation `can_manage`, die im FGA-Modell nur auf zwei Typen existiert. Vor der Montage muss das auf eine typabhängige Verwaltungs-Permission umgestellt werden, sonst schlägt der Endpunkt für `tenant`, `channel` und `device_group` immer fehl. **[geprüft 12.08.: unverändert** — `explain.go:89` setzt weiterhin `Permission: "can_manage"`.**]**

---

### 4.5 L1 — Notfallzugang, Impersonation, Widerruf

Alle Schreiboperationen hier sind `audit: critical` ⇒ synchroner Ledger-Schreibvorgang, Ablehnung der Transaktion bei Audit-Fehler.

| Endpunkt | M | T | LP | Permission | TL | W |
|---|---|---|---|---|---|---|
| `POST /api/v1/admin/break-glass` | ja | ja | nein | `admin.breakglass.request` | **L3+SU** | 2 |
| `POST /api/v1/admin/break-glass/{id}/approve` | ja | ja | nein | `admin.breakglass.approve` | **L3+SU** | 2 |
| `GET /api/v1/admin/break-glass` | nein | ja | nein | `admin.breakglass.list` | L2 | 2 |
| `DELETE /api/v1/admin/break-glass/{id}` | ja | ja | nein | `admin.breakglass.revoke` | **L3** | 2 |
| `POST /api/v1/admin/impersonation` | ja | ja | nein | `admin.impersonation.start` | **L3+SU** | 2 |
| `DELETE /api/v1/admin/impersonation/{id}` | ja | ja | nein | `admin.impersonation.end` | L2 | 2 |
| `GET /api/v1/tenants/{id}/impersonation` | nein | ja | nein | `admin.impersonation.list` | **L1** | 2 |
| `POST /api/v1/admin/revocations` | ja | ja | nein | `admin.revocation.create` | **L3+SU** | 1 |
| `DELETE /api/v1/admin/revocations/{key}` | ja | ja | nein | `admin.revocation.delete` | **L3** | 1 |
| `GET /api/v1/admin/revocations` | nein | ja | nein | `admin.revocation.list` | L2 | 1 |
| `POST /api/v1/tenants/{id}/devices/{deviceId}/revoke` | ja | ja | nein | `fleet.device.revoke` | **L3** | 2 |

**`GET /api/v1/tenants/{id}/impersonation` steht bewusst auf L1 und ist die einzige Zeile in dieser Tabelle mit niedrigem Trust-Level.** Sie erfüllt die Zusage aus IDP-060, dass Support-Zugriff *für den Kunden sichtbar* ist. Ohne diesen Endpunkt ist die Zusage nicht eingelöst — und es gibt heute nichts, was sie einlöst. Jedes Mitglied des Tenants muss sie lesen können, nicht nur Admins.

Zwei Endpunkte für Break-Glass (Request + Approve) statt einem, weil Dual Control zwei Requests von zwei Personen bedeutet. Ein einzelner Endpunkt, der beide URNs im Body entgegennimmt, ist kein Vier-Augen-Prinzip — genau das ist die heutige `ActivateBreakGlass`-Signatur.

---

### 4.6 L1 — Release-Governance

| Endpunkt | M | T | LP | Permission | TL | W |
|---|---|---|---|---|---|---|
| `POST /api/v1/releases/{id}/approvals` | ja | ja | nein | `release.approval.grant` | **L3+SU** | 2 |
| `DELETE /api/v1/releases/{id}/approvals` | ja | ja | nein | `release.approval.cancel` | **L3** | 2 |
| `GET /api/v1/releases/{id}/approvals` | nein | ja | nein | `release.approval.read` | L1 | 2 |
| `POST /api/v1/tenants/{id}/freeze-windows` | ja | ja | nein | `release.freeze.create` | **L3** | 3 |
| `GET /api/v1/tenants/{id}/freeze-windows` | nein | ja | nein | `release.freeze.list` | L1 | 3 |
| `DELETE /api/v1/tenants/{id}/freeze-windows/{id}` | ja | ja | nein | `release.freeze.delete` | **L3** | 3 |

`POST .../approvals` ist **ein** Endpunkt, nicht zwei: der Server entscheidet aus dem gespeicherten Zustand, ob es die erste oder die zweite Freigabe ist, und lehnt dieselbe Person zweimal ab. Das ist die einzige Variante, die gegen Race Conditions hält.

Freigaben tragen `requires_signature: true` im Katalog: der Request führt eine Detached Signature über `(release_id, artifact_digest, target_channel)` mit, nicht bloß ein Bearer-Token. Ohne diese Eigenschaft ist die Freigabe ein DB-Flag und kein kryptografisches Artefakt.

Welle 3 für Freeze-Windows, weil `approval/governance.go` sie heute nur im Prozessspeicher hält und nichts sie aufruft. Erst Persistenz, dann Endpunkt.

---

### 4.7 L1 — Audit-Zugriff des Kunden

| Endpunkt | M | T | LP | Permission | TL | W |
|---|---|---|---|---|---|---|
| `GET /api/v1/tenants/{id}/audit` | nein | ja | nein | `admin.audit.read` | L2 | 2 |
| `GET /api/v1/tenants/{id}/audit/checkpoints` | nein | ja | nein | `admin.audit.read` | L2 | 2 |

Cursor-Pagination über `(tenant_id, sequence_number)` — der vorhandene Index trägt das direkt. Die Checkpoints sind das, was der Kunde herunterlädt, um die Kette **offline** gegen `cmd/audit-verify` zu prüfen; sie machen die Zusage „Integrität ohne Vertrauen in uns" erst nachvollziehbar.

---

### 4.8 L2 — Flotte (mTLS)

**Aufrufer:** Gerät. **Trust:** Zertifikat, nicht Trust-Level — siehe Anmerkung unten. **Ratenlimit:** pro Tenant, Klasse `write`.

| Endpunkt | M | T | LP | Permission | W |
|---|---|---|---|---|---|
| `POST /fleet/v1/onboard` | ja | ja | nein | `fleet.device.onboard` | 2 |
| `POST /fleet/v1/certificates/rotate` | ja | ja | nein | `fleet.device.rotate` | 2 |

Zwei Endpunkte, mehr nicht. Das ist Absicht:

- **Kein Update-Manifest, kein Telemetrie-Ingest** — das ist der Update-Service. Geräte sprechen ihn mit demselben Zertifikat direkt an.
- **Kein Token-Austausch.** Unter E4 *ist* mTLS die Geräteidentität; ein Bearer-Token dazwischen wäre eine zweite, schwächere Identität für denselben Akteur.
- **Kein `/whoami`.** Ein widerrufenes Gerät erfährt das dadurch, dass die Verbindung abgelehnt wird.
- **Kein Workload-Zertifikatsendpunkt.** `pki/workload.go` dupliziert, was Vault über `pki/issue/nomad-cluster` bereits tut — inklusive Vault-Agent-Rotation in der Nomad-Rolle. Die Duplikation gehört gelöscht, nicht exponiert.

**Zur Trust-Level-Spalte:** Sie fehlt hier bewusst. `principal.ExtractPrincipalFromCertificate` setzt heute pauschal `TrustLevelL3` — damit erfüllt jedes Geräte-Zertifikat jedes L3-Gate, auch eines, das für menschliche Dual-Passkey-Freigaben gedacht ist. Kanalbindung und Authenticator-Assurance sind zwei unvergleichbare Skalen. Gates auf L1-Routen müssen zusätzlich auf `ActorType` prüfen, oder Zertifikate bekommen eine eigene Dimension. **[geprüft 12.08.: erledigt.** Der Extraktor setzt `TrustLevelL1` und begründet es im Code mit genau diesem Argument; Gates ab L2 prüfen zusätzlich `ActorType.HasAuthenticatorAssurance`. Die Spalte bleibt trotzdem zu Recht leer — die Geräteidentität ist das Zertifikat, nicht eine Stufe.**]**

---

### 4.9 L3 — Partner / Kunden-IdP (SCIM 2.0)

**Aufrufer:** Okta, Entra ID, Workday. **AuthN:** Bearer pro Tenant. **Ratenlimit:** Klasse `bulk`, ausschließlich pro Tenant. **Alle Routen T = ja, LP = nein.**

| Endpunkt | M | Permission | W |
|---|---|---|---|
| `GET /scim/v2/{tenant}/ServiceProviderConfig` | nein | — | 1 |
| `GET /scim/v2/{tenant}/ResourceTypes` | nein | — | 1 |
| `GET /scim/v2/{tenant}/Schemas` | nein | — | 1 |
| `POST /scim/v2/{tenant}/Users` | ja | `identity.scim.provision` | 1 |
| `GET /scim/v2/{tenant}/Users` | nein | `identity.scim.read` | 1 |
| `GET /scim/v2/{tenant}/Users/{id}` | nein | `identity.scim.read` | 1 |
| `PUT /scim/v2/{tenant}/Users/{id}` | ja | `identity.scim.provision` | 1 |
| `PATCH /scim/v2/{tenant}/Users/{id}` | ja | `identity.scim.provision` | 1 |
| `DELETE /scim/v2/{tenant}/Users/{id}` | ja | `identity.scim.deprovision` | 1 |
| `POST /scim/v2/{tenant}/Groups` | ja | `identity.scim.provision` | 2 |
| `GET /scim/v2/{tenant}/Groups` | nein | `identity.scim.read` | 2 |
| `GET /scim/v2/{tenant}/Groups/{id}` | nein | `identity.scim.read` | 2 |
| `PATCH /scim/v2/{tenant}/Groups/{id}` | ja | `identity.scim.provision` | 2 |
| `DELETE /scim/v2/{tenant}/Groups/{id}` | ja | `identity.scim.deprovision` | 2 |

Vier Abweichungen zum heutigen `scim.SCIMHandler`, drei davon blockierend:

**(1) `{tenant}` im Pfad ist Pflicht.** Ohne Tenant-Segment ist `MemoryUserStore.byEmail` ein globaler Index — **zwei Kunden können keine Nutzer mit gleicher E-Mail haben**, und der Account-Takeover-Guard vergleicht `externalId` über Tenantgrenzen hinweg. Bei zwei Kunden mit demselben Auftragnehmer ist das ein sofortiger Fehler.

**(2) `GET /Users` mit `filter=` ist nicht optional.** Okta und Entra rufen vor jedem `POST` ein `filter=userName eq "…"` auf, um zu entscheiden, ob sie anlegen oder aktualisieren. Ohne diese Route legt Okta bei jedem Sync-Lauf neu an oder bricht die Integration ab. Mindestumfang: `eq` auf `userName` und `externalId`, plus `startIndex`/`count`.

**[geprüft 12.08.]** Von den vier Abweichungen sind **drei erledigt** — (1) der Tenant steht im Pfad (`parseSCIMPath`), (3) PATCH ist ein echter Operationsparser (`scim/patch.go`), (4) der Konstruktor verlangt den Token-Verifier und vergleicht konstantzeitig. **Offen und weiterhin blockierend ist allein (2):** es gibt keinen `GET /Users`-Zweig ohne ID, also weder Liste noch Filter. Der Rest dieses Abschnitts ist als Begründung erhalten, beschreibt aber nicht mehr den heutigen Code.

**(3) PATCH ist ein PatchOp-Dokument, kein Teilobjekt.** Entra deaktiviert ausschließlich per

```json
{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
 "Operations":[{"op":"replace","path":"active","value":false}]}
```

Der heutige Handler dekodiert das in ein `SCIMUser` — Ergebnis ist ein Nullwert mit `Active: false`, der anschließend über `UpdateUser` den kompletten Datensatz überschreibt. **E-Mail, `userName` und `externalId` des Nutzers werden dabei gelöscht.** Das ist Datenverlust auf genau dem Pfad, der am häufigsten läuft, und er wird erst beim nächsten Login sichtbar. Der Test prüft nur POST und GET.

**(4) Authentifizierung ist heute optional.** `NewSCIMHandler(provider)` ohne `WithAuthToken` ergibt einen unauthentifizierten Handler, und genau so bauen ihn der Handler-Test und der Contract-Test. Der Vergleich ist zudem nicht laufzeitkonstant. Der Konstruktor muss das Token verlangen; `WithAuthToken` als optionaler Setter gehört gelöscht.

Jede SCIM-Mutation schreibt zusätzlich in `outbox_events` — damit erreichen Gruppenänderungen die FGA-Tupel über `identity-sync` statt synchron im Request. Bei einem Sync-Schub von 5 000 Nutzern ist das der Unterschied zwischen 5 000 blockierenden FGA-Writes und einem Batch.

---

### 4.10 L4 — Intern

**Nicht öffentlich routbar.** Bind ausschließlich auf das WireGuard-Interface.

| Endpunkt | Aufrufer | AuthN | M | T | LP | W |
|---|---|---|---|---|---|---|
| `POST /internal/v1/hooks/zitadel/pre-authentication` | Zitadel | HMAC | nein³ | ja | **JA (500 ms)** | 1 |
| `POST /internal/v1/hooks/zitadel/pre-token-creation` | Zitadel | HMAC | nein | ja | **JA (500 ms)** | 1 |
| `POST /internal/v1/hooks/zitadel/pre-user-creation` | Zitadel | HMAC | nein | ja | **JA (500 ms)** | 1 |
| `POST /internal/v1/hooks/zitadel/post-authentication` | Zitadel | HMAC | ja³ | ja | ja (Fail-Open) | 1 |
| `GET /internal/v1/tenant-directory/{key}` | Identity-Instanzen | mTLS Cell-CA | nein | nein⁴ | **JA** | 1 |
| `GET /internal/v1/releases/{id}/deployable` | Update-Service | mTLS Cell-CA | nein | ja | nein | 2 |
| `GET /healthz` | Nomad | — | nein | nein | nein | 1 |
| `GET /readyz` | Nomad | — | nein | nein | nein | 1 |
| `GET /metrics` | Prometheus | mTLS Cell-CA | nein | nein | nein | 1 |

³ Der einzige Schreibzugriff der Hook-Rolle ist `INSERT` in `audit_ledger` — etwa für die Break-Glass-Anmeldung, die `EvaluateBreakGlassAudit` heute nur als `slog.Error` protokolliert.
⁴ Das Tenant-Directory ist per Definition PII-frei und selbst nicht tenant-gebunden; es ist die Auflösungsschicht *vor* dem Scope.

**Das 500-ms-Budget hat eine Konsequenz, die leicht übersehen wird.** `pre_authentication` braucht die Policy des Tenants, also eine Directory-Auflösung. Wenn diese Auflösung ein HTTP-Aufruf gegen `/internal/v1/tenant-directory` ist, steckt ein Netzwerk-Roundtrip *innerhalb* des Budgets. Regel: **auf dem Hook-Pfad ist die Directory-Auflösung Cache-only.** Cache-Miss bei einem kritischen Hook ⇒ Fail-Closed, nicht Fetch. Der Cache wird vom Hintergrund-Sync warm gehalten.

**Pfadänderung:** `celldir.Client` ruft heute `GET {base}/api/v1/celldir/resolve?key=…`. Das ist der einzige interne Konsument; die Umstellung auf `/internal/v1/tenant-directory/{key}` sind zwei Zeilen und trennt intern von öffentlich sauber am Präfix.

**`/readyz` prüft vier Dinge und nicht drei:** DB erreichbar, FGA erreichbar, JWKS jünger als *n*, **und `schema_migrations.version` gleich der einkompilierten Erwartung**. Ohne den vierten Punkt nimmt eine Instanz mit veralteter Migration Traffic an.

---

## 5. Was bewusst kein Endpunkt ist

Der Gegenteil-Fall zur Regel „nenne nichts, das niemand ruft": festhalten, was wir *nicht* bauen, damit es niemand später „der Vollständigkeit halber" ergänzt.

| Nicht gebaut | Warum | Entscheidung |
|---|---|---|
| `POST /api/v1/authz/check` | Autorisierung ist Bibliothek; ein zentraler PDP verletzt das 15 %-Latenzbudget | D2 |
| `GET /.well-known/jwks.json`, `/.well-known/openid-configuration` | Zitadel ist der einzige Issuer | D1 |
| `POST /oauth/introspect`, `/oauth/revoke` | Zitadel | D1 |
| `POST /workload/v1/certificates` | Vault PKI tut das bereits, inklusive Rotation | — |
| Zell-Export/-Import, Tenant-Umzug, FGA-Rebuild, Modell-Promotion | CLI, ~20 Aufrufe im ersten Halbjahr | D4 |
| Audit-Kettenverifikation als Endpunkt | offline, `cmd/audit-verify`, bewusst ohne DB | — |
| `GET /api/v1/users/me` | `/bff/session` liefert das bereits | — |
| Update-Manifest, Telemetrie-Ingest | Update-Service | — |
| Registrierung, Passwort-Reset | per Design abgeschaltet (Einladung-only, passwortlos); Caddy blockt sie bereits | — |
| `GET /fleet/v1/whoami` | Ein widerrufenes Gerät erfährt es durch Ablehnung | — |

---

## 6. Querschnittsregeln

**Versionierung.** `/api/v1/`, `/fleet/v1/`, `/internal/v1/`, SCIM nach RFC (`/scim/v2/`). Die interne Version ist unabhängig von der öffentlichen; das erlaubt, L4 zu ändern, ohne Kunden zu betreffen.

**Fehlerformat.** RFC 9457 Problem Details überall außer SCIM (dort RFC 7644 `SCIMError`). **Ein** Schreiber: `serrors.WriteProblemDetails`. Die beiden Konkurrenten — `middleware.WriteProblemDetails` mit abweichender Signatur und der Inline-Schreiber in `enforce/interceptor_http.go`, der das `Code`-Feld gar nicht setzt — entfallen mit der Montage.

**Step-up.** Fehlschlag ⇒ HTTP 401 mit `WWW-Authenticate: DPoP error="insufficient_user_authentication", acr_values="urn:toob:mfa:webauthn", max_age=<n>` (RFC 9470) *und* Problem-Details-Body. Beides, nicht eines von beidem.

**Idempotenz.** Alle Endpunkte mit **M = ja**. Schlüssel ist `(tenant_id, key)`; die Tabelle existiert (Migration 010). Fehlt der Header, antwortet der Endpunkt mit 400 — nicht mit stillem Durchreichen wie heute in `IdempotencyMiddleware`.

**Ratenlimit-Klassen.** Der generierte `RateLimitCostCatalog` liefert die Kosten, die Klasse liefert die Dimension:

| Klasse | Dimensionen | Beispiel |
|---|---|---|
| `authn` | IP + client_id | `/oauth/token`, `/bff/callback` |
| `read` | Token | alle GETs |
| `write` | Token + Tenant | alle Mutationen |
| `bulk` | Tenant | SCIM |
| `hook` | Nebenläufigkeitsgrenze statt Rate | L4-Hooks |

Schlüsselschema: `ratelimit:{klasse}:{dimension}:{subjekt}` — die Permission geht über die Kosten ein, nicht über den Schlüssel. Damit teilt sich ein teurer Rollout nicht mehr denselben Eimer mit einem billigen List-Call, ohne dass die Schlüsselzahl explodiert. Das ist T-5.8.3.

**Pagination.** Cursor-basiert (`?cursor=&limit=`) auf allen Listen. Ausnahme SCIM: `startIndex`/`count`, weil RFC 7644 es so verlangt und Okta nichts anderes spricht.

**Korrelation.** `X-Correlation-ID` wird durchgereicht oder erzeugt; `authz.ContextWithCorrelationID` existiert bereits und muss von der äußersten Middleware gefüllt werden, nicht erst in `authz`.

---

## 7. Zuordnung Endpunkt → Enforcement in einem Satz pro Oberfläche

| Oberfläche | Wer bin ich? | Welcher Tenant? | Was darf ich? |
|---|---|---|---|
| L1 Browser | Session-Cookie → Token | Pfadparameter, gegen `p.OrgID` geprüft | Stage-2 FGA gegen Tenant-Store |
| L1 CLI | DPoP-gebundenes Bearer | Pfadparameter, gegen `p.OrgID` geprüft | Stage-2 FGA gegen Tenant-Store |
| L2 Flotte | SAN-URI des Client-Zertifikats | aus dem URN, gegen Tenant-CA geprüft | Stage-2 FGA, Subjekt `device:` |
| L3 SCIM | Bearer → Tenant-Service-Principal | **Pfadsegment** = einzige Quelle | fest: nur `identity.scim.*` |
| L4 Hook | HMAC → „Zitadel dieser Zelle" | aus dem Payload, nicht vertrauenswürdig ⇒ nur Policy-Auswertung, keine Datenmutation | keine Stage-2 |
| L4 S2S | Zell-CA-Zertifikat | Pfadparameter | Stage-2 FGA, Subjekt `workload:` |

Die Zeile für L4 Hook ist der Grund, warum die Hook-Rolle read-only sein muss: der Tenant kommt aus einem Payload, den wir nur per HMAC als „von Zitadel" belegen können — nicht als „inhaltlich korrekt". Ein Hook, der auf Basis dieses Tenants schreiben dürfte, wäre eine tenant-übergreifende Schreibprimitive.

---

## 8. Datenbank-Rollenmodell (T-9.5)

Sechs Rollen, abgeleitet aus den Oberflächen. Alle unterliegen RLS über `set_config('app.tenant_id', …, true)`; alle haben `REVOKE UPDATE, DELETE ON audit_ledger`.

| Rolle | Listener | Schreibt | Liest | Explizit **nicht** |
|---|---|---|---|---|
| `identity_bff` | L1 | `token_families`, `consumed_tokens`, `bff_sessions`, `audit_ledger`(I) | `revocation_entries` | Tenant-Fachtabellen |
| `identity_api` | L1 | Tenant-Fachtabellen, `idempotency_keys`, `outbox_events`(I), `audit_ledger`(I) | `tenant_directory` | `token_families`, `consumed_tokens` |
| `identity_fleet` | L2 | `device_certificates`, `bootstrap_invalidations`, `audit_ledger`(I) | `revocation_entries` | alles Nutzerbezogene |
| `identity_scim` | L3 | `scim_users`, `scim_groups`, `outbox_events`(I), `revocation_entries`(I), `audit_ledger`(I) | — | `token_families`, `release_approvals` |
| `identity_hook` | L4 | **nur** `audit_ledger`(I) | `tenant_directory`, `tenant_members` | alles andere |
| `identity_sync` | Daemon | `outbox_events`(U), `processed_events` | alles Lesende | `audit_ledger`(I) direkt |

(I) = nur INSERT · (U) = nur UPDATE

Zwei Eigenschaften, die diese Aufteilung erkauft und die man nachträglich nicht mehr bekommt:

- **Ein kompromittierter Hook-Endpunkt kann nichts verändern.** Das ist genau der Endpunkt, der auf dem Login-Pfad liegt und unauthentifizierte Bytes liest.
- **Ein kompromittierter SCIM-Endpunkt kann keine Sessions lesen.** Das ist genau der Endpunkt mit einem langlebigen, beim Kunden gespeicherten Bearer-Token.

Migration 009 legt heute Rechte für `identity_app` an, ohne die Rolle je zu erzeugen — die Migration ist damit nicht ausführbar. [prüfen] Sie muss ohnehin neu geschrieben werden; die richtige Fassung erzeugt sechs Rollen statt einer.

**[geprüft 12.08.]** Drei Korrekturen an diesem Abschnitt:

- **Die Migration ist ausführbar.** 009 erzeugt `identity_app` in einem `DO`-Block. Der Befund ist ein anderer und heißt **T-9.5**: die Rolle bekommt Rechte auf `audit_ledger` — und auf keiner der neun übrigen Tabellen. Ein Dienst, der sich als sie verbindet, bekäme dort „permission denied". Aufgefallen ist es, weil die RLS-Prüfung als App-Rolle nur auf `audit_ledger` möglich war.
- **`identity_sync` existiert schon**, als `identity_outbox_worker` (Migration 011). Zwei Policies statt `BYPASSRLS` — aus demselben Grund, den § 7 für die Hook-Rolle nennt: der Dispatcher handelt für keinen Tenant. `INSERT` hat sie nicht. Bitte übernehmen, nicht neu anlegen.
- **Fünf der genannten Tabellen gibt es nicht:** `bff_sessions`, `scim_users`, `scim_groups`, `device_certificates`, `bootstrap_invalidations`. Die Rollenmigration kann ihre Grants also nicht in einem Zug erteilen. Sauberer als eine Sammelmigration am Ende: **jede Tabellenmigration erteilt die Rechte ihrer eigenen Tabelle mit.** Eine Tabelle ohne Rechtezuweisung ist genau der Zustand, den T-9.5 beschreibt — und der entsteht dann gar nicht erst.

---

## 9. Der Konformitätstest (T-6.6 / O6)

Diese Liste ist erst dann eine Zusage, wenn sie in CI durchgesetzt wird. Ein Tabellentest, drei Richtungen:

1. **Jede Permission im Katalog hat mindestens eine Route.** Sonst: entweder tote Permission oder vergessener Endpunkt.
2. **Jede Route mit `M = ja` oder `T = ja` hat genau eine Permission.** Sonst: unautorisierte Mutation.
3. **Das Trust-Level der Route stimmt mit `min_trust_level` im Katalog überein.** Der Handler darf es nicht überschreiben.

Dazu zwei Invarianten, die derselbe Test billig mitnimmt:

- Jede Route mit `M = ja` liegt hinter `IdempotencyMiddleware`.
- Jede Route mit `T = ja` läuft in einer Transaktion mit gesetztem `app.tenant_id`.

Das ist auch die Stelle, an der die heutige `NewFleetPolicyRegistry` auffliegen würde: sie keyt auf `perm.Resource` statt auf die Permission-ID, überschreibt damit bei geteiltem Ressourcentyp, und welche Policy gewinnt, hängt an der randomisierten Map-Iteration. Derselbe Binary erzwingt bei jedem Prozessstart ein anderes Trust-Level. **[geprüft 12.08.: erledigt** — die Registry keyt auf die Permission-ID (`Get(permissionID string)`).**]** Der Konformitätstest macht das zu einem roten Build statt zu einem Betriebsrätsel.

**Vierte Richtung, die inzwischen billig ist:** seit § 9.2 gibt es einen Harness, der die Migrationen gegen echtes PostgreSQL fährt. Die beiden Invarianten unten (`Idempotency`, `app.tenant_id`) lassen sich dort **ausführen** statt behaupten — dieselbe Umstellung, die die RLS-Textprüfungen ersetzt hat.

---

## 10. Montagereihenfolge

**Welle 1 — der Durchstich (Gate B).** BFF-Session-Lifecycle, `/oauth/*`, `/activate`, Tenant- und Mitgliederverwaltung, Widerruf, SCIM Users inkl. Discovery und Filter, die vier Zitadel-Hooks, Tenant-Directory, Health. Ziel ist nicht Vollständigkeit, sondern: **eine Permission durchgängig** vom generierten Katalog über Stage-1 mit DPoP, Stage-2 gegen den Tenant-Store, eine RLS-Query auf einer Migration, die wirklich läuft, bis zu einem Eintrag im echten Ledger.

Der schmalste Kandidat dafür ist `GET /api/v1/tenants/{id}/members` mit `admin.member.list` — Read, tenant-gebunden, kein Step-up, kein Idempotenzschlüssel, aber alle sechs Gates und beide Stages.

**Welle 2 — Substanz.** Break-Glass, Impersonation inklusive der kundenseitigen Sichtbarkeit, Release-Freigaben, Audit-Zugriff, SCIM Groups, Flotten-Onboarding und -Rotation, `/authz/explain`, `/releases/{id}/deployable`.

**Welle 3 — was noch keinen Aufrufer hat.** Freeze-Windows, Profil-Upgrade P1→P2, `/permissions` — jeweils erst, wenn ein konkreter Konsument existiert.

---

## 11. Offene Punkte

| # | Frage | Blockiert |
|---|---|---|
| P1 | Unterstützt Zitadel v4 DPoP nativ? | Ob `/oauth/token` und `identity/device` überhaupt existieren müssen |
| P2 | Unterstützt Zitadel v4 RFC 8693 mit `act`-Claim? | D1 (a) |
| P3 | Sind die Ratenlimits pro Kunden-IdP vertraglich zugesagt? | Dimensionierung der `bulk`-Klasse |
| P4 | Welche Okta-/Entra-Konnektoren sind zugesagt? | Umfang von SCIM-Filter und PatchOp |
| P5 | Existiert der DNS-Name für L2 mit deaktiviertem CF-Proxy? | Erreichbarkeit der Flotte |
| P6 | Wer betreibt L4 — dieselbe Nomad-Gruppe wie L1–L3 oder eine eigene? | Deploy-Einheit B |

---

## 12. Antwort auf die gestellte Frage, im gewünschten Format

```
Oberfläche      Endpunkt                                         Aufrufer   verändert?  Tenant?  Login-Pfad?
öffentlich/BFF  GET    /bff/login                                Browser    Cookie      nein     ja
öffentlich/BFF  GET    /bff/callback                             Browser    ja          abgel.   ja
öffentlich/BFF  GET    /bff/session                              Browser    nein        ja       nein
öffentlich/BFF  POST   /bff/logout                               Browser    ja          ja       nein
öffentlich/BFF  GET    /activate                                 Browser    nein        nein     ja
öffentlich/BFF  POST   /activate                                 Browser    ja          ja       ja
öffentlich/CLI  POST   /oauth/device_authorization               CLI        ja          nein     ja
öffentlich/CLI  POST   /oauth/token                              CLI        ja          ja       JA
öffentlich      POST   /api/v1/tenants                           Browser    ja          nein     nein
öffentlich      GET    /api/v1/tenants/{id}                      beide      nein        ja       nein
öffentlich      PATCH  /api/v1/tenants/{id}                      beide      ja          ja       nein
öffentlich      POST   /api/v1/tenants/{id}/upgrade              Browser    ja          ja       nein
öffentlich      GET    /api/v1/tenants/{id}/members              beide      nein        ja       nein
öffentlich      POST   /api/v1/tenants/{id}/members              beide      ja          ja       nein
öffentlich      DELETE /api/v1/tenants/{id}/members/{uid}        beide      ja          ja       nein
öffentlich      PUT    /api/v1/tenants/{id}/members/{uid}/role   Browser    ja          ja       nein
öffentlich      POST   /api/v1/authz/explain                     beide      nein        ja       nein
öffentlich      POST   /api/v1/admin/break-glass                 Browser    ja          ja       nein
öffentlich      POST   /api/v1/admin/break-glass/{id}/approve    Browser    ja          ja       nein
öffentlich      GET    /api/v1/admin/break-glass                 beide      nein        ja       nein
öffentlich      DELETE /api/v1/admin/break-glass/{id}            Browser    ja          ja       nein
öffentlich      POST   /api/v1/admin/impersonation               Browser    ja          ja       nein
öffentlich      DELETE /api/v1/admin/impersonation/{id}          Browser    ja          ja       nein
öffentlich      GET    /api/v1/tenants/{id}/impersonation        Browser    nein        ja       nein
öffentlich      POST   /api/v1/admin/revocations                 beide      ja          ja       nein
öffentlich      DELETE /api/v1/admin/revocations/{key}           beide      ja          ja       nein
öffentlich      GET    /api/v1/admin/revocations                 beide      nein        ja       nein
öffentlich      POST   /api/v1/tenants/{id}/devices/{d}/revoke   beide      ja          ja       nein
öffentlich      POST   /api/v1/releases/{id}/approvals           Browser    ja          ja       nein
öffentlich      DELETE /api/v1/releases/{id}/approvals           Browser    ja          ja       nein
öffentlich      GET    /api/v1/releases/{id}/approvals           beide      nein        ja       nein
öffentlich      POST   /api/v1/tenants/{id}/freeze-windows       Browser    ja          ja       nein
öffentlich      GET    /api/v1/tenants/{id}/freeze-windows       beide      nein        ja       nein
öffentlich      DELETE /api/v1/tenants/{id}/freeze-windows/{f}   Browser    ja          ja       nein
öffentlich      GET    /api/v1/tenants/{id}/audit                beide      nein        ja       nein
öffentlich      GET    /api/v1/tenants/{id}/audit/checkpoints    beide      nein        ja       nein
mTLS-Flotte     POST   /fleet/v1/onboard                         Gerät      ja          ja       nein
mTLS-Flotte     POST   /fleet/v1/certificates/rotate             Gerät      ja          ja       nein
Partner/SCIM    GET    /scim/v2/{t}/ServiceProviderConfig        Okta       nein        ja       nein
Partner/SCIM    GET    /scim/v2/{t}/ResourceTypes                Okta       nein        ja       nein
Partner/SCIM    GET    /scim/v2/{t}/Schemas                      Okta       nein        ja       nein
Partner/SCIM    POST   /scim/v2/{t}/Users                        Okta       ja          ja       nein
Partner/SCIM    GET    /scim/v2/{t}/Users                        Okta       nein        ja       nein
Partner/SCIM    GET    /scim/v2/{t}/Users/{id}                   Okta       nein        ja       nein
Partner/SCIM    PUT    /scim/v2/{t}/Users/{id}                   Okta       ja          ja       nein
Partner/SCIM    PATCH  /scim/v2/{t}/Users/{id}                   Okta       ja          ja       nein
Partner/SCIM    DELETE /scim/v2/{t}/Users/{id}                   Okta       ja          ja       nein
Partner/SCIM    POST   /scim/v2/{t}/Groups                       Okta       ja          ja       nein
Partner/SCIM    GET    /scim/v2/{t}/Groups                       Okta       nein        ja       nein
Partner/SCIM    GET    /scim/v2/{t}/Groups/{id}                  Okta       nein        ja       nein
Partner/SCIM    PATCH  /scim/v2/{t}/Groups/{id}                  Okta       ja          ja       nein
Partner/SCIM    DELETE /scim/v2/{t}/Groups/{id}                  Okta       ja          ja       nein
intern          POST   /internal/v1/hooks/zitadel/pre-auth       Zitadel    nein        ja       JA
intern          POST   /internal/v1/hooks/zitadel/pre-token      Zitadel    nein        ja       JA
intern          POST   /internal/v1/hooks/zitadel/pre-user       Zitadel    nein        ja       JA
intern          POST   /internal/v1/hooks/zitadel/post-auth      Zitadel    ja(Audit)   ja       ja
intern          GET    /internal/v1/tenant-directory/{key}       Identity   nein        nein     JA
intern          GET    /internal/v1/releases/{id}/deployable     Update     nein        ja       nein
intern          GET    /healthz                                  Nomad      nein        nein     nein
intern          GET    /readyz                                   Nomad      nein        nein     nein
intern          GET    /metrics                                  Prometheus nein        nein     nein
```

**62 Endpunkte. 21 in Welle 1.**