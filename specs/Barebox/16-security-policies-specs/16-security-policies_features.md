> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/security-policies.rst`

# 16. Barebox Security Policies (SConfig)

Dieses Dokument spezifiziert das dynamische "Security Policy" Framework von Barebox. Es löst das Problem, dass man eigentlich nicht für jeden Einsatzzweck (z.B. Entwicklung im Labor vs. Auslieferung zum Kunden) einen komplett eigenen Bootloader kompilieren möchte, sondern Sicherheitsregeln erst *zur Laufzeit* (beim Booten) entscheiden will.

## 1. Das "SConfig" Konzept
Während normale Bootloader-Konfigurationen ("Kconfig") beim Kompilieren (Build-Time) starr in das Binary eingebrannt werden, nutzt SConfig das gleiche System für die Laufzeit (Run-time).

- [ ] **Multiple Plolicies:** Ein Entwickler kann mehrere Profile (Dateien) in denselben Bootloader kompilieren, z.B. `myboard-lockdown.sconfig` und `myboard-devel.sconfig`.
- [ ] **Runtime Switch:** Beim Booten der Platine kann der C-Code des Boards das Profil dynamisch wechseln (z.B. durch den Befehl `security_policy_select("lockdown");`). Ob er das restriktive oder das offene Profil lädt, kann er anhand von Umweltfaktoren entscheiden (z.B. Ist ein verifizierter "Debug-USB-Stick" eingesteckt? Ist ein Hardware-Schalter umlegt?).

## 2. Kconfig vs. SConfig
Barebox unterscheidet hier hart zwischen zwei Welten:

| Eigenschaft | Kconfig (Normaler Build) | SConfig (Security Policy) |
|-------------|--------------------------|---------------------------|
| **Zweck** | Build-time (Kompilierung) | Run-time (Boot-Grenzwerte) |
| **Ergebnis**| Exakt ein `.config` File pro Build | Beliebig viele `.sconfig` Profile pro Build |
| **Typen** | bool, integer, string | **Nur booleans** (Erlaubt/Nicht Erlaubt) |

## 3. Harte Sicherheits-Limitationen
Wer dynamische Sicherheits-Switches zur Laufzeit erlaubt, öffnet ein massives architektonisches Problemfenster (Race Conditions). Die Spezifikation definiert daher einen harten Vertrag:

- [ ] **"Restrictive First" Regel:** Ein Board **MUSS** immer und ohne Ausnahme im restriktivsten Profil (`lockdown`) starten! Es darf nur später (wenn z.B. das Debug-Token verifiziert wurde) in das weichere Profil wechseln.
- [ ] **Dangling State Vulnerability:** Startet man in einem weichen Profil (z.B. Shell ist temporär offen, ein Dateisystem auf dem USB-Stick wurde gemountet) und wechselt danach in das `lockdown`-Profil, hat das katastrophale Folgen: SConfig "schließt" keine bereits laufenden Instanzen! Die offene Shell bleibt offen und der gemountete USB-Stick bleibt gemountet. Die Sicherheit wäre komplett durchbrochen.
