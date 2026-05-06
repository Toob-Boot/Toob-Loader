HAben wir irgendwo eine Art gesamte Dependency-Logik, die neue Versionen quasi hochgibt? Quasi:

Vendor, Toolchain, Arch sind die voneinander unabhängigen Grunddependencies (haben ja auch alle eigene manifests) -> die gehen in Chip rein, der von allen denen abhängig ist. Wenn eine der Grunddependencies eine Version-Änderung durchmacht, dann muss entsprechend der SemVer von da (vx.x.x --> 1.x = Major, 2.x = Minor, 3.x = Patch)

Dann muss die neue Release Version um mindestens das ansteigen und eine neue Version auch für Chip generieren, aber nicht für andere unabhängige Manifests.

Und dann wird dieser Version durch die ganzen Build-Tests für alle chips und alle CLI Versionen die Kompatibilität getestet und dann in die compatibility Matrix eingetragen (auch wenn es fehlschlägt). Es muss keine Kombi getestet werden, die bereits getestet wurde, aber sobald auch nur eine x.x.+1 Änderung stattfang (ein patch) muss alles dafür getestet werden.

Sprich wir brauchen irgendwo nen Manager, der managed, was wie alles getestet/geupdatet wird etc.. Er muss Überblick über alle änderungen behalten und eine QUe von dem Soll und Ist Prüf-Kombi zustand errechnen und diese dann alle gemeinsam losschicken und testen lassen.

dadurch errechnen wir auch eine Art update-Manager und können Leute benachrichtigen, wenn es breaking Changes gibt oder eine neue CLI Version dafür sorgen würde, dass bestehende Projekte nicht gehandhabt werden könnten.

Wie wird das aktuell gehandhabt?
