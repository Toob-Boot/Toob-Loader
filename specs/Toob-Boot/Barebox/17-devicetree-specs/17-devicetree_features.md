> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/devicetree.rst`

# 17. Barebox Devicetree Management

Dieses Dokument zeigt, dass Barebox architektonisch näher am echten Linux-Kernel ist als an klassischen Bootloadern. Beide Systeme verwenden exakt denselben Mechanismus (den Flattened Device Tree / FDT), um ihre Hardware zu kennen und Treiber zu instanziieren.

## 1. Das "Two-Tree" Problem (Live Tree vs. Kernel Tree)
In einem Barebox-Bootzyklus existieren streng genommen **zwei** unabhängige Device-Trees, die nicht verwechselt werden dürfen:

| Architektur-Baum | Bestimmung & Lifecycle |
|------------------|------------------------|
| **Live Tree (Internal)** | Dieser Devicetree (DTS) wird fest in das Barebox-Binary einkompiliert. Barebox operiert sein gesamtes Leben lang auf diesem Tree. Befehle auf der Konsole wie `of_node` oder `of_property` verändern standardmäßig *nur* diesen Baum! Hardware wird direkt aus diesem Baum instanziiert (`devinfo`). |
| **Kernel Tree** | Der Tree, den Barebox dem OS-Kernel beim Boot-Handoff überreicht. Er kann theoretisch identisch zum Live-Tree sein, ist aber in der Regel ein separates File. Soll ein Barebox-Konsolenbefehl eine Eigenschaft im Kernel-Tree (statt im Live-Tree) fixen/überschreiben, **muss** das `-f` (Fixup) Flag verwendet werden! |

## 2. Devicetree Overlays (Runtime Hot-Patching)
Barebox besitzt die Fähigkeit, Devicetrees **zur Laufzeit** dynamisch zusammenzukleben ("Overlays"). Ein riesiger Vorteil, z.B. wenn man Erweiterungs-Platinen (Hats/Capes) aufsteckt, für die man nicht die gesamte Master-Konfiguration neu kompilieren will.

- [ ] **Overlay Voreinstellungen:** Base-Trees müssen beim Kompilieren mit `dtc -@` gebaut werden, damit der Compiler den Node `/__symbols__` exportiert. Ohne diese Symbole kann das Overlay keine Verweise (`phandles`) in den Basis-Baum auflösen.
- [ ] **Live Tree Einschränkung:** Ein Overlay kann auf den "Live Tree" angewendet werden, aber Barebox merkt das im laufenden System nicht rückwirkend! Der C-Code des Boards **muss** das Overlay im pre-boot patchen, also *bevor* die Driver probe() Funktionen gelaufen sind.
- [ ] **Kernel Tree Assembly:** Kurz bevor Barebox den Kernel lädt, prüft das System die globale Variable `global.of.overlay.path` (die auf einen Ordner oder ein FIT-Image zeigt). Barebox sucht dort vollautomatisch nach kompatiblen Overlays (Filterung via `.compatible` String oder Patter-Matching der Dateinamen) und injiziert all diese Patches "on-the-fly" in den Kernel-Tree, bevor es die Ausführung an Linux übergibt. Ein extrem mächtiges Feature für variable Hardware-Produktionslinien.
