> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/system-reset.rst`

# 09. System Restart & Reset Architecture

Dieses Dokument behandelt die Architekturkritik an "weichen" System-Reboots in Embedded-Umgebungen. Es definiert die Gefahren von internen SoC-Watchdogs und plädiert für echte Hardware-Schnittstellen beim Reboot ("Power-On Reset" equivalent).

## 1. Das "Internal Watchdog" Problem
Der simpelste Weg, ein Board neu zu starten, ist, den On-Chip Watchdog des Prozessors anspringen zu lassen. Barebox warnt davor, da dieser Mechanismus in der Regel **nur den CPU-Kern** resettet, die restliche Peripherie auf dem Board aber unter Strom im alten Zustand lässt. Das führt zu desaströsen Zuständen:

- [ ] **Flash-Desync ("Array Mode"):** Wenn die CPU gerade einen NOR-Flash programmiert und resettet wird, wacht sie auf und will Boot-Instruktionen aus dem Flash lesen. Der Flash wartet aber immer noch auf die Payload-Daten des Programmiervorgangs. Das System brickt sofort, weil der Flash nicht mit resettet wurde.
- [ ] **Bootstrap Pin Corruption:** Viele Chips entscheiden anhand von Pull-Up/Down Pins beim Booten, wie sie starten sollen (z.B. USB-Boot vs. SD-Karten-Boot). Nach dem Start werden diese Pins oft für andere Zwecke (z.B. LEDs oder Taster) genutzt. Resettet nur die CPU, werden die Werte der aktiven LEDs plötzlich als "Bootstrap-Wunsch" falsch interpretiert.
- [ ] **PMIC Voltage Mismatch (Under-Volting):** Um Strom zu sparen, senkt moderne Software den CPU-Takt und zeitgleich die externe Netzteil-Spannung (PMIC). Resettet die CPU intern, taktet sie sofort wieder auf Vollgas hoch. Da das externe Netzteil aber nicht resettet wurde, liefert es weiterhin nur die niedrige Energiespar-Spannung. Die CPU stürzt sofort wegen Unterspannung ab.
- [ ] **DMA Amokläufer:** DMA-Controller übertragen Daten völlig unabhängig von der CPU. Ein CPU-Reset stoppt diese nicht. Die CPU wacht im Bootloader auf, während der DMA-Controller weiterhin lustig den RAM überschreibt und den Bootloader zerstört.

## 2. Die architekturelle Lösung: System-Wide Resets (PMICs)
Um diese Hardware-Desyncs zu verhindern, definiert Barebox eine Architekturlösung für den Restart.

| Reset Strategie | Technische Auswirkung & Vertrag |
|-----------------|---------------------------------|
| **External SoC Reset Line** | Löst die CPU den Reset aus, **MUSS** der SoC ein dediziertes physikalisches Hardware-Pin nach außen anlegen, welches die Platine und alle Peripherie zeitgleich vom Strom nimmt. |
| **PMIC Watchdog Routing** | Hat der SoC kein solches Pin, darf der interne Watchdog nicht verwendet werden. Der Vertrag lautet: Der Watchdog des **externen PMIC (Stromcontrollers)** wird scharfgeschaltet. Dieser trennt stumpf die Stromversorgung der gesamten Platine und erzwingt so einen absolut echten "Power-On Reset" (POR). |

## 3. Der Nachteil von PMIC Resets
Die Lösung via externem Netzteil-Reset hat einen architektonischen Trade-off:
- [ ] **Verlust der Diagnostik (`reset_reason`):** Da der PMIC den Strom komplett kappt, verliert die CPU intern jegliches Wissen darüber, *warum* sie abgestürzt ist. Von Seiten der CPU sieht dieser Watchdog-Reset exakt aus wie das erste Einstecken des Kaltgerätesteckers (POR). Barebox kann dem Betriebssystem dann nicht mehr melden, ob es ein gezielter Reboot oder ein Watchdog-Crash war (es sei denn, der PMIC selbst protokolliert dies und Barebox kann den PMIC per I2C auslesen).
