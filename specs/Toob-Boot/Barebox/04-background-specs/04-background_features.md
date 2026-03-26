> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/devel/background-execution.rst`

# 04. Background Execution & Multitasking

Dieses Dokument spezifiziert das reaktive Modell von Barebox. Um die Komplexität gering zu halten, verbietet Barebox architektonisch den Einsatz von Hardware-Interrupts für Hintergrundprozesse! Stattdessen setzt das System vollkommen auf **Cooperative Multitasking**.

## 1. Die asynchronen Execution Contracts
Barebox bietet 4 primitive Mechanismen, um Code "im Hintergrund" auszuführen (z.B. für USB-Fastboot oder blinkende Status-LEDs). Keines davon nutzt echte Hardware-Interrupts.

| Mechanismus | Funktionsweise & Invariante |
|-------------|-----------------------------|
| **1. Pollers** | Sehr kurze Code-Blöcke. Ein Poller (`poller_register()`) wird ausschließlich dann aufgerufen, wenn irgendein anderer Treiber im System die Funktion `is_timeout()` aufruft! **Vertrag:** Pollers dürfen niemals das Dateisystem berühren oder Shell-Befehle auslösen! |
| **2. Workqueues** | Wenn ein Prozess Dateizugriffe braucht (z.B. Flashen eines Images via Netzwerk), registriert ein Poller einen Auftrag in der Workqueue (`wq_queue_work()`). Dieser Auftrag wird dann später sicher vom Haupt-Thread der interaktiven Shell (zwischen zwei Shell-Kommandos) abgearbeitet. |
| **3. bthreads** | Cooperative "Green Threads". Ein Thread (`bthread_create()`) hat einen eigenen Stack, wird aber exakt wie Workqueues nur aktiv, wenn die Shell idle ist. Er gibt die Kontrolle freiwillig zurück, sobald er `is_timeout()` ruft. Perfekt, um dicke Thread-Architekturen aus dem großen Linux-Kernel nach Barebox zu portieren. |

## 2. Resource-Locking ("Slices")
Da es keine echten preemptiven Mutexe gibt, aber Pollers durch zufällige `is_timeout()` Aufrufe mitten in andere IO-Zugriffe crashen könnten, existieren "Slices".

- [ ] **Slice Acquisition:** Bevor ein Poller z.B. einen I2C-Bus oder Netzwerk-Chip berührt, **MUSS** er dessen Zustand validieren (`slice_busy()`). Ist die Hardware belegt (weil der Treiber sie gerade selbst nutzt), muss der Poller den Versuch sofort abbrechen und beim nächsten Timeout-Zyklus von vorne beginnen.
- [ ] **Dependency Chaining:** Ressourcen können hardwaretechnisch verknüpft werden. Sagt ein USB-Ethernet Modul `slice_depends_on(USB_HOST)`, springt das Ethernet Slice automatisch auf "Busy", sobald irgendein anderer Prozess auf den USB Host Controller zugreift.

## 3. Limitierungen (UX Restrictions)
Das cooperative Design führt zu einem starken Vertrag für die User-Experience (UX):
- [ ] Da Pollers und Workqueues nicht unterbrochen werden können (No Preemption), blockiert ein zu langer Task (wie z.B. das Flashen eines 50MB Images über Fastboot) den kompletten Barebox Main-Loop. Die `hush` Shell reagiert dann vorrübergehend auf keinerlei Tastenanschläge der Tastatur mehr ("Sluggishness"). Diagnostisch kann dies über den Befehl `poller -t` in der Shell gebenchmarkt werden.
