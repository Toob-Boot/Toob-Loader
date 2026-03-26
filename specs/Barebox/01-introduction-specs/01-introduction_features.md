> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/introduction.rst`

# 01. Barebox Core Philosophy & Introduction

Dieses Dokument abstrahiert die grundlegende Philosophie und den Workflow von Barebox. Es dient als Einstieg, um die strategische Ausrichtung des Bootloaders zu verstehen.

## 1. Die "Swiss Army Knife" Philosophie
Barebox beschreibt sich selbst als das "Schweizer Taschenmesser für Bare Metal", analog zu BusyBox in der Linux-Welt.
- [ ] **Dual-Use-Architektur:** Barebox ist nicht nur ein reiner Produktions-Bootloader. Er ist explizit als interaktives Werkzeug für Hardware Bring-ups konzipiert. Entwickler können ihn vollumfänglich "aufblähen" (Full-Featured Development Binary), um neue Platinen zu testen, und später für die Produktion extrem abspecken ("Lean").
- [ ] **Skalierbarkeit auf Architekturen:** Das System ist tief von Hardware abstrahiert und läuft nativ auf extrem verschiedenen Kernen: x86, ARM, MIPS, und PowerPC.

## 2. Der Patch-Workflow (Linux-Kernel Stil)
Im Gegensatz zu modernen Open-Source Projekten, die PRs auf GitHub/GitLab nutzen, verwendet Barebox exakt den e-Mail-basierten Hardcore-Workflow des Linux-Kernels.

| Tooling / Workflow | Protokoll / Mechanik |
|--------------------|----------------------|
| **Mailing List** | Code-Änderungen dürfen auschließlich als Patch-eMails an `barebox@lists.infradead.org` gesendet werden. Das Archiv liegt unter `lore.barebox.org`. |
| **Patch Management (`b4`)** | Entwickler manipulieren Patches nicht per simplen git-pulls, sondern per `b4` (einem Tool für Patchwork/Mailing-Listen). Mit dem Befehl `b4 shazam -H <lore-link>` saugt das Tool Patch-Serien aus der Mailing-E-Mail, rebased sie automatisch, wendet sie an und aktualisiert den `FETCH_HEAD`. |
