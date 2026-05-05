# Local Publisher Pipeline Setup (GitOps / Docker)

Diese Dokumentation beschreibt, wie du den "Toob Publisher Daemon" auf deinem Backend-Server ausrollst. 
Das System nutzt `nektos/act` verpackt in einen Docker-Container. Das bedeutet: Zero Install auf deinem Host-System, automatische Webhook-Verarbeitung und absolute Supply Chain Security durch Wegwerf-VMs.

## 1. Secrets hinterlegen

Damit `act` die fertigen Binaries in das externe Release-Repo pushen darf, speichern wir deinen Token in einer lokalen `.secrets` Datei auf dem Server.

1. Erstelle auf GitHub einen "Fine-grained Personal Access Token" (PAT).
2. Gib dem Token **nur** Zugriff auf das Repository `Toob-CLI-Release` und setze die Berechtigung `Contents: Write`.
3. Erstelle auf deinem Server im Root-Verzeichnis deines Repos (`Toob-Loader/.secrets`) die Datei:
   ```text
   RELEASE_TARGET_TOKEN=dein_github_token_hier
   ```

*(Hinweis: `.secrets` wird durch die `.gitignore` automatisch von Git ignoriert!)*

## 2. Den Daemon starten (GitOps Deployment)

Logge dich auf deinem Server ein, navigiere in das Toob-Loader Repository und starte den Daemon:

```bash
cd cli/publisher
export WEBHOOK_SECRET="DeinGeheimesPasswortFürDenWebhook"
docker-compose up -d --build
```

Damit läuft der Daemon ressourcenschonend im Hintergrund und lauscht auf Port `9000`.

## 3. GitHub Webhook einrichten

Damit der Daemon weiß, wann er loslegen soll:
1. Gehe auf GitHub in die Settings deines `Toob-Loader` Repositories.
2. Gehe auf **Webhooks** -> **Add webhook**.
3. **Payload URL:** `http://dein-server.com:9000/hooks/release`
4. **Content type:** `application/json`
5. **Secret:** Das Passwort, das du im `WEBHOOK_SECRET` vergeben hast.
6. **Trigger:** Wähle "Let me select individual events" und hake **nur** `Branch or tag creation` an.

## 4. Wie funktioniert der Release-Prozess jetzt?

1. Du pusht lokal auf deinem Laptop einen neuen Tag:
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```
2. GitHub schickt sofort einen Ping an deinen Server (Port 9000).
3. Der `toob-publisher` Docker-Container prüft das kryptografische Secret.
4. Er startet über den Docker-Socket eine temporäre, isolierte Ubuntu-VM ("Sibling Container").
5. Der Code wird hermetisch für Windows, Linux und macOS kompiliert, signiert und hochgeladen.
6. Die Ubuntu-VM zerstört sich spurlos selbst.

## Updates des Daemons
Wenn du das `Dockerfile` oder `docker-compose.yml` änderst, gehst du einfach auf den Server und tippst:
```bash
git pull
docker-compose up -d --build
```
Alles wird automatisch und sauber aktualisiert.
