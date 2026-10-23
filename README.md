# Nachhilfe-Buchung

Kleine Webanwendung zur Buchung von Nachhilfestunden (Python, Flask, SQLite).
Ein Lehrer legt freie Termine an, Schüler fragen sie an, der Lehrer bestätigt oder lehnt ab.
Keine externen Dienste, keine CDNs, keine Tracker, kein E-Mail-Versand.

## Ablauf

- **Lehrer:** legt Termine an (Datum, Uhrzeit, Dauer, Fach), löscht freie Termine, bearbeitet Anfragen im Posteingang (Zähler im Menü, Aktualisierung alle 15 Sekunden), setzt Startpasswörter für Schüler zurück.
- **Schüler:** sieht freie Termine, fragt einen an (optional mit Nachricht), sieht unter „Meine Buchungen“ den Status und kann eine Anfrage vor der Bestätigung zurückziehen.
- Ein Termin kann nie doppelt gebucht werden. Das ist in der Datenbank abgesichert (atomares Update in einer Transaktion plus Unique-Index auf aktive Buchungen).
- Zeitzone Europe/Berlin, deutsches Datumsformat.

## Lokal starten

Voraussetzung: Python 3.10 oder neuer.

```bash
python -m venv venv
# Windows (PowerShell):  venv\Scripts\Activate.ps1
# Windows (cmd):         venv\Scripts\activate.bat
# macOS/Linux:           source venv/bin/activate
pip install -r requirements.txt
```

Einstellungen: `.env.example` nach `.env` kopieren und ausfüllen. Der Befehl `flask` lädt `.env` automatisch.

```
FLASK_APP=app
SECRET_KEY=<langer Zufallswert>
COOKIE_SECURE=0
```

Zufallswert erzeugen: `python -c "import secrets; print(secrets.token_hex(32))"`.
`COOKIE_SECURE=0` ist nur lokal nötig, weil `http://127.0.0.1` kein HTTPS hat. Ohne `SECRET_KEY` startet die App absichtlich nicht.

```bash
flask init-db          # legt instance/nachhilfe.db an (löscht nichts Vorhandenes)
flask create-teacher   # fragt Name, E-Mail und Passwort ab
flask run
```

Die Seite läuft unter <http://127.0.0.1:5000>. Schüler registrieren sich dort selbst; Lehrer-Konten gibt es nur über `flask create-teacher`.

### Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Veröffentlichung

### A) Code auf GitHub

1. Im Projektordner `git init` ausführen.
2. Mit `git status` prüfen: Es dürfen **keine** `.db`-Datei, kein `instance/`-Ordner, keine `.env` und kein `venv/` aufgeführt sein. Was einmal öffentlich committet wurde, bleibt in der Git-Historie.
3. `git add .` und `git commit -m "Erste Version"`.
4. Auf github.com ein neues **öffentliches** Repository **ohne** README anlegen und die angezeigten Befehle ausführen:
   `git branch -M main`, `git remote add origin https://github.com/NUTZERNAME/REPOSITORY.git`, `git push -u origin main`.

### B) PythonAnywhere (kostenloses Beginner-Konto)

1. Konto auf pythonanywhere.com als „Beginner“ anlegen. Ein langes, einmaliges Passwort wählen und, falls angeboten, die Zwei-Faktor-Anmeldung aktivieren. Die Seite ist danach unter `BENUTZERNAME.pythonanywhere.com` erreichbar.
2. Im Reiter **Consoles** eine Bash-Konsole öffnen und das Repository klonen:
   `git clone https://github.com/NUTZERNAME/REPOSITORY.git`
3. Im Projektordner eine virtuelle Umgebung anlegen und Pakete installieren (Python 3.10 oder neuer wählen, z. B. 3.12):
   ```bash
   mkvirtualenv --python=/usr/bin/python3.12 meinenv
   cd REPOSITORY
   pip install -r requirements.txt
   ```
4. Reiter **Web** → „Add a new web app“ → Domain bestätigen → „Manual configuration“ → dieselbe Python-Version wählen.
5. Auf der Web-Seite eintragen: **Source code** = `/home/BENUTZERNAME/REPOSITORY`, **Virtualenv** = `/home/BENUTZERNAME/.virtualenvs/meinenv`.
6. Die WSGI-Konfigurationsdatei (Link auf der Web-Seite) öffnen, den gesamten Inhalt durch diesen Block ersetzen und die zwei Platzhalter anpassen:
   ```python
   import os
   import sys

   projekt = "/home/BENUTZERNAME/REPOSITORY"
   if projekt not in sys.path:
       sys.path.insert(0, projekt)

   os.environ["SECRET_KEY"] = "HIER_ZUFALLSWERT_EINTRAGEN"
   os.environ["COOKIE_SECURE"] = "1"   # Seite läuft über HTTPS
   os.environ["TRUST_PROXY"] = "1"     # echte Client-IP für die Login-Begrenzung
   # Optional: os.environ["DATABASE_PATH"] = "/home/BENUTZERNAME/REPOSITORY/instance/nachhilfe.db"

   from app import create_app
   application = create_app()
   ```
   Den `SECRET_KEY` mit `python -c "import secrets; print(secrets.token_hex(32))"` erzeugen und nirgends sonst ablegen. Ändert er sich später, werden alle angemeldeten Nutzer abgemeldet.
7. In der Bash-Konsole (im Projektordner, Virtualenv aktiv) Datenbank und Lehrer-Konto anlegen. Dafür dieselben Umgebungsvariablen setzen:
   ```bash
   export FLASK_APP=app SECRET_KEY=HIER_DENSELBEN_WERT COOKIE_SECURE=1
   flask init-db
   flask create-teacher
   ```
8. Auf der Web-Seite **Force HTTPS** einschalten und auf **Reload** klicken. Dann die Adresse im Browser öffnen und testen.
9. Aktualisieren später: in der Konsole `git pull`, bei neuen Paketen `pip install -r requirements.txt`, dann auf der Web-Seite **Reload**.
10. Beim kostenlosen Konto muss auf der Web-Seite etwa alle drei Monate der Knopf zur Verlängerung geklickt werden, sonst wird die App abgeschaltet. Wortlaut und aktuelle Frist dort nachlesen.
11. Der Zugriff auf externe Server ist beim kostenlosen Konto eingeschränkt. Die App benötigt deshalb keine externen Dienste.

### Hinweise zum Betrieb

- Die Datenbank (`instance/nachhilfe.db`) liegt nur auf dem Server, nicht im Git. Sicherung: Datei in PythonAnywhere unter „Files“ herunterladen.
- Die Login-Begrenzung (5 pro Minute je IP) zählt im Arbeitsspeicher des jeweiligen Prozesses.

## Noch von Ihnen auszufüllen

`templates/datenschutz.html` und `templates/impressum.html` enthalten einen deutlich markierten Bereich „NOCH AUSZUFÜLLEN“. Dort den rechtlich verbindlichen Text und das Impressum eintragen und den Kasten danach entfernen.
