"""Nachhilfe-Buchung: Flask + SQLite.

Start: `flask init-db`, `flask create-teacher`, `flask run` (siehe README).
"""
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps
from zoneinfo import ZoneInfo

import click
from flask import (Flask, abort, current_app, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

TZ = ZoneInfo("Europe/Berlin")
MIN_PASSWORT = 10
MAX_PASSWORT = 200  # verhindert absurd lange Eingaben (Hashing-Last)
FORMAT = "%Y-%m-%d %H:%M"
WOCHENTAGE = ["Mo.", "Di.", "Mi.", "Do.", "Fr.", "Sa.", "So."]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)

# Zeit ---------------------------------------------------------------------


def jetzt():
    """Aktuelle Berliner Zeit im Speicherformat (Textvergleich == Zeitvergleich)."""
    return datetime.now(TZ).strftime(FORMAT)


def parse(start):
    return datetime.strptime(start, FORMAT)


# Datenbank ----------------------------------------------------------------


def get_db():
    if "db" not in g:
        # isolation_level=None: wir steuern Transaktionen selbst (siehe tx()).
        db = sqlite3.connect(current_app.config["DATABASE"], timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        g.db = db
    return g.db


@contextmanager
def tx():
    """Schreibtransaktion. BEGIN IMMEDIATE sperrt die DB sofort für andere
    Schreiber, so dass gleichzeitige Buchungen nacheinander laufen."""
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


# Zugriffsschutz -----------------------------------------------------------


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if g.user is None:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def rolle_required(rolle):
    """Serverseitige Rollenprüfung: nicht angemeldet -> Login, falsche Rolle -> 403."""
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if g.user is None:
                return redirect(url_for("login"))
            if g.user["rolle"] != rolle:
                abort(403)
            return f(*a, **kw)
        return wrapper
    return deco


def pruefe_passwort(pw):
    if len(pw) < MIN_PASSWORT:
        return f"Das Passwort muss mindestens {MIN_PASSWORT} Zeichen lang sein."
    if len(pw) > MAX_PASSWORT:
        return f"Das Passwort darf höchstens {MAX_PASSWORT} Zeichen lang sein."
    return None


# App-Factory --------------------------------------------------------------


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    secret = os.environ.get("SECRET_KEY", "")
    app.config.update(
        SECRET_KEY=secret,
        DATABASE=os.environ.get(
            "DATABASE_PATH", os.path.join(app.instance_path, "nachhilfe.db")),
        # Standard sicher; lokal per COOKIE_SECURE=0 abschaltbar (http://127.0.0.1).
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") != "0",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        WTF_CSRF_TIME_LIMIT=None,  # Token gilt so lange wie die Session
        RATELIMIT_STORAGE_URI="memory://",
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError(
            "SECRET_KEY fehlt. Bitte als Umgebungsvariable setzen "
            "(siehe README / .env.example).")

    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)

    # Hinter dem Proxy von PythonAnywhere kommt die echte IP per X-Forwarded-For.
    if os.environ.get("TRUST_PROXY") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    csrf.init_app(app)
    limiter.init_app(app)

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.before_request
    def lade_nutzer():
        g.user = None
        uid = session.get("uid")
        if uid is not None:
            g.user = get_db().execute(
                "SELECT * FROM nutzer WHERE id = ?", (uid,)).fetchone()
            if g.user is None:
                session.clear()
        # Startpasswort vom Lehrer: erst ändern, dann weiter.
        if (g.user and g.user["muss_passwort_aendern"]
                and request.endpoint not in ("passwort_aendern", "logout", "static")):
            return redirect(url_for("passwort_aendern"))

    @app.after_request
    def sicherheits_header(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        resp.headers["Referrer-Policy"] = "same-origin"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def nav_daten():
        offen = 0
        if g.get("user") and g.user["rolle"] == "lehrer":
            offen = zaehle_offene(g.user["id"])
        return {"offene_anfragen": offen}

    @app.template_filter("datum")
    def datum_filter(start):
        d = parse(start)
        return f"{WOCHENTAGE[d.weekday()]} {d:%d.%m.%Y}"

    @app.template_filter("zeitraum")
    def zeitraum_filter(start, dauer):
        d = parse(start)
        return f"{d:%H:%M}–{d + timedelta(minutes=dauer):%H:%M} Uhr"

    @app.template_filter("zeitpunkt")
    def zeitpunkt_filter(start):
        return f"{parse(start):%d.%m.%Y, %H:%M} Uhr"

    for code, titel, text in [
        (400, "Ungültige Anfrage", "Die Anfrage war ungültig. Bitte laden Sie die Seite neu und versuchen Sie es erneut."),
        (403, "Kein Zugriff", "Für diese Seite fehlt Ihnen die Berechtigung."),
        (404, "Nicht gefunden", "Diese Seite gibt es nicht."),
        (413, "Zu groß", "Die Eingabe ist zu groß."),
        (429, "Zu viele Versuche", "Zu viele Versuche in kurzer Zeit. Bitte warten Sie eine Minute."),
        (500, "Fehler", "Es ist ein Fehler aufgetreten."),
    ]:
        def handler(_e, code=code, titel=titel, text=text):
            return render_template("fehler.html", code=code, titel=titel, text=text), code
        app.register_error_handler(code, handler)

    @app.errorhandler(CSRFError)
    def csrf_fehler(_e):
        return render_template(
            "fehler.html", code=400, titel="Sitzung abgelaufen",
            text="Das Formular ist nicht mehr gültig. Bitte laden Sie die Seite neu und versuchen Sie es erneut."), 400

    registriere_routen(app)
    registriere_cli(app)
    return app


# Hilfsabfragen ------------------------------------------------------------


def zaehle_offene(lehrer_id):
    return get_db().execute(
        """SELECT COUNT(*) FROM buchung b JOIN termin t ON t.id = b.termin_id
           WHERE t.lehrer_id = ? AND b.status = 'angefragt'""", (lehrer_id,)).fetchone()[0]


def offene_anfragen(lehrer_id):
    return get_db().execute(
        """SELECT b.id, b.nachricht, b.erstellt_am, t.start, t.dauer_min, t.fach,
                  n.name AS schueler_name
           FROM buchung b
           JOIN termin t ON t.id = b.termin_id
           JOIN nutzer n ON n.id = b.schueler_id
           WHERE t.lehrer_id = ? AND b.status = 'angefragt'
           ORDER BY t.start""", (lehrer_id,)).fetchall()


def buchungen_des_schuelers(schueler_id):
    """Liefert (aktuelle, verlauf). Nur eigene Buchungen: schueler_id steckt in der Abfrage."""
    rows = get_db().execute(
        """SELECT b.id, b.status, b.nachricht, b.ablehnungsgrund, b.erstellt_am,
                  t.start, t.dauer_min, t.fach, l.name AS lehrer_name
           FROM buchung b
           JOIN termin t ON t.id = b.termin_id
           JOIN nutzer l ON l.id = t.lehrer_id
           WHERE b.schueler_id = ?
           ORDER BY t.start""", (schueler_id,)).fetchall()
    jetzt_str = jetzt()
    aktuell = [r for r in rows if r["status"] in ("angefragt", "bestaetigt")
               and (r["status"] == "angefragt" or r["start"] >= jetzt_str)]
    verlauf = [r for r in reversed(rows) if r not in aktuell][:30]
    return aktuell, verlauf


# Routen -------------------------------------------------------------------


def registriere_routen(app):

    @app.route("/")
    def start():
        if g.user is None:
            return redirect(url_for("login"))
        if g.user["rolle"] == "lehrer":
            return redirect(url_for("lehrer_termine"))
        return redirect(url_for("termine"))

    # --- Anmeldung -------------------------------------------------------

    @app.route("/registrieren", methods=["GET", "POST"])
    @limiter.limit("10 per hour", methods=["POST"])
    def registrieren():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            pw = request.form.get("passwort", "")
            fehler = None
            if not name or len(name) > 100:
                fehler = "Bitte geben Sie Ihren Namen an (höchstens 100 Zeichen)."
            elif not EMAIL_RE.match(email) or len(email) > 254:
                fehler = "Bitte geben Sie eine gültige E-Mail-Adresse an."
            else:
                fehler = pruefe_passwort(pw)
            if not fehler:
                try:
                    # Rolle ist fest "schueler": Lehrer entstehen nur über die CLI.
                    get_db().execute(
                        """INSERT INTO nutzer (name, email, passwort_hash, rolle, erstellt_am)
                           VALUES (?, ?, ?, 'schueler', ?)""",
                        (name, email, generate_password_hash(pw), jetzt()))
                except sqlite3.IntegrityError:
                    fehler = "Diese E-Mail-Adresse ist bereits registriert."
            if fehler:
                flash(fehler, "fehler")
                return render_template("registrieren.html", name=name, email=email), 400
            flash("Konto angelegt. Sie können sich jetzt anmelden.", "ok")
            return redirect(url_for("login"))
        return render_template("registrieren.html", name="", email="")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            pw = request.form.get("passwort", "")
            user = get_db().execute(
                "SELECT * FROM nutzer WHERE email = ?", (email,)).fetchone()
            # Immer ein Hash-Vergleich, damit die Antwortzeit nichts verrät.
            hash_ = user["passwort_hash"] if user else DUMMY_HASH
            if check_password_hash(hash_, pw) and user:
                session.clear()  # neue Session nach Login (gegen Session-Fixation)
                session.permanent = True
                session["uid"] = user["id"]
                return redirect(url_for("start"))
            flash("E-Mail oder Passwort ist falsch.", "fehler")
            return render_template("login.html", email=email), 401
        if g.user:
            return redirect(url_for("start"))
        return render_template("login.html", email="")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/passwort-aendern", methods=["GET", "POST"])
    @login_required
    def passwort_aendern():
        if request.method == "POST":
            alt = request.form.get("alt", "")
            neu = request.form.get("neu", "")
            neu2 = request.form.get("neu2", "")
            fehler = None
            if not check_password_hash(g.user["passwort_hash"], alt):
                fehler = "Das aktuelle Passwort ist falsch."
            elif neu != neu2:
                fehler = "Die beiden neuen Passwörter stimmen nicht überein."
            elif neu == alt:
                fehler = "Das neue Passwort muss sich vom alten unterscheiden."
            else:
                fehler = pruefe_passwort(neu)
            if fehler:
                flash(fehler, "fehler")
                return render_template("passwort_aendern.html"), 400
            get_db().execute(
                "UPDATE nutzer SET passwort_hash = ?, muss_passwort_aendern = 0 WHERE id = ?",
                (generate_password_hash(neu), g.user["id"]))
            flash("Passwort geändert.", "ok")
            return redirect(url_for("start"))
        return render_template("passwort_aendern.html")

    # --- Schüler ---------------------------------------------------------

    @app.route("/termine")
    @rolle_required("schueler")
    def termine():
        rows = get_db().execute(
            """SELECT t.id, t.start, t.dauer_min, t.fach, l.name AS lehrer_name
               FROM termin t JOIN nutzer l ON l.id = t.lehrer_id
               WHERE t.status = 'frei' AND t.start > ?
               ORDER BY t.start""", (jetzt(),)).fetchall()
        return render_template("termine.html", termine=rows)

    @app.route("/termine/<int:termin_id>/buchen", methods=["GET", "POST"])
    @rolle_required("schueler")
    def buchen(termin_id):
        db = get_db()
        t = db.execute(
            """SELECT t.*, l.name AS lehrer_name FROM termin t
               JOIN nutzer l ON l.id = t.lehrer_id WHERE t.id = ?""", (termin_id,)).fetchone()
        if t is None:
            abort(404)
        if request.method == "POST":
            nachricht = request.form.get("nachricht", "").strip()
            if len(nachricht) > 500:
                flash("Die Nachricht darf höchstens 500 Zeichen lang sein.", "fehler")
                return render_template("buchen.html", t=t, nachricht=nachricht), 400
            erfolg = False
            try:
                with tx() as conn:
                    # Atomar: nur wer den Termin von 'frei' auf 'angefragt' setzt, bekommt ihn.
                    cur = conn.execute(
                        "UPDATE termin SET status = 'angefragt' WHERE id = ? AND status = 'frei' AND start > ?",
                        (termin_id, jetzt()))
                    if cur.rowcount == 1:
                        conn.execute(
                            """INSERT INTO buchung (termin_id, schueler_id, nachricht, erstellt_am)
                               VALUES (?, ?, ?, ?)""",
                            (termin_id, g.user["id"], nachricht, jetzt()))
                        erfolg = True
            except sqlite3.IntegrityError:
                erfolg = False  # Unique-Index hat eine Doppelbuchung verhindert
            if not erfolg:
                flash("Dieser Termin ist leider nicht mehr verfügbar.", "fehler")
                return redirect(url_for("termine"))
            flash("Anfrage gesendet. Sie sehen den Status unter „Meine Buchungen“.", "ok")
            return redirect(url_for("meine_buchungen"))
        if t["status"] != "frei" or t["start"] <= jetzt():
            flash("Dieser Termin ist leider nicht mehr verfügbar.", "fehler")
            return redirect(url_for("termine"))
        return render_template("buchen.html", t=t, nachricht="")

    @app.route("/buchungen")
    @rolle_required("schueler")
    def meine_buchungen():
        aktuell, verlauf = buchungen_des_schuelers(g.user["id"])
        return render_template("buchungen.html", aktuell=aktuell, verlauf=verlauf)

    @app.route("/buchungen/<int:buchung_id>/zurueckziehen", methods=["POST"])
    @rolle_required("schueler")
    def zurueckziehen(buchung_id):
        with tx() as conn:
            # schueler_id in der WHERE-Klausel: fremde Buchungen sind nicht erreichbar.
            b = conn.execute(
                "SELECT termin_id FROM buchung WHERE id = ? AND schueler_id = ? AND status = 'angefragt'",
                (buchung_id, g.user["id"])).fetchone()
            if b:
                conn.execute("UPDATE buchung SET status = 'zurueckgezogen' WHERE id = ?", (buchung_id,))
                conn.execute("UPDATE termin SET status = 'frei' WHERE id = ?", (b["termin_id"],))
        if b:
            flash("Anfrage zurückgezogen.", "ok")
        else:
            flash("Diese Anfrage kann nicht mehr zurückgezogen werden.", "fehler")
        return redirect(url_for("meine_buchungen"))

    # --- Live-Aktualisierung (Polling alle 15 s) --------------------------

    @app.route("/api/benachrichtigungen")
    @login_required
    def api_benachrichtigungen():
        mit_html = request.args.get("html") == "1"
        if g.user["rolle"] == "lehrer":
            rows = offene_anfragen(g.user["id"])
            html = render_template("_anfragen.html", anfragen=rows) if mit_html else None
            return jsonify(count=len(rows), html=html)
        aktuell, verlauf = buchungen_des_schuelers(g.user["id"])
        html = render_template("_buchungen.html", aktuell=aktuell, verlauf=verlauf) if mit_html else None
        return jsonify(count=0, html=html)

    # --- Lehrer ----------------------------------------------------------

    @app.route("/lehrer/termine", methods=["GET", "POST"])
    @rolle_required("lehrer")
    def lehrer_termine():
        werte = {"datum": "", "zeit": "", "dauer": "60", "fach": ""}
        if request.method == "POST":
            werte = {k: request.form.get(k, "").strip() for k in werte}
            fehler = None
            try:
                beginn = datetime.strptime(f"{werte['datum']} {werte['zeit']}", FORMAT)
                dauer = int(werte["dauer"])
            except ValueError:
                fehler = "Bitte Datum, Uhrzeit und Dauer korrekt angeben."
            else:
                if not 15 <= dauer <= 240:
                    fehler = "Die Dauer muss zwischen 15 und 240 Minuten liegen."
                elif not werte["fach"] or len(werte["fach"]) > 60:
                    fehler = "Bitte ein Fach angeben (höchstens 60 Zeichen)."
                elif beginn.strftime(FORMAT) <= jetzt():
                    fehler = "Der Termin muss in der Zukunft liegen."
            if not fehler:
                with tx() as conn:
                    # Eigene Termine dürfen sich nicht überschneiden.
                    ende = beginn + timedelta(minutes=dauer)
                    for s, d in conn.execute(
                            "SELECT start, dauer_min FROM termin WHERE lehrer_id = ? AND start LIKE ?",
                            (g.user["id"], f"{beginn:%Y-%m-%d}%")):
                        s0 = parse(s)
                        if s0 < ende and s0 + timedelta(minutes=d) > beginn:
                            fehler = "Dieser Zeitraum überschneidet sich mit einem vorhandenen Termin."
                            break
                    if not fehler:
                        conn.execute(
                            "INSERT INTO termin (lehrer_id, start, dauer_min, fach) VALUES (?, ?, ?, ?)",
                            (g.user["id"], beginn.strftime(FORMAT), dauer, werte["fach"]))
            if fehler:
                flash(fehler, "fehler")
            else:
                flash("Termin angelegt.", "ok")
                return redirect(url_for("lehrer_termine"))
        rows = get_db().execute(
            """SELECT t.id, t.start, t.dauer_min, t.fach, t.status,
                      b.id AS buchung_id, n.name AS schueler_name
               FROM termin t
               LEFT JOIN buchung b ON b.termin_id = t.id AND b.status IN ('angefragt', 'bestaetigt')
               LEFT JOIN nutzer n ON n.id = b.schueler_id
               WHERE t.lehrer_id = ? AND t.start > ?
               ORDER BY t.start""", (g.user["id"], jetzt())).fetchall()
        return render_template("lehrer_termine.html", termine=rows, w=werte), (400 if request.method == "POST" else 200)

    @app.route("/lehrer/termine/<int:termin_id>/loeschen", methods=["POST"])
    @rolle_required("lehrer")
    def termin_loeschen(termin_id):
        with tx() as conn:
            # Nur freie Termine: angefragte erst ablehnen, bestätigte bleiben bestehen.
            cur = conn.execute(
                "DELETE FROM termin WHERE id = ? AND lehrer_id = ? AND status = 'frei'",
                (termin_id, g.user["id"]))
        if cur.rowcount:
            flash("Termin gelöscht.", "ok")
        else:
            flash("Dieser Termin kann nicht gelöscht werden. Angefragte Termine bitte zuerst ablehnen; bestätigte Termine bleiben bestehen.", "fehler")
        return redirect(url_for("lehrer_termine"))

    @app.route("/lehrer/anfragen")
    @rolle_required("lehrer")
    def lehrer_anfragen():
        return render_template("lehrer_anfragen.html", anfragen=offene_anfragen(g.user["id"]))

    def anfrage_bearbeiten(buchung_id, neu, grund=None):
        """Bestätigen/Ablehnen. Nur offene Anfragen eigener Termine; Rückgabe: geklappt?"""
        with tx() as conn:
            b = conn.execute(
                """SELECT b.termin_id FROM buchung b JOIN termin t ON t.id = b.termin_id
                   WHERE b.id = ? AND t.lehrer_id = ? AND b.status = 'angefragt'""",
                (buchung_id, g.user["id"])).fetchone()
            if b is None:
                return False
            conn.execute("UPDATE buchung SET status = ?, ablehnungsgrund = ? WHERE id = ?",
                         (neu, grund, buchung_id))
            conn.execute("UPDATE termin SET status = ? WHERE id = ?",
                         ("bestaetigt" if neu == "bestaetigt" else "frei", b["termin_id"]))
            return True

    @app.route("/lehrer/buchungen/<int:buchung_id>/bestaetigen", methods=["POST"])
    @rolle_required("lehrer")
    def bestaetigen(buchung_id):
        if anfrage_bearbeiten(buchung_id, "bestaetigt"):
            flash("Termin bestätigt.", "ok")
        else:
            flash("Diese Anfrage ist nicht mehr offen (eventuell zurückgezogen).", "fehler")
        return redirect(url_for("lehrer_anfragen"))

    @app.route("/lehrer/buchungen/<int:buchung_id>/ablehnen", methods=["POST"])
    @rolle_required("lehrer")
    def ablehnen(buchung_id):
        grund = request.form.get("grund", "").strip()
        if not grund or len(grund) > 300:
            flash("Bitte eine kurze Begründung angeben (höchstens 300 Zeichen).", "fehler")
        elif anfrage_bearbeiten(buchung_id, "abgelehnt", grund):
            flash("Anfrage abgelehnt. Der Termin ist wieder frei.", "ok")
        else:
            flash("Diese Anfrage ist nicht mehr offen (eventuell zurückgezogen).", "fehler")
        return redirect(url_for("lehrer_anfragen"))

    @app.route("/lehrer/schueler", methods=["GET"])
    @rolle_required("lehrer")
    def lehrer_schueler():
        rows = get_db().execute(
            "SELECT id, name, email FROM nutzer WHERE rolle = 'schueler' ORDER BY name").fetchall()
        return render_template("lehrer_schueler.html", schueler=rows)

    @app.route("/lehrer/schueler/<int:nutzer_id>/passwort", methods=["POST"])
    @rolle_required("lehrer")
    def startpasswort_setzen(nutzer_id):
        pw = request.form.get("passwort", "")
        fehler = pruefe_passwort(pw)
        if fehler:
            flash(fehler, "fehler")
            return redirect(url_for("lehrer_schueler"))
        cur = get_db().execute(
            """UPDATE nutzer SET passwort_hash = ?, muss_passwort_aendern = 1
               WHERE id = ? AND rolle = 'schueler'""",
            (generate_password_hash(pw), nutzer_id))
        if cur.rowcount:
            flash("Startpasswort gesetzt. Der Schüler muss es beim nächsten Login ändern.", "ok")
        else:
            abort(404)
        return redirect(url_for("lehrer_schueler"))

    # --- Statische Seiten ------------------------------------------------

    @app.route("/datenschutz")
    def datenschutz():
        return render_template("datenschutz.html")

    @app.route("/impressum")
    def impressum():
        return render_template("impressum.html")


# Für Login-Versuche mit unbekannter E-Mail (konstante Rechenzeit).
DUMMY_HASH = generate_password_hash("kein-echtes-passwort")


# CLI ----------------------------------------------------------------------


def registriere_cli(app):

    @app.cli.command("init-db")
    def init_db():
        """Legt die Tabellen an (löscht keine vorhandenen Daten)."""
        db = sqlite3.connect(app.config["DATABASE"])
        with open(os.path.join(app.root_path, "schema.sql"), encoding="utf-8") as f:
            db.executescript(f.read())
        db.close()
        click.echo("Datenbank bereit: " + app.config["DATABASE"])

    @app.cli.command("create-teacher")
    @click.option("--name", prompt="Name")
    @click.option("--email", prompt="E-Mail")
    @click.password_option("--passwort", prompt="Passwort", confirmation_prompt=True,
                           help="Wird abgefragt, nie als Argument übergeben.")
    def create_teacher(name, email, passwort):
        """Legt ein Lehrer-Konto an (Registrierung im Web erzeugt nur Schüler)."""
        email = email.strip().lower()
        fehler = None
        if not EMAIL_RE.match(email):
            fehler = "Ungültige E-Mail-Adresse."
        else:
            fehler = pruefe_passwort(passwort)
        if fehler:
            raise click.ClickException(fehler)
        db = sqlite3.connect(app.config["DATABASE"])
        try:
            db.execute(
                """INSERT INTO nutzer (name, email, passwort_hash, rolle, erstellt_am)
                   VALUES (?, ?, ?, 'lehrer', ?)""",
                (name.strip(), email, generate_password_hash(passwort), jetzt()))
            db.commit()
        except sqlite3.IntegrityError:
            raise click.ClickException("Diese E-Mail-Adresse ist bereits vergeben.")
        finally:
            db.close()
        click.echo("Lehrer-Konto angelegt.")
