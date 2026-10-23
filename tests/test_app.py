import re
import sqlite3
import threading
from datetime import datetime, timedelta

import pytest

from app import TZ, create_app

PW = "ein-langes-passwort"


def make_app(tmp_path, **cfg):
    config = dict(SECRET_KEY="test", DATABASE=str(tmp_path / "t.db"),
                  SESSION_COOKIE_SECURE=False, WTF_CSRF_ENABLED=False,
                  RATELIMIT_ENABLED=False)
    config.update(cfg)
    app = create_app(config)
    runner = app.test_cli_runner()
    assert runner.invoke(args=["init-db"]).exit_code == 0
    return app


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path)


def teacher(app, email="lehrer@example.de"):
    r = app.test_cli_runner().invoke(
        args=["create-teacher"], input=f"Frau Lehrerin\n{email}\n{PW}\n{PW}\n")
    assert r.exit_code == 0, r.output


def login(client, email, pw=PW):
    return client.post("/login", data={"email": email, "passwort": pw})


def register(app, name, email):
    c = app.test_client()
    assert c.post("/registrieren", data={"name": name, "email": email, "passwort": PW}).status_code == 302
    login(c, email)
    return c


def zukunft(tage=3, stunde=15):
    d = datetime.now(TZ) + timedelta(days=tage)
    return d.strftime("%Y-%m-%d"), f"{stunde:02d}:00"


def neuer_termin(c, tage=3, stunde=15, fach="Mathe"):
    datum, zeit = zukunft(tage, stunde)
    return c.post("/lehrer/termine", data={"datum": datum, "zeit": zeit, "dauer": "60", "fach": fach})


def sql(app, query, args=()):
    db = sqlite3.connect(app.config["DATABASE"])
    try:
        return db.execute(query, args).fetchall()
    finally:
        db.commit()
        db.close()


@pytest.fixture
def szene(app):
    """Lehrer mit einem freien Termin, zwei Schüler."""
    teacher(app)
    t = app.test_client()
    login(t, "lehrer@example.de")
    assert neuer_termin(t).status_code == 302
    return app, t, register(app, "Anna", "anna@example.de"), register(app, "Ben", "ben@example.de")


# --- Start / Konfiguration ---------------------------------------------------

def test_ohne_secret_key_startet_app_nicht(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app({"DATABASE": str(tmp_path / "x.db")})


def test_header_und_cookie_flags(tmp_path):
    app = make_app(tmp_path, SESSION_COOKIE_SECURE=True)
    teacher(app)
    c = app.test_client()
    r = c.post("/login", data={"email": "lehrer@example.de", "passwort": PW}, base_url="https://localhost")
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie
    h = c.get("/login").headers
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in h["Content-Security-Policy"]


# --- Registrierung / Login ----------------------------------------------------

def test_registrierung_nur_schueler_und_hash(app):
    c = app.test_client()
    r = c.post("/registrieren", data={"name": "Anna", "email": "Anna@Example.de",
                                       "passwort": PW, "rolle": "lehrer"})
    assert r.status_code == 302
    rolle, pw_hash, email = sql(app, "SELECT rolle, passwort_hash, email FROM nutzer")[0]
    assert rolle == "schueler" and email == "anna@example.de"
    assert PW not in pw_hash and pw_hash.startswith(("scrypt:", "pbkdf2:"))


def test_registrierung_validierung(app):
    c = app.test_client()
    assert c.post("/registrieren", data={"name": "A", "email": "a@b.de", "passwort": "kurz"}).status_code == 400
    assert c.post("/registrieren", data={"name": "A", "email": "keine-mail", "passwort": PW}).status_code == 400
    c.post("/registrieren", data={"name": "A", "email": "a@b.de", "passwort": PW})
    assert c.post("/registrieren", data={"name": "B", "email": "A@B.de", "passwort": PW}).status_code == 400


def test_login_falsches_passwort_und_sql_zeichen(app):
    teacher(app)
    c = app.test_client()
    assert login(c, "lehrer@example.de", "falsch").status_code == 401
    assert login(c, "' OR 1=1 --", "x").status_code == 401
    assert login(c, "lehrer@example.de").status_code == 302


def test_cli_create_teacher_doppelt_und_kurzes_passwort(app):
    teacher(app)
    r = app.test_cli_runner().invoke(args=["create-teacher"], input=f"X\nlehrer@example.de\n{PW}\n{PW}\n")
    assert r.exit_code != 0
    r = app.test_cli_runner().invoke(args=["create-teacher"], input="X\nneu@example.de\nkurz\nkurz\n")
    assert r.exit_code != 0


def test_login_ratelimit(tmp_path):
    app = make_app(tmp_path, RATELIMIT_ENABLED=True)
    c = app.test_client()
    codes = [login(c, "x@y.de", "falsch").status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_csrf_schutz_aktiv(tmp_path):
    app = make_app(tmp_path, WTF_CSRF_ENABLED=True)
    c = app.test_client()
    assert c.post("/login", data={"email": "a@b.de", "passwort": "x"}).status_code == 400
    html = c.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    assert c.post("/login", data={"email": "a@b.de", "passwort": "x", "csrf_token": token}).status_code == 401


# --- Rollen -------------------------------------------------------------------

def test_rollenpruefung(szene):
    app, t, anna, ben = szene
    for url in ["/lehrer/termine", "/lehrer/anfragen", "/lehrer/schueler"]:
        assert anna.get(url).status_code == 403
        assert app.test_client().get(url).status_code == 302  # anonym -> Login
    assert anna.post("/lehrer/termine/1/loeschen").status_code == 403
    assert anna.post("/lehrer/buchungen/1/bestaetigen").status_code == 403
    assert anna.post("/lehrer/schueler/2/passwort", data={"passwort": PW}).status_code == 403
    assert t.get("/termine").status_code == 403  # Lehrer hat keine Schülerseite
    assert anna.get("/termine").status_code == 200


# --- Buchungsablauf -----------------------------------------------------------

def test_buchen_bestaetigen(szene):
    app, t, anna, ben = szene
    assert "Mathe" in anna.get("/termine").get_data(as_text=True)
    assert anna.post("/termine/1/buchen", data={"nachricht": "Bruchrechnen"}).status_code == 302
    assert sql(app, "SELECT status FROM termin") == [("angefragt",)]
    # für andere gesperrt
    assert "Mathe" not in ben.get("/termine").get_data(as_text=True)
    ben.post("/termine/1/buchen", data={})
    assert sql(app, "SELECT COUNT(*) FROM buchung") == [(1,)]
    # Posteingang + Zähler
    assert t.get("/api/benachrichtigungen").get_json()["count"] == 1
    inbox = t.get("/lehrer/anfragen").get_data(as_text=True)
    assert "Anna" in inbox and "Bruchrechnen" in inbox
    assert t.post("/lehrer/buchungen/1/bestaetigen").status_code == 302
    assert sql(app, "SELECT status FROM termin") == [("bestaetigt",)]
    assert "bestätigt" in anna.get("/buchungen").get_data(as_text=True)
    assert t.get("/api/benachrichtigungen").get_json()["count"] == 0
    # bestätigte Termine: nicht löschbar, nicht zurückziehbar
    t.post("/lehrer/termine/1/loeschen")
    assert sql(app, "SELECT COUNT(*) FROM termin") == [(1,)]
    anna.post("/buchungen/1/zurueckziehen")
    assert sql(app, "SELECT status FROM buchung") == [("bestaetigt",)]


def test_ablehnen_gibt_termin_frei_und_zeigt_grund(szene):
    app, t, anna, ben = szene
    anna.post("/termine/1/buchen", data={})
    # ohne Begründung wird nicht abgelehnt
    t.post("/lehrer/buchungen/1/ablehnen", data={"grund": " "})
    assert sql(app, "SELECT status FROM buchung") == [("angefragt",)]
    t.post("/lehrer/buchungen/1/ablehnen", data={"grund": "Da bin ich verreist"})
    assert sql(app, "SELECT status FROM termin") == [("frei",)]
    assert "Da bin ich verreist" in anna.get("/buchungen").get_data(as_text=True)
    # Termin ist wieder buchbar, auch für Ben
    ben.post("/termine/1/buchen", data={})
    assert sql(app, "SELECT status FROM buchung ORDER BY id") == [("abgelehnt",), ("angefragt",)]


def test_zurueckziehen_und_fremde_buchung(szene):
    app, t, anna, ben = szene
    anna.post("/termine/1/buchen", data={})
    ben.post("/buchungen/1/zurueckziehen")  # fremde Buchung: wirkungslos
    assert sql(app, "SELECT status FROM buchung") == [("angefragt",)]
    assert "Anna" not in ben.get("/buchungen").get_data(as_text=True)
    anna.post("/buchungen/1/zurueckziehen")
    assert sql(app, "SELECT status FROM buchung") == [("zurueckgezogen",)]
    assert sql(app, "SELECT status FROM termin") == [("frei",)]
    # Lehrer kann zurückgezogene Anfrage nicht mehr bestätigen
    t.post("/lehrer/buchungen/1/bestaetigen")
    assert sql(app, "SELECT status FROM termin") == [("frei",)]


def test_loeschen_nur_frei(szene):
    app, t, anna, ben = szene
    anna.post("/termine/1/buchen", data={})
    t.post("/lehrer/termine/1/loeschen")
    assert sql(app, "SELECT COUNT(*) FROM termin") == [(1,)]
    t.post("/lehrer/buchungen/1/ablehnen", data={"grund": "nein"})
    t.post("/lehrer/termine/1/loeschen")
    assert sql(app, "SELECT COUNT(*) FROM termin") == [(0,)]


def test_termin_validierung(szene):
    app, t, *_ = szene
    assert neuer_termin(t, tage=3, stunde=15).status_code == 400  # exakt gleicher Zeitpunkt
    datum, _ = zukunft(3)
    assert t.post("/lehrer/termine", data={"datum": datum, "zeit": "15:30", "dauer": "60", "fach": "X"}).status_code == 400  # Überschneidung
    assert t.post("/lehrer/termine", data={"datum": "2020-01-01", "zeit": "10:00", "dauer": "60", "fach": "X"}).status_code == 400  # Vergangenheit
    assert t.post("/lehrer/termine", data={"datum": datum, "zeit": "18:00", "dauer": "5", "fach": "X"}).status_code == 400


def test_html_wird_escaped(szene):
    app, t, anna, ben = szene
    anna.post("/termine/1/buchen", data={"nachricht": "<script>alert(1)</script>"})
    html = t.get("/lehrer/anfragen").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


# --- Doppelbuchung --------------------------------------------------------------

def test_unique_index_verhindert_zwei_aktive_buchungen(szene):
    app, *_ = szene
    db = sqlite3.connect(app.config["DATABASE"])
    ins = "INSERT INTO buchung (termin_id, schueler_id, status, erstellt_am) VALUES (1, ?, ?, 'x')"
    db.execute(ins, (2, "angefragt"))
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(ins, (3, "bestaetigt"))
    db.execute(ins, (3, "abgelehnt"))  # inaktive Buchungen sind beliebig oft erlaubt
    db.close()


def test_gleichzeitige_buchung_nur_eine_gewinnt(app):
    teacher(app)
    t = app.test_client()
    login(t, "lehrer@example.de")
    neuer_termin(t)
    clients = [register(app, f"S{i}", f"s{i}@example.de") for i in range(8)]
    start = threading.Barrier(len(clients))
    codes = []

    def los(c):
        start.wait()
        codes.append(c.post("/termine/1/buchen", data={"nachricht": "ich"}).status_code)

    threads = [threading.Thread(target=los, args=(c,)) for c in clients]
    [x.start() for x in threads]
    [x.join() for x in threads]
    assert sql(app, "SELECT COUNT(*) FROM buchung") == [(1,)]
    assert sql(app, "SELECT status FROM termin") == [("angefragt",)]


# --- Passwort zurücksetzen ------------------------------------------------------

def test_startpasswort_erzwingt_aenderung(szene):
    app, t, anna, ben = szene
    assert t.post("/lehrer/schueler/2/passwort", data={"passwort": "kurz"}).status_code == 302
    assert sql(app, "SELECT muss_passwort_aendern FROM nutzer WHERE id = 2") == [(0,)]
    t.post("/lehrer/schueler/2/passwort", data={"passwort": "startpasswort-1"})
    c = app.test_client()
    assert login(c, "anna@example.de").status_code == 401  # altes Passwort ungültig
    login(c, "anna@example.de", "startpasswort-1")
    r = c.get("/termine")
    assert r.status_code == 302 and "/passwort-aendern" in r.headers["Location"]
    c.post("/passwort-aendern", data={"alt": "startpasswort-1", "neu": "neues-passwort-2", "neu2": "neues-passwort-2"})
    assert c.get("/termine").status_code == 200
    # Lehrer-Konto lässt sich so nicht überschreiben
    assert t.post("/lehrer/schueler/1/passwort", data={"passwort": "startpasswort-1"}).status_code == 404
