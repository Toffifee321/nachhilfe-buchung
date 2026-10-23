-- Schema für Nachhilfe-Buchung. Idempotent (IF NOT EXISTS), löscht nie Daten.
-- Zeiten sind lokale Zeit Europe/Berlin als Text 'YYYY-MM-DD HH:MM'.

CREATE TABLE IF NOT EXISTS nutzer (
    id                    INTEGER PRIMARY KEY,
    name                  TEXT    NOT NULL,
    email                 TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    passwort_hash         TEXT    NOT NULL,
    rolle                 TEXT    NOT NULL CHECK (rolle IN ('schueler', 'lehrer')),
    muss_passwort_aendern INTEGER NOT NULL DEFAULT 0 CHECK (muss_passwort_aendern IN (0, 1)),
    erstellt_am           TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS termin (
    id         INTEGER PRIMARY KEY,
    lehrer_id  INTEGER NOT NULL REFERENCES nutzer (id),
    start      TEXT    NOT NULL,
    dauer_min  INTEGER NOT NULL CHECK (dauer_min BETWEEN 15 AND 240),
    fach       TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'frei' CHECK (status IN ('frei', 'angefragt', 'bestaetigt')),
    UNIQUE (lehrer_id, start)
);

CREATE TABLE IF NOT EXISTS buchung (
    id               INTEGER PRIMARY KEY,
    termin_id        INTEGER NOT NULL REFERENCES termin (id) ON DELETE CASCADE,
    schueler_id      INTEGER NOT NULL REFERENCES nutzer (id),
    nachricht        TEXT    NOT NULL DEFAULT '',
    ablehnungsgrund  TEXT,
    status           TEXT    NOT NULL DEFAULT 'angefragt'
                     CHECK (status IN ('angefragt', 'bestaetigt', 'abgelehnt', 'zurueckgezogen')),
    erstellt_am      TEXT    NOT NULL
);

-- Doppelbuchungs-Schutz in der Datenbank: pro Termin höchstens EINE aktive Buchung.
CREATE UNIQUE INDEX IF NOT EXISTS buchung_ein_aktiver_je_termin
    ON buchung (termin_id) WHERE status IN ('angefragt', 'bestaetigt');

CREATE INDEX IF NOT EXISTS buchung_schueler ON buchung (schueler_id);
CREATE INDEX IF NOT EXISTS termin_start ON termin (start);
