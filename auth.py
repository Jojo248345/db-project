'''import logging
from flask_login import LoginManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from db import db_read, db_write

# Logger für dieses Modul
logger = logging.getLogger(__name__)

login_manager = LoginManager()


class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    @staticmethod
    def get_by_id(user_id):
        logger.debug("User.get_by_id() aufgerufen mit user_id=%s", user_id)
        try:
            row = db_read(
                "SELECT * FROM users WHERE id = %s",
                (user_id,),
                single=True
            )
            logger.debug("User.get_by_id() DB-Ergebnis: %r", row)
        except Exception:
            logger.exception("Fehler bei User.get_by_id(%s)", user_id)
            return None

        if row:
            return User(row["id"], row["username"], row["password"])
        else:
            logger.warning("User.get_by_id(): kein User mit id=%s gefunden", user_id)
            return None

    @staticmethod
    def get_by_username(username):
        logger.debug("User.get_by_username() aufgerufen mit username=%s", username)
        try:
            row = db_read(
                "SELECT * FROM users WHERE username = %s",
                (username,),
                single=True
            )
            logger.debug("User.get_by_username() DB-Ergebnis: %r", row)
        except Exception:
            logger.exception("Fehler bei User.get_by_username(%s)", username)
            return None

        if row:
            return User(row["id"], row["username"], row["password"])
        else:
            logger.info("User.get_by_username(): kein User mit username=%s", username)
            return None


# Flask-Login
@login_manager.user_loader
def load_user(user_id):
    logger.debug("load_user() aufgerufen mit user_id=%s", user_id)
    try:
        user = User.get_by_id(int(user_id))
    except ValueError:
        logger.error("load_user(): user_id=%r ist keine int", user_id)
        return None

    if user:
        logger.debug("load_user(): User gefunden: %s (id=%s)", user.username, user.id)
    else:
        logger.warning("load_user(): kein User für id=%s gefunden", user_id)

    return user


# Helpers
def register_user(username, password):
    logger.info("register_user(): versuche neuen User '%s' anzulegen", username)

    existing = User.get_by_username(username)
    if existing:
        logger.warning("register_user(): Username '%s' existiert bereits", username)
        return False

    hashed = generate_password_hash(password)
    try:
        db_write(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hashed)
        )
        logger.info("register_user(): User '%s' erfolgreich angelegt", username)
    except Exception:
        logger.exception("Fehler beim Anlegen von User '%s'", username)
        return False

    return True


def authenticate(username, password):
    logger.info("authenticate(): Login-Versuch für '%s'", username)
    user = User.get_by_username(username)

    if not user:
        logger.warning("authenticate(): kein User mit username='%s' gefunden", username)
        return None

    if check_password_hash(user.password, password):
        logger.info("authenticate(): Passwort korrekt für '%s'", username)
        return user

    logger.warning("authenticate(): falsches Passwort für '%s'", username)
    return None'''
from flask_login import LoginManager, UserMixin
from db import db_read, db_write

login_manager = LoginManager()

# Die Benutzer-Klasse
# Sie speichert temporär, wer gerade eingeloggt ist (Kunde oder Mitarbeiter)
class User(UserMixin):
    def __init__(self, id, role, name):
        self.id = id      # Die ID, z.B. "K-1" oder "M-2"
        self.role = role  # "kunde" oder "mitarbeiter"
        self.name = name

# Flask ruft diese Funktion bei JEDEM Seitenaufruf auf
# Sie lädt den User anhand der ID aus der Datenbank nach
@login_manager.user_loader
def load_user(user_id):
    parts = user_id.split('-') # Teilt "K-1" in ["K", "1"]
    typ = parts[0]
    db_id = parts[1]
    
    if typ == 'K': # Kunde
        res = db_read("SELECT * FROM Kunden WHERE Kunden_id = %s", (db_id,))
        if res: return User(user_id, 'kunde', res[0]['Kunden_Benutzername'])
        
    elif typ == 'M': # Mitarbeiter
        res = db_read("SELECT * FROM MitarbeiterInnen WHERE MitarbeiterInnen_id = %s", (db_id,))
        if res: return User(user_id, 'mitarbeiter', res[0]['MitarbeiterInnen_Name'])
        
    return None

# Diese Funktion wird NUR beim Klick auf "Login" aufgerufen
# Sie prüft Benutzername und Passwort
def authenticate(username, password, role):
    if role == 'kunde':
        # Prüfen ob Name UND Passwort stimmen
        res = db_read("SELECT * FROM Kunden WHERE Kunden_Benutzername = %s AND Kunden_password = %s", (username, password))
        if res: 
            return User(f"K-{res[0]['Kunden_id']}", 'kunde', res[0]['Kunden_Benutzername'])
    
    elif role == 'mitarbeiter':
        # Nur Name prüfen (Mitarbeiter haben kein Passwort in deiner Tabelle)
        # WICHTIG: Hier muss der Spaltenname stimmen!
        res = db_read("SELECT * FROM MitarbeiterInnen WHERE MitarbeiterInnen_Name = %s", (username,))
        if res: 
            return User(f"M-{res[0]['MitarbeiterInnen_id']}", 'mitarbeiter', res[0]['MitarbeiterInnen_Name'])
            
    return None

# Diese Funktion wird beim Registrieren aufgerufen
def register_user(username, password, name, adresse):
    # Gibt es den Namen schon?
    exists = db_read("SELECT * FROM Kunden WHERE Kunden_Benutzername = %s", (username,))
    if exists: return False
    
    # Speichern
    db_write(
        "INSERT INTO Kunden (Kunden_Benutzername, Kunden_password, Kunden_Name, Kunden_Vorname, Kunden_Adresse) VALUES (%s, %s, %s, 'Neu', %s)", 
        (username, password, name, adresse)
    )
    return True