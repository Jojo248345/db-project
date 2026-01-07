from flask import Flask, redirect, render_template, request, url_for, session
from dotenv import load_dotenv
import os
import git
import hmac
import hashlib
from db import db_read, db_write
from auth import login_manager, authenticate, register_user
from flask_login import login_user, logout_user, login_required, current_user
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# Load .env variables
load_dotenv()
W_SECRET = os.getenv("W_SECRET")

# Init flask app
app = Flask(__name__)
app.config["DEBUG"] = True
app.secret_key = "supersecret"

# Init auth
login_manager.init_app(app)
login_manager.login_view = "login"

# DON'T CHANGE
def is_valid_signature(x_hub_signature, data, private_key):
    hash_algorithm, github_signature = x_hub_signature.split('=', 1)
    algorithm = hashlib.__dict__.get(hash_algorithm)
    encoded_key = bytes(private_key, 'latin-1')
    mac = hmac.new(encoded_key, msg=data, digestmod=algorithm)
    return hmac.compare_digest(mac.hexdigest(), github_signature)

# DON'T CHANGE
@app.post('/update_server')
def webhook():
    x_hub_signature = request.headers.get('X-Hub-Signature')
    if is_valid_signature(x_hub_signature, request.data, W_SECRET):
        repo = git.Repo('./mysite')
        origin = repo.remotes.origin
        origin.pull()
        return 'Updated PythonAnywhere successfully', 200
    return 'Unathorized', 401

# Auth routes
'''@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        user = authenticate(
            request.form["username"],
            request.form["password"]
        )

        if user:
            login_user(user)
            return redirect(url_for("index"))

        error = "Benutzername oder Passwort ist falsch."

    return render_template(
        "auth.html",
        title="In dein Konto einloggen",
        action=url_for("login"),
        button_label="Einloggen",
        error=error,
        footer_text="Noch kein Konto?",
        footer_link_url=url_for("register"),
        footer_link_label="Registrieren"
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        ok = register_user(username, password)
        if ok:
            return redirect(url_for("login"))

        error = "Benutzername existiert bereits."

    return render_template(
        "auth.html",
        title="Neues Konto erstellen",
        action=url_for("register"),
        button_label="Registrieren",
        error=error,
        footer_text="Du hast bereits ein Konto?",
        footer_link_url=url_for("login"),
        footer_link_label="Einloggen"
    )

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))



@app.route("/produkt-neu", methods=["GET", "POST"])
def produkt_neu():

    # GET → Formular anzeigen
    if request.method == "GET":
        rezepte = db_read("SELECT * FROM Rezept")
        return render_template("produkt_neu.html", rezepte=rezepte)

    # POST → Produkt speichern
    name = request.form["name"]
    preis = request.form["preis"]
    rezept_id = request.form["rezept_id"]

    db_write(
        "INSERT INTO Produkte (Produkt_Name, Produkt_Preis_CHF, Rezept_id) VALUES (%s, %s, %s)",
        (name, preis, rezept_id)
    )

    return "✅ Produkt wurde erfolgreich gespeichert!"









# 1️⃣ Produkte anzeigen
@app.route("/produkte")
def produkte():
    produkte = db_read("SELECT * FROM Produkte")
    return render_template("produkte.html", produkte=produkte)


# 2️⃣ Produkt in Warenkorb
@app.post("/warenkorb")

def warenkorb_add():
    produkt_id = request.form["produkt_id"]

    if "warenkorb" not in session:
        session["warenkorb"] = []

    session["warenkorb"].append(int(produkt_id))
    return redirect("/produkte")


# 3️⃣ Drohne auswählen
@app.route("/drohne", methods=["GET", "POST"])

def drohne():
    if request.method == "GET":
        drohnen = db_read("SELECT * FROM Drohnen WHERE Drohnen_beschaeftigt = 0")
        return render_template("drohne.html", drohnen=drohnen)

    session["drohnen_id"] = request.form["drohnen_id"]
    return redirect("/bezahlen")


# 4️⃣ Bezahlen (SIMULIERT)
@app.route("/bezahlen", methods=["GET", "POST"])
def bezahlen():
    if request.method == "GET":
        return render_template("bezahlen.html")

    # Bestellung speichern (sehr einfach)
    db_write(
        "INSERT INTO Bestellung (Kunden_id, Drohnen_id, Gesamtpreis_CHF) VALUES (%s, %s, %s)",
        (current_user.id, session["drohnen_id"], 20.00)
    )

    session.pop("warenkorb", None)
    return "✅ Bestellung abgeschlossen!" '''

@app.route("/")
def index():
    return render_template("index.html")





# --- LOGIN & REGISTER ---

'''@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = authenticate(
            request.form["username"], 
            request.form["password"], 
            request.form.get("role", "kunde")
        )
        if user:
            login_user(user)
            return redirect(url_for("index"))
        error = "Falscher Name oder Passwort!"

    return render_template("auth.html", title="Login", action="/login", button_label="Anmelden", error=error, is_register=False)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        ok = register_user(
            request.form["username"], 
            request.form["password"], 
            request.form["name"], 
            request.form["adresse"]
        )
        if ok:
            return redirect(url_for("login"))
        error = "Name schon vergeben!"

    return render_template("auth.html", title="Registrieren", action="/register", button_label="Erstellen", error=error, is_register=True)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# --- MITARBEITER (Zeigt 'produkt_neu.html' & 'drohne_neu.html') ---

@app.route("/produkt-neu", methods=["GET", "POST"])
@login_required
def produkt_neu():
    if current_user.role != 'mitarbeiter': return "Verboten!"

    if request.method == "GET":
        return render_template("produkt_neu.html")

    # 1. Rezept speichern
    rezept_id = db_write(
        "INSERT INTO Rezept (Mehl_g, Zucker_g, Schokolade_g, Wasser_ml, Milch_ml, Butter_g, Eier_stk, Salz_g) VALUES (%s, %s, %s, 0, 0, 0, 0, 0)",
        (request.form["mehl"], request.form["zucker"], request.form["schoko"])
    )
    # 2. Produkt speichern
    db_write(
        "INSERT INTO Produkte (Produkt_Name, Produkt_Preis_CHF, Rezept_id) VALUES (%s, %s, %s)",
        (request.form["name"], request.form["preis"], rezept_id)
    )
    return "✅ Produkt gespeichert! <a href='/'>Zurück</a>"

@app.route("/drohne-neu", methods=["GET", "POST"])
@login_required
def drohne_neu():
    if current_user.role != 'mitarbeiter': return "Verboten!"
    
    if request.method == "POST":
        db_write(
            "INSERT INTO Drohnen (Drohnen_Name, Drohnen_Geschwindigkeit_kmh, Drohnen_Preis_CHF, Drohnen_beschaeftigt) VALUES (%s, %s, %s, 0)",
            (request.form["name"], request.form["speed"], request.form["preis"])
        )
        return "✅ Drohne gespeichert! <a href='/'>Zurück</a>"
    
    return render_template("drohne_neu.html")

@app.route("/produkt-loeschen/<int:id>")
@login_required
def produkt_loeschen(id):
    if current_user.role != 'mitarbeiter': return "Verboten!"
    db_write("DELETE FROM Produkte WHERE Produkt_id = %s", (id,))
    return redirect("/produkte")


# --- KUNDEN (Zeigt 'produkte.html', 'drohne.html', 'bezahlen.html') ---

@app.route("/produkte")
def produkte():
    daten = db_read("SELECT * FROM Produkte")
    return render_template("produkte.html", produkte=daten)

@app.route("/warenkorb", methods=["POST"])
@login_required
def warenkorb_add():
    # Speichert Produkt temporär
    session["warenkorb_id"] = request.form["produkt_id"]
    session["warenkorb_name"] = request.form["produkt_name"]
    session["warenkorb_preis"] = float(request.form["produkt_preis"])
    return redirect("/drohne")

@app.route("/drohne", methods=["GET", "POST"])
@login_required
def drohne():
    if request.method == "GET":
        # Nur freie Drohnen laden
        daten = db_read("SELECT * FROM Drohnen WHERE Drohnen_beschaeftigt = 0")
        return render_template("drohne.html", drohnen=daten)

    # Speichert Drohnen-Wahl
    session["drohne_id"] = request.form["drohnen_id"]
    session["drohne_preis"] = float(request.form["drohne_preis"])
    return redirect("/bezahlen")

@app.route("/bezahlen", methods=["GET", "POST"])
@login_required
def bezahlen():
    total = session.get("warenkorb_preis", 0) + session.get("drohne_preis", 0)

    if request.method == "GET":
        return render_template("bezahlen.html", total=total)

    # Bestellung abschicken
    kunden_id = current_user.id.split("-")[1]
    db_write("INSERT INTO Bestellung (Kunden_id, Drohnen_id, Bestell_Datum, Gesamtpreis_CHF, Status) VALUES (%s, %s, NOW(), %s, 'Bezahlt')",
             (kunden_id, session["drohne_id"], total))
    
    # Drohne auf 'beschäftigt' setzen
    db_write("UPDATE Drohnen SET Drohnen_beschaeftigt = 1 WHERE Drohnen_id = %s", (session["drohne_id"],))
    
    session.pop("warenkorb_id", None) # Warenkorb leeren
    return "✅ Bestellt! <a href='/'>Home</a>"

if __name__ == "__main__":
    app.run()'''

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = authenticate(
            request.form["username"], 
            request.form["password"], 
            request.form.get("role", "kunde")
        )
        if user:
            login_user(user)
            return redirect(url_for("index"))
        error = "Falscher Name oder Passwort!"

    return render_template("auth.html", title="Login", action="/login", button_label="Anmelden", error=error, is_register=False)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        ok = register_user(
            request.form["username"], 
            request.form["password"], 
            request.form["name"], 
            request.form["adresse"]
        )
        if ok:
            return redirect(url_for("login"))
        error = "Name schon vergeben!"

    return render_template("auth.html", title="Registrieren", action="/register", button_label="Erstellen", error=error, is_register=True)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# --- MITARBEITER ---

@app.route("/produkt-neu", methods=["GET", "POST"])
@login_required
def produkt_neu():
    if current_user.role != 'mitarbeiter': return "Verboten!"

    if request.method == "GET":
        return render_template("produkt_neu.html")

    # UPDATE: Hier lesen wir jetzt ALLE Zutaten aus dem Formular
    # Wir nutzen 'or 0', damit leere Felder als 0 gespeichert werden und nicht crashen
    mehl = request.form.get("mehl") or 0
    wasser = request.form.get("wasser") or 0
    butter = request.form.get("butter") or 0
    milch = request.form.get("milch") or 0
    eier = request.form.get("eier") or 0
    zucker = request.form.get("zucker") or 0
    salz = request.form.get("salz") or 0
    schoko = request.form.get("schoko") or 0

    # 1. Rezept speichern (mit allen Spalten)
    sql_rezept = """
        INSERT INTO Rezept (Mehl_g, Wasser_ml, Butter_g, Milch_ml, Eier_stk, Zucker_g, Salz_g, Schokolade_g) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    rezept_id = db_write(sql_rezept, (mehl, wasser, butter, milch, eier, zucker, salz, schoko))

    # 2. Produkt speichern
    db_write(
        "INSERT INTO Produkte (Produkt_Name, Produkt_Preis_CHF, Rezept_id) VALUES (%s, %s, %s)",
        (request.form["name"], request.form["preis"], rezept_id)
    )
    return "✅ Produkt erfolgreich mit Rezept gespeichert! <a href='/'>Zurück</a>"

@app.route("/produkt-loeschen/<int:id>")
@login_required
def produkt_loeschen(id):
    if current_user.role != 'mitarbeiter': return "Verboten!"
    db_write("DELETE FROM Produkte WHERE Produkt_id = %s", (id,))
    return redirect("/produkte")


# --- DROHNEN VERWALTUNG (NEU) ---

@app.route("/drohne-neu", methods=["GET", "POST"])
@login_required
def drohne_neu():
    if current_user.role != 'mitarbeiter': return "Verboten!"
    
    # Wenn Formular gesendet (POST) -> Speichern
    if request.method == "POST":
        db_write(
            "INSERT INTO Drohnen (Drohnen_Name, Drohnen_Geschwindigkeit_kmh, Drohnen_Preis_CHF, Drohnen_beschaeftigt) VALUES (%s, %s, %s, 0)",
            (request.form["name"], request.form["speed"], request.form["preis"])
        )
        return redirect(url_for('drohne_neu')) # Seite neu laden damit die neue Drohne erscheint
    
    # Immer (GET): Liste aller Drohnen laden und anzeigen
    drohnen_liste = db_read("SELECT * FROM Drohnen")
    return render_template("drohne_neu.html", drohnen=drohnen_liste)

@app.route("/drohne-loeschen/<int:id>")
@login_required
def drohne_loeschen(id):
    if current_user.role != 'mitarbeiter': return "Verboten!"
    
    # Drohne löschen
    db_write("DELETE FROM Drohnen WHERE Drohnen_id = %s", (id,))
    return redirect(url_for('drohne_neu'))

@app.route("/drohne-reset/<int:id>")
@login_required
def drohne_reset(id):
    if current_user.role != 'mitarbeiter': return "Verboten!"
    
    # Setze 'Drohnen_beschaeftigt' auf 0 (False)
    db_write("UPDATE Drohnen SET Drohnen_beschaeftigt = 0 WHERE Drohnen_id = %s", (id,))
    return redirect(url_for('drohne_neu'))


# --- KUNDEN ---

@app.route("/produkte")
def produkte():
    daten = db_read("SELECT * FROM Produkte")
    return render_template("produkte.html", produkte=daten)

@app.route("/warenkorb", methods=["POST"])
@login_required
def warenkorb_add():
    session["warenkorb_id"] = request.form["produkt_id"]
    session["warenkorb_name"] = request.form["produkt_name"]
    session["warenkorb_preis"] = float(request.form["produkt_preis"])
    return redirect("/drohne")

@app.route("/drohne", methods=["GET", "POST"])
@login_required
def drohne():
    if request.method == "GET":
        daten = db_read("SELECT * FROM Drohnen WHERE Drohnen_beschaeftigt = 0")
        return render_template("drohne.html", drohnen=daten)

    session["drohne_id"] = request.form["drohnen_id"]
    session["drohne_preis"] = float(request.form["drohne_preis"])
    return redirect("/bezahlen")

@app.route("/bezahlen", methods=["GET", "POST"])
@login_required
def bezahlen():
    total = session.get("warenkorb_preis", 0) + session.get("drohne_preis", 0)

    if request.method == "GET":
        return render_template("bezahlen.html", total=total)

    kunden_id = current_user.id.split("-")[1]
    db_write("INSERT INTO Bestellung (Kunden_id, Drohnen_id, Bestell_Datum, Gesamtpreis_CHF, Status) VALUES (%s, %s, NOW(), %s, 'Bezahlt')",
             (kunden_id, session["drohne_id"], total))
    
    db_write("UPDATE Drohnen SET Drohnen_beschaeftigt = 1 WHERE Drohnen_id = %s", (session["drohne_id"],))
    
    session.pop("warenkorb_id", None)
    return "✅ Bestellt! <a href='/'>Home</a>"

if __name__ == "__main__":
    app.run()