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
import threading
import time

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




@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        # Einfacher Aufruf in einer Zeile
        user = authenticate(request.form["username"], request.form["password"], request.form.get("role", "kunde"))
        if user:
            login_user(user)
            return redirect(url_for("index"))
        error = "Falscher Name oder Passwort!"
    return render_template("auth.html", title="Login", action="/login", button_label="Anmelden", error=error, is_register=False)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        if register_user(request.form["username"], request.form["password"], request.form["name"], request.form["adresse"]):
            return redirect(url_for("login"))
        error = "Name schon vergeben!"
    return render_template("auth.html", title="Registrieren", action="/register", button_label="Erstellen", error=error, is_register=True)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# --- MITARBEITER FUNKTIONEN ---

@app.route("/produkt-neu", methods=["GET", "POST"])
@login_required
def produkt_neu():
    if current_user.role != 'mitarbeiter': return "Verboten!"
    
    if request.method == "GET":
        return render_template("produkt_neu.html")

    # Werte holen (kurz und bündig)
    mehl = request.form.get("mehl") or 0
    wasser = request.form.get("wasser") or 0
    butter = request.form.get("butter") or 0
    milch = request.form.get("milch") or 0
    eier = request.form.get("eier") or 0
    zucker = request.form.get("zucker") or 0
    salz = request.form.get("salz") or 0
    schoko = request.form.get("schoko") or 0

    # 1. Rezept speichern
    sql = "INSERT INTO Rezept (Mehl_g, Wasser_ml, Butter_g, Milch_ml, Eier_stk, Zucker_g, Salz_g, Schokolade_g) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
    rezept_id = db_write(sql, (mehl, wasser, butter, milch, eier, zucker, salz, schoko))

    # 2. Produkt speichern
    db_write("INSERT INTO Produkte (Produkt_Name, Produkt_Preis_CHF, Rezept_id) VALUES (%s, %s, %s)", 
             (request.form["name"], request.form["preis"], rezept_id))
    
    return "✅ Produkt erfolgreich mit Rezept gespeichert! <a href='/'>Zurück</a>"

@app.route("/produkt-loeschen/<int:id>")
@login_required
def produkt_loeschen(id):
    if current_user.role != 'mitarbeiter': return "Verboten!"
    db_write("DELETE FROM Produkte WHERE Produkt_id = %s", (id,))
    return redirect("/produkte")


# --- DROHNEN VERWALTUNG ---

@app.route("/drohne-neu", methods=["GET", "POST"])
@login_required
def drohne_neu():
    if current_user.role != 'mitarbeiter': return "Verboten!"

    if request.method == "POST":
        sql = "INSERT INTO Drohnen (Drohnen_Name, Drohnen_Geschwindigkeit_kmh, Drohnen_Preis_CHF, Drohnen_beschaeftigt) VALUES (%s, %s, %s, 0)"
        db_write(sql, (request.form["name"], request.form["speed"], request.form["preis"]))
        return redirect(url_for('drohne_neu'))
    
    return render_template("drohne_neu.html", drohnen=db_read("SELECT * FROM Drohnen"))

@app.route("/drohne-loeschen/<int:id>")
@login_required
def drohne_loeschen(id):
    if current_user.role != 'mitarbeiter': return "Verboten!"
    db_write("DELETE FROM Drohnen WHERE Drohnen_id = %s", (id,))
    return redirect(url_for('drohne_neu'))

@app.route("/drohne-reset/<int:id>")
@login_required
def drohne_reset(id):
    if current_user.role != 'mitarbeiter': return "Verboten!"
    db_write("UPDATE Drohnen SET Drohnen_beschaeftigt = 0 WHERE Drohnen_id = %s", (id,))
    return redirect(url_for('drohne_neu'))


# --- KUNDEN & BESTELLUNG ---

@app.route("/produkte")
def produkte():
    return render_template("produkte.html", produkte=db_read("SELECT * FROM Produkte"))

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
        return render_template("drohne.html", drohnen=db_read("SELECT * FROM Drohnen WHERE Drohnen_beschaeftigt = 0"))

    session["drohne_id"] = request.form["drohnen_id"]
    session["drohne_preis"] = float(request.form["drohne_preis"])
    return redirect("/bezahlen")


# --- HINTERGRUND PROZESS ---

def drohne_automatisch_freigeben(drohnen_id):
    time.sleep(60) # Original Code gelassen (60s Sleep, obwohl 10s im Kommentar stand)
    print(f"⏳ Drohne {drohnen_id} wird freigegeben...")
    db_write("UPDATE Drohnen SET Drohnen_beschaeftigt = 0 WHERE Drohnen_id = %s", (drohnen_id,))
    print(f"✅ Drohne {drohnen_id} ist wieder bereit!")

@app.route("/bezahlen", methods=["GET", "POST"])
@login_required
def bezahlen():
    total = session.get("warenkorb_preis", 0) + session.get("drohne_preis", 0)

    if request.method == "GET":
        return render_template("bezahlen.html", total=total)

    kunden_id = current_user.id.split("-")[1]
    drohnen_id = session["drohne_id"]

    # 1. Bestellung speichern
    db_write("INSERT INTO Bestellung (Kunden_id, Drohnen_id, Bestell_Datum, Gesamtpreis_CHF, Status) VALUES (%s, %s, NOW(), %s, 'Bezahlt')",
             (kunden_id, drohnen_id, total))
    
    # 2. Drohne blockieren & Timer starten
    db_write("UPDATE Drohnen SET Drohnen_beschaeftigt = 1 WHERE Drohnen_id = %s", (drohnen_id,))
    threading.Thread(target=drohne_automatisch_freigeben, args=(drohnen_id,)).start()
    
    # 3. Session aufräumen
    session.pop("warenkorb_id", None)
    
    return "✅ Bestellt! Die Drohne liefert jetzt aus und kommt gleich zurück. <a href='/'>Home</a>"