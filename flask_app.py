from flask import Flask, redirect, render_template, request, url_for
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
@app.route("/login", methods=["GET", "POST"])
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



'''@app.route("/produkt-neu", methods=["GET", "POST"])
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

    return "✅ Produkt wurde erfolgreich gespeichert!"'''

@app.route("/produkt-neu", methods=["GET", "POST"])
@login_required
def produkt_neu():
    success = False

    if request.method == "POST":
        db_write(
            "INSERT INTO Produkte (Produkt_Name, Produkt_Preis_CHF, Rezept_id) VALUES (%s, %s, %s)",
            (
                request.form["name"],
                request.form["preis"],
                request.form["rezept_id"]
            )
        )
        success = True

    rezepte = db_read("SELECT Rezept_id FROM Rezept")
    produkte = db_read("SELECT Produkt_Name, Produkt_Preis_CHF, Rezept_id FROM Produkte")

    return render_template(
        "produkt_neu.html",
        success=success,
        rezepte=rezepte,
        produkte=produkte
    )







# 1️⃣ Produkte anzeigen
@app.route("/produkte")
@login_required
def produkte():
    produkte = db_read("SELECT * FROM Produkte")
    return render_template("produkte.html", produkte=produkte)


# 2️⃣ Produkt in Warenkorb
@app.post("/warenkorb/add")
@login_required
def warenkorb_add():
    produkt_id = request.form["produkt_id"]

    if "warenkorb" not in session:
        session["warenkorb"] = []

    session["warenkorb"].append(int(produkt_id))
    return redirect("/produkte")


# 3️⃣ Drohne auswählen
@app.route("/drohne", methods=["GET", "POST"])
@login_required
def drohne():
    if request.method == "GET":
        drohnen = db_read("SELECT * FROM Drohnen WHERE Drohnen_beschaeftigt = 0")
        return render_template("drohne.html", drohnen=drohnen)

    session["drohnen_id"] = request.form["drohnen_id"]
    return redirect("/bezahlen")


# 4️⃣ Bezahlen (SIMULIERT)
@app.route("/bezahlen", methods=["GET", "POST"])
@login_required
def bezahlen():
    if request.method == "GET":
        return render_template("bezahlen.html")

    # Bestellung speichern (sehr einfach)
    db_write(
        "INSERT INTO Bestellung (Kunden_id, Drohnen_id, Gesamtpreis_CHF) VALUES (%s, %s, %s)",
        (current_user.id, session["drohnen_id"], 20.00)
    )

    session.pop("warenkorb", None)
    return "✅ Bestellung abgeschlossen!"


