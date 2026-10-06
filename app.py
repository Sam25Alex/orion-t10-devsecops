"""
Application de démonstration — Projet T10 (Laboratoire ORION / ISTIN)
========================================================================
Petite application web Flask volontairement vulnérable, utilisée comme
support expérimental pour le projet « Développement web sécurisé et
DevSecOps ».

Trois vulnérabilités du Top 10 OWASP y sont introduites DÉLIBÉRÉMENT,
chacune clairement annotée dans le code par un bloc de commentaires
"VULNÉRABILITÉ OWASP ...". Elles serviront de cibles pour le pipeline
CI/CD (SAST / DAST / SCA) construit à l'étape suivante du projet.

NE JAMAIS déployer ce code tel quel sur un serveur exposé à Internet.
"""

import sqlite3
import hashlib
from flask import Flask, request, render_template, redirect, url_for, session, g

app = Flask(__name__)
app.secret_key = "dev-secret-key"  # clé fixe en dur : acceptable ici (démo locale), à corriger en prod

DATABASE = "app.db"


# -------------------------------------------------------------------------
# Connexion à la base de données SQLite
# -------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS comments;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content TEXT NOT NULL
        );
        """
    )
    # Utilisateur de démonstration (mot de passe volontairement faible : "admin123")
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("admin", hash_password_weak("admin123")),
    )
    db.commit()
    db.close()


# -------------------------------------------------------------------------
# VULNÉRABILITÉ OWASP A02:2021 — Cryptographic Failures
# -------------------------------------------------------------------------
# Le mot de passe est haché avec MD5, un algorithme obsolète et rapide à
# casser par force brute / tables arc-en-ciel. Aucun "sel" (salt) n'est
# utilisé. Un algorithme adapté serait bcrypt, scrypt ou Argon2.
def hash_password_weak(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# -------------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    comments = db.execute("SELECT username, content FROM comments ORDER BY id DESC").fetchall()
    return render_template("index.html", comments=comments, user=session.get("username"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hash_password_weak(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Ce nom d'utilisateur existe déjà.")
        return redirect(url_for("login"))
    return render_template("register.html")


# -------------------------------------------------------------------------
# VULNÉRABILITÉ OWASP A03:2021 — Injection (SQL Injection)
# -------------------------------------------------------------------------
# La requête SQL est construite par concaténation directe de chaînes à
# partir d'une entrée utilisateur non filtrée (f-string). Un attaquant
# peut injecter du SQL arbitraire, par exemple avec le login :
#   admin' OR '1'='1
# pour contourner l'authentification sans connaître le mot de passe.
# Le correctif attendu est l'utilisation de requêtes paramétrées (comme
# c'est déjà fait correctement dans register() ci-dessus).
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed = hash_password_weak(password)

        db = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"
        user = db.execute(query).fetchone()

        if user:
            session["username"] = user["username"]
            return redirect(url_for("index"))
        return render_template("login.html", error="Identifiants incorrects.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


# -------------------------------------------------------------------------
# VULNÉRABILITÉ OWASP A03:2021 — Injection (Cross-Site Scripting stocké)
# -------------------------------------------------------------------------
# Le contenu du commentaire est affiché dans le template avec le filtre
# Jinja2 "|safe", qui désactive l'échappement HTML automatique. Un
# attaquant peut poster un commentaire contenant une balise <script>,
# qui s'exécutera dans le navigateur de chaque visiteur consultant la
# page d'accueil (XSS stocké / persistant).
# Le correctif attendu est de retirer le filtre "|safe" et de laisser
# Jinja2 échapper le contenu par défaut.
@app.route("/comment", methods=["POST"])
def comment():
    if "username" not in session:
        return redirect(url_for("login"))
    content = request.form["content"]
    db = get_db()
    db.execute(
        "INSERT INTO comments (username, content) VALUES (?, ?)",
        (session["username"], content),
    )
    db.commit()
    return redirect(url_for("index"))


if __name__ == "__main__":
    import os

    if not os.path.exists(DATABASE):
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
