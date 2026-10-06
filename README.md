# ORION — Démo DevSecOps (Thème T10)

Application Flask minimale, volontairement vulnérable, servant de support
expérimental au projet de fin de cycle « Développement web sécurisé et
DevSecOps ».

## Lancer l'application en local

```bash
python -m venv venv
# Windows : venv\Scripts\activate
# Linux/Mac : source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Puis ouvrir http://127.0.0.1:5000 dans le navigateur.
Compte de démonstration : `admin` / `admin123`

## Lancer avec Docker

```bash
docker build -t orion-webapp .
docker run -p 5000:5000 orion-webapp
```

## Les 3 vulnérabilités volontairement introduites

| # | Fichier | Catégorie OWASP | Description |
|---|---------|------------------|--------------|
| 1 | `app.py`, route `/login` | A03:2021 — Injection | Requête SQL construite par concaténation de chaînes (f-string). Contournement possible avec `admin' OR '1'='1` comme nom d'utilisateur. |
| 2 | `app.py`, fonction `hash_password_weak` | A02:2021 — Cryptographic Failures | Mot de passe haché avec MD5 sans sel, algorithme obsolète et cassable par force brute / rainbow tables. |
| 3 | `templates/index.html` | A03:2021 — Injection (XSS stocké) | Le filtre Jinja2 `\|safe` désactive l'échappement HTML automatique sur le contenu des commentaires, permettant l'exécution de JavaScript arbitraire. |

Chaque vulnérabilité est annotée directement dans le code source par un
bloc de commentaires `VULNÉRABILITÉ OWASP ...`, pour faciliter leur
repérage lors de la démonstration devant le jury et leur détection par
les outils SAST (Bandit, Semgrep) à l'étape suivante du projet.

## Tests manuels effectués (validés)

- Connexion normale avec `admin` / `admin123` → fonctionne (HTTP 302 redirection).
- Injection SQL via le champ nom d'utilisateur `admin' OR '1'='1` → contourne l'authentification.
- Commentaire contenant `<script>alert(1)</script>` → la balise est rendue telle quelle dans la page HTML (non échappée).

## Prochaine étape du projet

Construction du pipeline CI/CD intégrant SAST (Bandit/Semgrep), SCA (Trivy)
et DAST (OWASP ZAP), destiné à détecter automatiquement ces trois failles.
