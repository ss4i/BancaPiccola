# BancaPiccola-secure

**Versione sicura** di BancaPiccola: stessa applicazione della cartella `../BancaPiccola-vuln/`, ma con **tutte le vulnerabilità dei capitoli 5-10 corrette**.

---

## A cosa serve

Questa versione è il **riferimento** al quale confrontare le proprie correzioni durante i laboratori:

1. Fai il laboratorio su `BancaPiccola-vuln/app.py`, applicando le tue correzioni
2. Quando pensi di aver finito, confronta il tuo codice con `BancaPiccola-secure/app.py`
3. Identifica le differenze, capisci perché ogni difesa è scritta così

Puoi usarla anche come base pulita per sperimentare: puoi provare a **reintrodurre** una vulnerabilità per vedere come si manifesta, e poi chiudere di nuovo la breccia.

---

## Installazione

Identica alla vuln. Da terminale, nella cartella `BancaPiccola-secure/`:

```bash
python -m venv venv
source venv/bin/activate          # su Linux/macOS
.\venv\Scripts\Activate.ps1       # su Windows PowerShell

pip install -r requirements.txt
python app.py
```

Apri: <http://127.0.0.1:5000>

---

## Credenziali di test

Identiche alla vuln:

| Username | Password | Ruolo |
|---|---|---|
| `admin` | `admin123` | admin |
| `mario` | `mario123` | cliente |
| `giulia` | `giulia2025` | cliente |
| `luca` | `passwordLuca!` | cliente |

> ℹ️ Le password nel database sono hashate con **bcrypt cost 12**. Aprendo il database con DB Browser for SQLite vedrai stringhe tipo `$2b$12$...`, non le password in chiaro. È il cambiamento principale rispetto a vuln.

---

## Mappa delle difese applicate

| Capitolo | Vulnerabilità vuln | Difesa applicata in secure | Dove vederla |
|---|---|---|---|
| Cap. 5 | SQLi su `/login` e `/cerca` | Query parametrizzate (placeholder `?`) | `def login()`, `def cerca()` |
| Cap. 6 | IDOR su `/fattura/<id>` | Ownership check nella query: `WHERE f.id = ? AND f.utente_id = ?` | `def fattura()` |
| Cap. 6 | IDOR su `/api/utenti/<id>` | Autenticazione + ownership check sull'API | `def api_utente()` |
| Cap. 6 | Mass Assignment su `/profilo` | Whitelist hard-coded dei campi modificabili: `{"nome", "cognome", "email"}` | `def profilo()` |
| Cap. 7 | Password in MD5 | `bcrypt.hashpw()` con cost 12 | `hash_password()`, `verify_password()` |
| Cap. 7 | `secret_key` debole in chiaro | Variabile d'ambiente con fallback `secrets.token_hex(32)` | Riga `app.secret_key = ...` |
| Cap. 7 | Timing attack sul login | Chiamata dummy a `verify_password` quando l'utente non esiste | `def login()` |
| Cap. 8 | Reflected XSS su `/cerca` | Rimosso `| safe` da Jinja2, ora escape automatico | Template di `cerca()` |
| Cap. 8 | Stored XSS sui commenti | Idem: rimosso `| safe` da `{{ c['testo'] }}` | Template di `prodotto()` |
| Cap. 8 | Cookie senza flag | `HttpOnly` + `SameSite=Lax` attivati | `app.config.update(...)` |
| Cap. 8 | Nessuna CSP | Header `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` | `@app.after_request` |
| Cap. 9 | `requirements.txt` con CVE | Versioni aggiornate | `requirements.txt` |
| Cap. 10 | Path Traversal su `/download` | `basename` + whitelist estensioni + `realpath` + verifica prefisso + ownership check | `def download()` |

---

## Cosa NON è incluso (per tenerlo semplice)

La versione secure applica le difese dei capitoli 5-10, ma rimane un'applicazione didattica. In un progetto reale aggiungeresti almeno:

- **HTTPS obbligatorio** con certificato reale (Let's Encrypt) + `SESSION_COOKIE_SECURE=True`
- **CSRF token** espliciti sui form (qui ci affidiamo solo a `SameSite=Lax`)
- **Rate limiting** sul login (per limitare forza bruta) — con `flask-limiter`
- **Logging strutturato** di autenticazioni e accessi falliti
- **Autenticazione a due fattori (2FA)** con TOTP
- **Revoca delle sessioni** lato server (qui Flask usa cookie firmati client-side)
- **WSGI server di produzione** (gunicorn, uwsgi) al posto del dev server di Flask
- **Sistemi di monitoring/SIEM** per rilevare anomalie

Tutto questo è materia del secondo anno e dei moduli avanzati.

---

## Confronto diretto vuln ↔ secure

Per vedere tutte le modifiche in un colpo solo:

```bash
diff -u ../BancaPiccola-vuln/app.py app.py | less
```

(su Windows `less` non c'è: usa `| more` oppure redirigi in un file).

Il diff mostra circa 200 righe di differenze: ogni differenza è una difesa applicata.
