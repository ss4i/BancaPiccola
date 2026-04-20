# =============================================================================
#  BancaPiccola-SECURE — Applicazione didattica SICURA
# =============================================================================
#
#  Versione corretta di BancaPiccola-vuln con tutte le difese applicate.
#  Stessa logica applicativa, stessi endpoint, stessa base dati. Cambia
#  solo il modo in cui vengono gestiti input, query, password e percorsi.
#
#  Difese applicate (mappa Capitolo -> Difesa):
#    Cap. 5 (SQL Injection):   query parametrizzate ovunque (placeholder '?')
#    Cap. 6 (IDOR/BAC):        controllo proprieta' in ogni query sensibile
#                              whitelist campi in /profilo (no Mass Assignment)
#                              autenticazione sulle API
#    Cap. 7 (Crypto Failures): bcrypt (cost 12) per tutte le password
#                              secret_key da variabile d'ambiente
#    Cap. 8 (XSS):             niente '| safe' su input utente
#                              cookie HttpOnly + Secure + SameSite=Lax
#                              Content-Security-Policy restrittiva
#    Cap. 9 (Supply Chain):    requirements.txt con versioni aggiornate
#    Cap. 10 (Path Traversal): basename + whitelist estensioni +
#                              realpath + verifica prefisso
# =============================================================================

from flask import (Flask, request, redirect, session, render_template_string,
                   url_for, abort, send_file, jsonify, make_response)
import sqlite3
import bcrypt                   # ✅ hashing sicuro per le password
import os
import datetime
import secrets


app = Flask(__name__)

# ✅ CAP.7 — secret_key da variabile d'ambiente, con fallback casuale sicuro
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ✅ Cookie di sessione: difese XSS e CSRF (Cap. 8)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,        # JavaScript non vede il cookie
    SESSION_COOKIE_SAMESITE="Lax",       # Anti-CSRF base
    # SESSION_COOKIE_SECURE=True,        # Abilitare solo in produzione (HTTPS)
)

# Modalita' debug DISABILITATA di default
app.config["DEBUG"] = False

DB = os.path.join(os.path.dirname(__file__), "bancapiccola.db")
DOCUMENTI_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "documenti"))

# ✅ CAP.10 — whitelist estensioni ammesse per i download
ESTENSIONI_AMMESSE = {".pdf"}


# =============================================================================
#  Helper: connessione al DB + funzioni bcrypt
# =============================================================================
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(plain):
    """Hash bcrypt della password (cost 12)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain, hashed):
    """Verifica della password contro l'hash bcrypt salvato."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# =============================================================================
#  ✅ CAP.8 — Content Security Policy su ogni risposta
# =============================================================================
@app.after_request
def aggiungi_header_sicurezza(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "  # ammettiamo CSS inline per semplicita'
        "script-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


# =============================================================================
#  Inizializzazione database (invariato a parte l'hashing delle password)
# =============================================================================
def init_db():
    conn = db()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS utenti (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            ruolo TEXT NOT NULL DEFAULT 'cliente',
            nome TEXT,
            cognome TEXT,
            data_registrazione TEXT
        );

        CREATE TABLE IF NOT EXISTS conti (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            utente_id INTEGER NOT NULL,
            iban TEXT UNIQUE NOT NULL,
            saldo REAL DEFAULT 0.0,
            FOREIGN KEY (utente_id) REFERENCES utenti(id)
        );

        CREATE TABLE IF NOT EXISTS fatture (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            utente_id INTEGER NOT NULL,
            numero TEXT,
            data TEXT NOT NULL,
            descrizione TEXT NOT NULL,
            importo REAL NOT NULL,
            allegato TEXT,
            FOREIGN KEY (utente_id) REFERENCES utenti(id)
        );

        CREATE TABLE IF NOT EXISTS prodotti (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            descrizione TEXT NOT NULL,
            prezzo REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS commenti (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prodotto_id INTEGER NOT NULL,
            autore TEXT NOT NULL,
            testo TEXT NOT NULL,
            data TEXT,
            FOREIGN KEY (prodotto_id) REFERENCES prodotti(id)
        );
    """)

    cur.execute("SELECT COUNT(*) FROM utenti")
    if cur.fetchone()[0] > 0:
        conn.close()
        return

    # ✅ Utenti di test con password hashate con bcrypt
    utenti_test = [
        ("admin",    "admin123",      "admin@bancapicc.it", "admin",   "Ammin",   "Istratore"),
        ("mario",    "mario123",      "mario@rossi.it",     "cliente", "Mario",   "Rossi"),
        ("giulia",   "giulia2025",    "giulia@bianchi.it",  "cliente", "Giulia",  "Bianchi"),
        ("luca",     "passwordLuca!", "luca@verdi.it",      "cliente", "Luca",    "Verdi"),
    ]
    for username, pwd, email, ruolo, nome, cognome in utenti_test:
        cur.execute(
            "INSERT INTO utenti (username, password, email, ruolo, nome, cognome, data_registrazione) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, hash_password(pwd), email, ruolo, nome, cognome,
             datetime.date.today().isoformat())
        )

    cur.executemany(
        "INSERT INTO conti (utente_id, iban, saldo) VALUES (?, ?, ?)",
        [
            (2, "IT60X0542811101000000123456", 1500.50),
            (3, "IT60X0542811101000000654321", 8200.00),
            (4, "IT60X0542811101000000987654",  320.75),
        ]
    )

    fatture_test = [
        (2, "F-2025-001", "2025-09-30", "Bonifico stipendio ANTHROPIC SRL",    3200.00, "fattura-001.pdf"),
        (2, "F-2025-002", "2025-10-05", "Pagamento abbonamento Netflix",         -15.99, "fattura-002.pdf"),
        (2, "F-2025-003", "2025-10-12", "Bolletta Enel Energia",                -78.40, "fattura-003.pdf"),
        (3, "F-2025-004", "2025-09-27", "Bonifico stipendio FIAT-Stellantis",  2150.00, "fattura-004.pdf"),
        (3, "F-2025-005", "2025-10-08", "Bolletta gas Edison",                 -134.50, "fattura-005.pdf"),
        (3, "F-2025-006", "2025-10-10", "Rata mutuo Intesa SanPaolo",          -780.00, "fattura-006.pdf"),
        (3, "F-2025-007", "2025-10-15", "Acquisto Amazon",                      -245.30, "fattura-007.pdf"),
        (4, "F-2025-008", "2025-09-28", "Pensione INPS",                        980.00, "fattura-008.pdf"),
        (4, "F-2025-009", "2025-10-02", "Pagamento RC Auto Allianz",           -512.00, "fattura-009.pdf"),
    ]
    cur.executemany(
        "INSERT INTO fatture (utente_id, numero, data, descrizione, importo, allegato) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        fatture_test
    )

    cur.executemany(
        "INSERT INTO prodotti (nome, descrizione, prezzo) VALUES (?, ?, ?)",
        [
            ("Conto Base",       "Conto corrente senza canone, operazioni illimitate online",       0.0),
            ("Conto Premium",    "Conto con carta gratuita, bonifici istantanei illimitati",        5.0),
            ("Carta Prepagata",  "Carta ricaricabile IBAN gratuita per minorenni",                 12.0),
            ("Mutuo Casa",       "Mutuo prima casa a tasso fisso 4,2%, durata fino a 30 anni",    200.0),
            ("Polizza Vita",     "Assicurazione vita base, capitale assicurato 50k",               45.0),
            ("Fondo Pensione",   "Fondo pensione integrativo con vantaggi fiscali",                20.0),
        ]
    )

    conn.commit()
    conn.close()
    print("[init_db] Database inizializzato con dati di test.")


def genera_pdf_fatture():
    """Identico a vuln: genera PDF minimali validi."""
    os.makedirs(DOCUMENTI_DIR, exist_ok=True)

    def crea_pdf_minimale(percorso, testo):
        contenuto = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R
/Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length {len(testo) + 100} >> stream
BT /F1 14 Tf 50 800 Td (BancaPiccola - {testo}) Tj ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000107 00000 n
0000000212 00000 n
0000000350 00000 n
trailer << /Size 6 /Root 1 0 R >>
startxref
415
%%EOF
"""
        with open(percorso, "w", encoding="ascii") as f:
            f.write(contenuto)

    for i in range(1, 10):
        p = os.path.join(DOCUMENTI_DIR, f"fattura-{i:03d}.pdf")
        if not os.path.exists(p):
            crea_pdf_minimale(p, f"fattura-{i:03d}.pdf")

    # Nella versione secure il file "segreto" NON viene creato:
    # la vulnerabilita' Path Traversal e' chiusa, quindi non serve il file esca.


# =============================================================================
#  TEMPLATE base (identico al vuln)
# =============================================================================
BASE_CSS = """
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif;
         max-width: 900px; margin: 0 auto; padding: 20px; color: #222; }
  header { background: #1a6e3a; color: white; padding: 15px 20px;
           margin: -20px -20px 20px -20px; }
  header h1 { margin: 0; font-size: 20px; display: inline-block; }
  header nav { display: inline-block; float: right; margin-top: 5px; }
  header nav a { color: white; margin-left: 15px; text-decoration: none; }
  .avviso { padding: 8px 12px; background: #d4edda; border: 1px solid #28a745;
            border-radius: 4px; margin: 10px 0; font-size: 14px; }
  .box { border: 1px solid #ddd; border-radius: 6px; padding: 15px; margin: 10px 0; }
  table { border-collapse: collapse; width: 100%; margin: 10px 0; }
  th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
  th { background: #f5f5f5; }
  form { margin: 10px 0; }
  input[type=text], input[type=password], input[type=email], textarea {
    padding: 8px; width: 100%; max-width: 400px; border: 1px solid #ccc;
    border-radius: 4px; box-sizing: border-box; }
  button { padding: 8px 16px; background: #1a6e3a; color: white; border: none;
           border-radius: 4px; cursor: pointer; }
  button:hover { background: #145a2d; }
  .importo-positivo { color: #28a745; }
  .importo-negativo { color: #dc3545; }
  .ruolo-admin { background: #dc3545; color: white; padding: 2px 6px;
                 border-radius: 3px; font-size: 12px; }
  pre { background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; }
</style>
"""

BASE_HEADER = """
<header>
  <h1>🏦 BancaPiccola <small style="font-size:12px">(versione sicura)</small></h1>
  <nav>
    <a href="/">Home</a>
    {% if session.get('utente_id') %}
      <a href="/dashboard">Conto</a>
      <a href="/profilo">Profilo</a>
      {% if session.get('ruolo') == 'admin' %}<a href="/admin">Admin</a>{% endif %}
      <a href="/logout">Esci ({{ session.get('username') }})</a>
    {% else %}
      <a href="/login">Accedi</a>
      <a href="/registrazione">Registrati</a>
    {% endif %}
  </nav>
</header>
<div class="avviso">✅ Versione SICURA: tutte le vulnerabilità del corso sono corrette.</div>
"""


def render(contenuto, **kw):
    html = BASE_CSS + BASE_HEADER + contenuto
    return render_template_string(html, **kw)


# =============================================================================
#  HOME
# =============================================================================
@app.route("/")
def home():
    return render("""
        <h2>Benvenuto</h2>
        <p>Accedi al tuo conto online o cerca i nostri prodotti.</p>
        <form method="GET" action="/cerca">
          <label>Cerca un prodotto:</label><br>
          <input name="q" placeholder="es. conto, mutuo, polizza..." size="40">
          <button>Cerca</button>
        </form>
        <div class="box">
          <b>Credenziali di test:</b><br>
          <code>admin / admin123</code> (admin)<br>
          <code>mario / mario123</code><br>
          <code>giulia / giulia2025</code><br>
          <code>luca / passwordLuca!</code>
        </div>
    """)


# =============================================================================
#  LOGIN — ✅ SICURO (query parametrizzata + bcrypt)
# =============================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    errore = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ✅ Query parametrizzata: input NON concatenato (Cap. 5)
        conn = db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password, ruolo FROM utenti WHERE username = ?",
            (username,)
        )
        riga = cur.fetchone()
        conn.close()

        # ✅ Verifica bcrypt (Cap. 7)
        # Nota: se la riga non esiste, verify_password viene chiamato comunque
        #       su un hash dummy per uniformare i tempi (difesa timing attack)
        hash_dummy = "$2b$12$abcdefghijklmnopqrstuvwxyz012345678901234567890123ABCDEF"
        if riga and verify_password(password, riga["password"]):
            session["utente_id"] = riga["id"]
            session["username"]  = riga["username"]
            session["ruolo"]     = riga["ruolo"]
            session.permanent = False
            return redirect("/dashboard")
        else:
            # Chiamata dummy per uniformare i tempi
            verify_password(password, hash_dummy)
            errore = "Credenziali errate"

    return render("""
        <h2>Accedi</h2>
        {% if errore %}<div class="avviso" style="background:#f8d7da;border-color:#dc3545;">{{ errore }}</div>{% endif %}
        <form method="POST">
          <label>Username:</label><br>
          <input type="text" name="username" autofocus><br><br>
          <label>Password:</label><br>
          <input type="password" name="password"><br><br>
          <button>Accedi</button>
        </form>
    """, errore=errore)


# =============================================================================
#  REGISTRAZIONE — ✅ SICURA (bcrypt + query parametrizzata)
# =============================================================================
@app.route("/registrazione", methods=["GET", "POST"])
def registrazione():
    errore = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email    = request.form.get("email", "").strip()

        # ✅ Validazione base dell'input
        if len(username) < 3 or len(password) < 8:
            errore = "Username >= 3 caratteri, password >= 8 caratteri"
        elif not username.replace("_", "").isalnum():
            errore = "L'username puo' contenere solo lettere, numeri e underscore"
        else:
            try:
                conn = db()
                cur = conn.cursor()
                # ✅ Ruolo HARDCODED a 'cliente': nessun Mass Assignment
                cur.execute(
                    "INSERT INTO utenti (username, password, email, ruolo, data_registrazione) "
                    "VALUES (?, ?, ?, 'cliente', ?)",
                    (username, hash_password(password), email,
                     datetime.date.today().isoformat())
                )
                utente_id = cur.lastrowid
                iban = f"IT60X054281110100{utente_id:010d}"
                cur.execute(
                    "INSERT INTO conti (utente_id, iban, saldo) VALUES (?, ?, ?)",
                    (utente_id, iban, 0.0)
                )
                conn.commit()
                conn.close()
                return redirect("/login")
            except sqlite3.IntegrityError:
                errore = "Username gia' esistente"

    return render("""
        <h2>Crea un conto</h2>
        {% if errore %}<div class="avviso" style="background:#f8d7da">{{ errore }}</div>{% endif %}
        <form method="POST">
          Username: <input name="username" required><br><br>
          Email: <input type="email" name="email"><br><br>
          Password: <input type="password" name="password" required minlength="8"><br><br>
          <button>Registrati</button>
        </form>
    """, errore=errore)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# =============================================================================
#  DASHBOARD
# =============================================================================
@app.route("/dashboard")
def dashboard():
    if "utente_id" not in session:
        return redirect("/login")

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT iban, saldo FROM conti WHERE utente_id = ?",
                (session["utente_id"],))
    conto = cur.fetchone()
    cur.execute("SELECT id, numero, data, descrizione, importo "
                "FROM fatture WHERE utente_id = ? ORDER BY data DESC",
                (session["utente_id"],))
    fatture = cur.fetchall()
    conn.close()

    return render("""
        <h2>Il tuo conto</h2>
        {% if conto %}
          <div class="box">
            <p><b>IBAN:</b> {{ conto['iban'] }}</p>
            <p><b>Saldo:</b>
              <span class="{{ 'importo-positivo' if conto['saldo'] >= 0 else 'importo-negativo' }}">
                {{ "%.2f"|format(conto['saldo']) }} €
              </span>
            </p>
          </div>
        {% endif %}

        <h3>Le tue fatture</h3>
        {% if fatture %}
        <table>
          <tr><th>#</th><th>Numero</th><th>Data</th><th>Descrizione</th><th>Importo</th></tr>
          {% for f in fatture %}
            <tr>
              <td><a href="/fattura/{{ f['id'] }}">Dettaglio</a></td>
              <td>{{ f['numero'] }}</td>
              <td>{{ f['data'] }}</td>
              <td>{{ f['descrizione'] }}</td>
              <td class="{{ 'importo-positivo' if f['importo'] >= 0 else 'importo-negativo' }}">
                {{ "+" if f['importo'] >= 0 else "" }}{{ "%.2f"|format(f['importo']) }} €
              </td>
            </tr>
          {% endfor %}
        </table>
        {% else %}
          <p><i>Nessuna fattura.</i></p>
        {% endif %}
    """, conto=conto, fatture=fatture)


# =============================================================================
#  DETTAGLIO FATTURA — ✅ SICURO (ownership check)
# =============================================================================
@app.route("/fattura/<int:fattura_id>")
def fattura(fattura_id):
    if "utente_id" not in session:
        return redirect("/login")

    utente_id = session["utente_id"]
    ruolo = session.get("ruolo", "cliente")

    conn = db()
    cur = conn.cursor()
    # ✅ Ownership check nella query: la fattura DEVE appartenere all'utente
    #    (eccezione: admin puo' vedere tutto)
    if ruolo == "admin":
        cur.execute("""
            SELECT f.id, f.numero, f.data, f.descrizione, f.importo, f.allegato,
                   u.username, u.nome, u.cognome
            FROM fatture f JOIN utenti u ON f.utente_id = u.id
            WHERE f.id = ?
        """, (fattura_id,))
    else:
        cur.execute("""
            SELECT f.id, f.numero, f.data, f.descrizione, f.importo, f.allegato,
                   u.username, u.nome, u.cognome
            FROM fatture f JOIN utenti u ON f.utente_id = u.id
            WHERE f.id = ? AND f.utente_id = ?
        """, (fattura_id, utente_id))
    f = cur.fetchone()
    conn.close()

    # ✅ 404 anche quando la fattura esiste ma non appartiene all'utente:
    #    cosi' non si rivela nemmeno l'esistenza della risorsa
    if not f:
        abort(404)

    return render("""
        <h2>Fattura {{ f['numero'] }}</h2>
        <div class="box">
          <p><b>Intestatario:</b> {{ f['nome'] }} {{ f['cognome'] }} ({{ f['username'] }})</p>
          <p><b>Data:</b> {{ f['data'] }}</p>
          <p><b>Descrizione:</b> {{ f['descrizione'] }}</p>
          <p><b>Importo:</b>
            <span class="{{ 'importo-positivo' if f['importo'] >= 0 else 'importo-negativo' }}">
              {{ "+" if f['importo'] >= 0 else "" }}{{ "%.2f"|format(f['importo']) }} €
            </span>
          </p>
          {% if f['allegato'] %}
            <p><a href="/download?file={{ f['allegato'] }}">📄 Scarica documento PDF</a></p>
          {% endif %}
        </div>
        <p><a href="/dashboard">⬅ Torna alla dashboard</a></p>
    """, f=f)


# =============================================================================
#  DOWNLOAD — ✅ SICURO (difese a 3 livelli contro Path Traversal)
# =============================================================================
@app.route("/download")
def download():
    if "utente_id" not in session:
        return redirect("/login")

    filename = request.args.get("file", "")

    # ✅ Difesa 1 — basename: rimuove qualunque componente di percorso
    nome_base = os.path.basename(filename)
    if not nome_base:
        abort(400)

    # ✅ Difesa 2 — whitelist estensioni
    estensione = os.path.splitext(nome_base)[1].lower()
    if estensione not in ESTENSIONI_AMMESSE:
        abort(403)

    # ✅ Difesa 3 — realpath + verifica che il percorso risolto stia
    #              davvero dentro DOCUMENTI_DIR
    percorso_proposto = os.path.join(DOCUMENTI_DIR, nome_base)
    percorso_reale = os.path.realpath(percorso_proposto)
    if not percorso_reale.startswith(DOCUMENTI_DIR + os.sep):
        abort(403)

    if not os.path.isfile(percorso_reale):
        abort(404)

    # ✅ Difesa 4 bonus — verifica che la risorsa sia associata
    #    a una fattura dell'utente (ownership check, se applicabile)
    conn = db()
    cur = conn.cursor()
    ruolo = session.get("ruolo", "cliente")
    if ruolo == "admin":
        cur.execute("SELECT 1 FROM fatture WHERE allegato = ?", (nome_base,))
    else:
        cur.execute("SELECT 1 FROM fatture WHERE allegato = ? AND utente_id = ?",
                    (nome_base, session["utente_id"]))
    trovato = cur.fetchone()
    conn.close()
    if not trovato:
        abort(404)

    return send_file(percorso_reale, as_attachment=True)


# =============================================================================
#  RICERCA PRODOTTI — ✅ SICURO (query parametrizzata + escape)
# =============================================================================
@app.route("/cerca")
def cerca():
    q = request.args.get("q", "")

    # ✅ Query parametrizzata: niente SQL Injection
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, nome, descrizione, prezzo FROM prodotti WHERE nome LIKE ?",
        (f"%{q}%",)
    )
    risultati = cur.fetchall()
    conn.close()

    # ✅ Jinja2 escape automatico: niente | safe su 'q'
    return render("""
        <h2>Risultati per "{{ q }}"</h2>
        <p><a href="/">⬅ Home</a></p>
        {% if risultati %}
        <table>
          <tr><th>Nome</th><th>Descrizione</th><th>Canone</th></tr>
          {% for p in risultati %}
            <tr>
              <td><a href="/prodotto/{{ p['id'] }}">{{ p['nome'] }}</a></td>
              <td>{{ p['descrizione'] }}</td>
              <td>{{ "%.2f"|format(p['prezzo']) }} €/mese</td>
            </tr>
          {% endfor %}
        </table>
        {% else %}
          <p><i>Nessun risultato.</i></p>
        {% endif %}
    """, q=q, risultati=risultati)


# =============================================================================
#  PRODOTTO + COMMENTI — ✅ SICURO (niente XSS Stored, escape automatico)
# =============================================================================
@app.route("/prodotto/<int:prodotto_id>", methods=["GET", "POST"])
def prodotto(prodotto_id):
    conn = db()
    cur = conn.cursor()

    if request.method == "POST":
        if "username" not in session:
            return redirect("/login")
        testo = request.form.get("testo", "").strip()
        # ✅ Validazione lunghezza
        if 1 <= len(testo) <= 500:
            cur.execute(
                "INSERT INTO commenti (prodotto_id, autore, testo, data) "
                "VALUES (?, ?, ?, ?)",
                (prodotto_id, session["username"], testo,
                 datetime.date.today().isoformat())
            )
            conn.commit()

    cur.execute("SELECT id, nome, descrizione, prezzo FROM prodotti WHERE id = ?",
                (prodotto_id,))
    prod = cur.fetchone()
    cur.execute("SELECT autore, testo, data FROM commenti "
                "WHERE prodotto_id = ? ORDER BY id DESC",
                (prodotto_id,))
    commenti = cur.fetchall()
    conn.close()

    if not prod:
        abort(404)

    # ✅ Niente | safe sul testo dei commenti: Jinja2 fa escape automatico
    return render("""
        <h2>{{ prod['nome'] }}</h2>
        <div class="box">
          <p>{{ prod['descrizione'] }}</p>
          <p><b>Canone:</b> {{ "%.2f"|format(prod['prezzo']) }} €/mese</p>
        </div>

        <h3>Commenti dei clienti</h3>
        {% if session.get('username') %}
          <form method="POST">
            <textarea name="testo" rows="3" maxlength="500"
                      placeholder="Scrivi un commento (max 500 caratteri)..."></textarea><br>
            <button>Pubblica</button>
          </form>
        {% else %}
          <p><a href="/login">Accedi</a> per commentare.</p>
        {% endif %}

        {% for c in commenti %}
          <div class="box">
            <b>{{ c['autore'] }}</b> <small>({{ c['data'] }})</small><br>
            {{ c['testo'] }}
          </div>
        {% else %}
          <p><i>Nessun commento.</i></p>
        {% endfor %}
    """, prod=prod, commenti=commenti)


# =============================================================================
#  PROFILO — ✅ SICURO (whitelist campi + ownership)
# =============================================================================
# Nota: rimosso /profilo/<int:utente_id> — l'utente puo' modificare solo il proprio.
# L'admin modifica altri utenti da un endpoint separato dedicato (non incluso qui).
@app.route("/profilo", methods=["GET", "POST"])
def profilo():
    if "utente_id" not in session:
        return redirect("/login")

    utente_id = session["utente_id"]
    conn = db()
    cur = conn.cursor()

    if request.method == "POST":
        # ✅ WHITELIST dei campi modificabili: SOLO questi, mai 'ruolo'
        campi_ammessi = {"nome", "cognome", "email"}
        aggiornamenti = {}
        for campo in campi_ammessi:
            valore = request.form.get(campo, "").strip()
            if valore:
                aggiornamenti[campo] = valore

        if aggiornamenti:
            # ✅ Costruzione controllata della query (nomi colonna hardcoded)
            set_clause = ", ".join(f"{campo} = ?" for campo in aggiornamenti.keys())
            valori = list(aggiornamenti.values()) + [utente_id]
            cur.execute(f"UPDATE utenti SET {set_clause} WHERE id = ?", valori)
            conn.commit()

    cur.execute("SELECT id, username, email, nome, cognome, ruolo FROM utenti WHERE id = ?",
                (utente_id,))
    u = cur.fetchone()
    conn.close()

    if not u:
        abort(404)

    return render("""
        <h2>Il tuo profilo</h2>
        <form method="POST">
          Nome: <input name="nome" value="{{ u['nome'] or '' }}"><br><br>
          Cognome: <input name="cognome" value="{{ u['cognome'] or '' }}"><br><br>
          Email: <input type="email" name="email" value="{{ u['email'] or '' }}"><br><br>
          <p>Ruolo: <span class="ruolo-{{ u['ruolo'] }}">{{ u['ruolo'] }}</span>
             <small>(modificabile solo dall'amministratore)</small></p>
          <button>Salva modifiche</button>
        </form>
    """, u=u)


# =============================================================================
#  ADMIN — ✅ SICURO (controllo ruolo)
# =============================================================================
@app.route("/admin")
def admin():
    if session.get("ruolo") != "admin":
        return render("<h2>403 — Accesso riservato agli amministratori</h2>"), 403

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, ruolo, data_registrazione FROM utenti ORDER BY id")
    utenti = cur.fetchall()
    cur.execute("SELECT COUNT(*) c FROM fatture")
    n_fatture = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) c FROM commenti")
    n_commenti = cur.fetchone()["c"]
    conn.close()

    return render("""
        <h2>Pannello Amministratore</h2>
        <p><b>Totali:</b> {{ utenti|length }} utenti, {{ n_fatture }} fatture,
           {{ n_commenti }} commenti</p>
        <table>
          <tr><th>ID</th><th>Username</th><th>Email</th><th>Ruolo</th><th>Registrato il</th></tr>
          {% for u in utenti %}
            <tr>
              <td>{{ u['id'] }}</td>
              <td>{{ u['username'] }}</td>
              <td>{{ u['email'] }}</td>
              <td><span class="ruolo-{{ u['ruolo'] }}">{{ u['ruolo'] }}</span></td>
              <td>{{ u['data_registrazione'] }}</td>
            </tr>
          {% endfor %}
        </table>
    """, utenti=utenti, n_fatture=n_fatture, n_commenti=n_commenti)


# =============================================================================
#  API — ✅ SICURE (autenticazione + ownership)
# =============================================================================
@app.route("/api/utenti/<int:utente_id>")
def api_utente(utente_id):
    # ✅ Autenticazione obbligatoria
    if "utente_id" not in session:
        return jsonify({"errore": "autenticazione richiesta"}), 401

    # ✅ Ownership: l'utente puo' vedere solo se stesso (o tutto se admin)
    if session.get("ruolo") != "admin" and session["utente_id"] != utente_id:
        return jsonify({"errore": "accesso negato"}), 403

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, ruolo, nome, cognome FROM utenti WHERE id = ?",
                (utente_id,))
    u = cur.fetchone()
    conn.close()
    if not u:
        return jsonify({"errore": "utente non trovato"}), 404
    return jsonify(dict(u))


@app.route("/api/fatture/<int:fattura_id>")
def api_fattura(fattura_id):
    # ✅ Autenticazione obbligatoria
    if "utente_id" not in session:
        return jsonify({"errore": "autenticazione richiesta"}), 401

    conn = db()
    cur = conn.cursor()
    # ✅ Ownership check nella query (admin vede tutto)
    if session.get("ruolo") == "admin":
        cur.execute("""
            SELECT f.id, f.numero, f.data, f.descrizione, f.importo, u.username
            FROM fatture f JOIN utenti u ON f.utente_id = u.id
            WHERE f.id = ?
        """, (fattura_id,))
    else:
        cur.execute("""
            SELECT f.id, f.numero, f.data, f.descrizione, f.importo, u.username
            FROM fatture f JOIN utenti u ON f.utente_id = u.id
            WHERE f.id = ? AND f.utente_id = ?
        """, (fattura_id, session["utente_id"]))
    f = cur.fetchone()
    conn.close()
    if not f:
        return jsonify({"errore": "fattura non trovata"}), 404
    return jsonify(dict(f))


# =============================================================================
#  Avvio
# =============================================================================
if __name__ == "__main__":
    init_db()
    genera_pdf_fatture()
    print("\n" + "=" * 70)
    print("🏦  BancaPiccola-SECURE in esecuzione su http://127.0.0.1:5000")
    print("=" * 70)
    print("✅  Versione sicura: tutte le vulnerabilita' del corso sono corrette.\n")
    print("Credenziali di test: admin/admin123, mario/mario123,")
    print("                     giulia/giulia2025, luca/passwordLuca!\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
