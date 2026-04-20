# =============================================================================
#  BancaPiccola-vuln — Applicazione didattica INTENZIONALMENTE VULNERABILE
# =============================================================================
#
#  ⚠️  AVVERTENZA
#  Questa applicazione contiene vulnerabilita' di sicurezza DELIBERATE a scopo
#  didattico. Non eseguirla MAI su una rete pubblica o esposta a internet.
#  E' progettata esclusivamente per girare in localhost (127.0.0.1) per scopi
#  formativi nell'ambito del corso "Sviluppo Sicuro del Software" (ITS Prodigi
#  / ITS Empoli / SS4I S.r.l.).
#
#  Vulnerabilita' intenzionali (mappa Capitolo -> Endpoint):
#    Cap. 5 (SQL Injection):   /login, /cerca
#    Cap. 6 (IDOR/BAC):        /fattura/<id>, /profilo/<id>, /api/utenti/<id>
#    Cap. 7 (Crypto Failures): hash MD5 senza salt, secret_key debole
#    Cap. 8 (XSS):             /cerca (Reflected), /prodotto/<id> (Stored)
#    Cap. 9 (Supply Chain):    requirements.txt con dipendenze con CVE noti
#    Cap. 10 (Path Traversal): /download
#    Bonus: Mass Assignment su /profilo (POST)
#
#  Credenziali di test:
#    admin  / admin123        (ruolo admin)
#    mario  / mario123        (cliente)
#    giulia / giulia2025      (cliente)
#    luca   / passwordLuca!   (cliente)
# =============================================================================

from flask import (Flask, request, redirect, session, render_template_string,
                   url_for, abort, send_file, jsonify, make_response)
import sqlite3
import hashlib                  # ❌ vulnerabile: MD5 per password
import os
import datetime


app = Flask(__name__)

# ❌ CAP.7 — secret_key debole e in chiaro nel codice
app.secret_key = "bancapiccola-secret-2024"

# Modalita' debug attiva (❌ in produzione andrebbe disattivata)
app.config["DEBUG"] = True

DB = os.path.join(os.path.dirname(__file__), "bancapiccola.db")
DOCUMENTI_DIR = os.path.join(os.path.dirname(__file__), "documenti")


# =============================================================================
#  Helper: connessione al DB
# =============================================================================
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# =============================================================================
#  Inizializzazione database + dati di test + PDF di esempio
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

    # Verifica se gia' popolato
    cur.execute("SELECT COUNT(*) FROM utenti")
    if cur.fetchone()[0] > 0:
        conn.close()
        return

    # ---- UTENTI (password hashate con MD5 - VULNERABILE - Cap.7) ----
    def md5(s):
        return hashlib.md5(s.encode("utf-8")).hexdigest()

    utenti_test = [
        # username,  password plain,  email,               ruolo,      nome,      cognome
        ("admin",    "admin123",      "admin@bancapicc.it", "admin",   "Ammin",   "Istratore"),
        ("mario",    "mario123",      "mario@rossi.it",     "cliente", "Mario",   "Rossi"),
        ("giulia",   "giulia2025",    "giulia@bianchi.it",  "cliente", "Giulia",  "Bianchi"),
        ("luca",     "passwordLuca!", "luca@verdi.it",      "cliente", "Luca",    "Verdi"),
    ]
    for username, pwd, email, ruolo, nome, cognome in utenti_test:
        cur.execute(
            "INSERT INTO utenti (username, password, email, ruolo, nome, cognome, data_registrazione) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, md5(pwd), email, ruolo, nome, cognome,
             datetime.date.today().isoformat())
        )

    # ---- CONTI (uno per utente cliente) ----
    cur.executemany(
        "INSERT INTO conti (utente_id, iban, saldo) VALUES (?, ?, ?)",
        [
            (2, "IT60X0542811101000000123456", 1500.50),  # mario
            (3, "IT60X0542811101000000654321", 8200.00),  # giulia
            (4, "IT60X0542811101000000987654",  320.75),  # luca
        ]
    )

    # ---- FATTURE (con numeri e allegati PDF) ----
    fatture_test = [
        # utente_id, numero,         data,         descrizione,                          importo,   allegato
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

    # ---- PRODOTTI (per ricerca e commenti) ----
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
    """Genera PDF minimali per i documenti delle fatture (se non esistono)."""
    os.makedirs(DOCUMENTI_DIR, exist_ok=True)

    # Template PDF minimo: header PDF valido + testo + chiusura
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
        nome = f"fattura-{i:03d}.pdf"
        p = os.path.join(DOCUMENTI_DIR, nome)
        if not os.path.exists(p):
            crea_pdf_minimale(p, nome)

    # ⚠️ File "segreto" FUORI dalla cartella documenti
    # — servira' per dimostrare il Path Traversal del Cap. 10
    parent = os.path.dirname(DOCUMENTI_DIR)
    segreto_path = os.path.join(parent, "SEGRETO.txt")
    if not os.path.exists(segreto_path):
        with open(segreto_path, "w", encoding="utf-8") as f:
            f.write("CHIAVE CEO BancaPiccola: TOPSECRET-CEO-2025\n"
                    "Se leggi questo file, stai sfruttando una vulnerabilita' "
                    "Path Traversal (Cap. 10 della dispensa).\n")


# =============================================================================
#  TEMPLATE base (inline per minimizzare file)
# =============================================================================
BASE_CSS = """
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif;
         max-width: 900px; margin: 0 auto; padding: 20px; color: #222; }
  header { background: #004070; color: white; padding: 15px 20px;
           margin: -20px -20px 20px -20px; }
  header h1 { margin: 0; font-size: 20px; display: inline-block; }
  header nav { display: inline-block; float: right; margin-top: 5px; }
  header nav a { color: white; margin-left: 15px; text-decoration: none; }
  header nav a:hover { text-decoration: underline; }
  .avviso { padding: 8px 12px; background: #fff3cd; border: 1px solid #ffc107;
            border-radius: 4px; margin: 10px 0; font-size: 14px; }
  .box { border: 1px solid #ddd; border-radius: 6px; padding: 15px; margin: 10px 0; }
  table { border-collapse: collapse; width: 100%; margin: 10px 0; }
  th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
  th { background: #f5f5f5; }
  form { margin: 10px 0; }
  input[type=text], input[type=password], input[type=email], textarea {
    padding: 8px; width: 100%; max-width: 400px; border: 1px solid #ccc;
    border-radius: 4px; box-sizing: border-box; }
  button { padding: 8px 16px; background: #004070; color: white; border: none;
           border-radius: 4px; cursor: pointer; }
  button:hover { background: #003050; }
  .importo-positivo { color: #28a745; }
  .importo-negativo { color: #dc3545; }
  .ruolo-admin { background: #dc3545; color: white; padding: 2px 6px;
                 border-radius: 3px; font-size: 12px; }
  pre { background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; }
</style>
"""

BASE_HEADER = """
<header>
  <h1>🏦 BancaPiccola</h1>
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
<div class="avviso">⚠️ Ambiente didattico VULNERABILE — non usare dati reali.</div>
"""


def render(contenuto, **kw):
    """Wrapper per render_template_string con base + contenuto."""
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
          <b>Credenziali di test (ambiente didattico):</b><br>
          <code>admin / admin123</code> (admin)<br>
          <code>mario / mario123</code><br>
          <code>giulia / giulia2025</code><br>
          <code>luca / passwordLuca!</code>
        </div>
    """)


# =============================================================================
#  LOGIN — ❌ VULNERABILE A SQL INJECTION (Cap. 5)
# =============================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    errore = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ❌ Password hashata con MD5 senza salt (Cap. 7)
        password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()

        # ❌ SQL INJECTION: query costruita con concatenazione di stringa (Cap. 5)
        query = (f"SELECT id, username, ruolo FROM utenti "
                 f"WHERE username = '{username}' AND password = '{password_hash}'")

        # Debug: stampa la query effettivamente eseguita (utile per il lab)
        print(f"\n[DEBUG SQL] {query}\n")

        try:
            conn = db()
            cur = conn.cursor()
            cur.execute(query)
            riga = cur.fetchone()
            conn.close()
        except sqlite3.Error as e:
            return render("""
                <h2>Errore nel database</h2>
                <pre>{{ errore }}</pre>
                <p><a href="/login">⬅ Riprova</a></p>
            """, errore=str(e))

        if riga:
            session["utente_id"] = riga["id"]
            session["username"]  = riga["username"]
            session["ruolo"]     = riga["ruolo"]
            return redirect("/dashboard")
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
#  REGISTRAZIONE
# =============================================================================
@app.route("/registrazione", methods=["GET", "POST"])
def registrazione():
    errore = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email    = request.form.get("email", "").strip()

        if len(username) < 3 or len(password) < 4:
            errore = "Username >= 3 caratteri e password >= 4 caratteri"
        else:
            password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
            try:
                conn = db()
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO utenti (username, password, email, ruolo, data_registrazione) "
                    "VALUES (?, ?, ?, 'cliente', ?)",
                    (username, password_hash, email, datetime.date.today().isoformat())
                )
                utente_id = cur.lastrowid
                # Crea conto automatico
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
          Password: <input type="password" name="password" required><br><br>
          <button>Registrati</button>
        </form>
    """, errore=errore)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# =============================================================================
#  DASHBOARD (conto e fatture dell'utente loggato)
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
#  DETTAGLIO FATTURA — ❌ VULNERABILE A IDOR (Cap. 6)
# =============================================================================
@app.route("/fattura/<int:fattura_id>")
def fattura(fattura_id):
    if "utente_id" not in session:
        return redirect("/login")

    conn = db()
    cur = conn.cursor()
    # ❌ IDOR: nessun controllo di proprieta' — chiunque loggato puo' vedere
    #          qualsiasi fattura, basta cambiare l'id nell'URL
    cur.execute("""
        SELECT f.id, f.numero, f.data, f.descrizione, f.importo, f.allegato,
               u.username, u.nome, u.cognome
        FROM fatture f JOIN utenti u ON f.utente_id = u.id
        WHERE f.id = ?
    """, (fattura_id,))
    f = cur.fetchone()
    conn.close()

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
#  DOWNLOAD — ❌ VULNERABILE A PATH TRAVERSAL (Cap. 10)
# =============================================================================
@app.route("/download")
def download():
    if "utente_id" not in session:
        return redirect("/login")

    filename = request.args.get("file", "")
    # ❌ Path Traversal: nessuna sanitizzazione del percorso
    percorso = os.path.join(DOCUMENTI_DIR, filename)
    print(f"\n[DEBUG PATH] Tentativo apertura: {percorso}\n")

    try:
        return send_file(percorso, as_attachment=True)
    except Exception as e:
        return f"Errore: {e}", 404


# =============================================================================
#  RICERCA PRODOTTI — ❌ VULNERABILE A SQL INJECTION + REFLECTED XSS (Cap. 5 e 8)
# =============================================================================
@app.route("/cerca")
def cerca():
    q = request.args.get("q", "")

    # ❌ SQL INJECTION: concatenazione di input (Cap. 5)
    query = f"SELECT id, nome, descrizione, prezzo FROM prodotti WHERE nome LIKE '%{q}%'"
    print(f"\n[DEBUG SQL] {query}\n")

    try:
        conn = db()
        cur = conn.cursor()
        cur.execute(query)
        risultati = cur.fetchall()
        conn.close()
    except sqlite3.Error as e:
        return render("<h2>Errore DB</h2><pre>{{ err }}</pre>", err=str(e))

    return render("""
        <!-- ❌ Reflected XSS: {{ q | safe }} non fa escape (Cap. 8) -->
        <h2>Risultati per "{{ q | safe }}"</h2>
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
#  DETTAGLIO PRODOTTO + COMMENTI — ❌ VULNERABILE A STORED XSS (Cap. 8)
# =============================================================================
@app.route("/prodotto/<int:prodotto_id>", methods=["GET", "POST"])
def prodotto(prodotto_id):
    conn = db()
    cur = conn.cursor()

    if request.method == "POST":
        if "username" not in session:
            return redirect("/login")
        testo = request.form.get("testo", "")
        cur.execute(
            "INSERT INTO commenti (prodotto_id, autore, testo, data) "
            "VALUES (?, ?, ?, ?)",
            (prodotto_id, session["username"], testo, datetime.date.today().isoformat())
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

    return render("""
        <h2>{{ prod['nome'] }}</h2>
        <div class="box">
          <p>{{ prod['descrizione'] }}</p>
          <p><b>Canone:</b> {{ "%.2f"|format(prod['prezzo']) }} €/mese</p>
        </div>

        <h3>Commenti dei clienti</h3>
        {% if session.get('username') %}
          <form method="POST">
            <textarea name="testo" rows="3" placeholder="Scrivi un commento..."></textarea><br>
            <button>Pubblica</button>
          </form>
        {% else %}
          <p><a href="/login">Accedi</a> per commentare.</p>
        {% endif %}

        {% for c in commenti %}
          <div class="box">
            <!-- ❌ Stored XSS: {{ c['testo'] | safe }} non fa escape (Cap. 8) -->
            <b>{{ c['autore'] }}</b> <small>({{ c['data'] }})</small><br>
            {{ c['testo'] | safe }}
          </div>
        {% else %}
          <p><i>Nessun commento.</i></p>
        {% endfor %}
    """, prod=prod, commenti=commenti)


# =============================================================================
#  PROFILO — ❌ VULNERABILE A IDOR + MASS ASSIGNMENT (Cap. 6)
# =============================================================================
@app.route("/profilo", methods=["GET", "POST"])
@app.route("/profilo/<int:utente_id>", methods=["GET", "POST"])
def profilo(utente_id=None):
    if "utente_id" not in session:
        return redirect("/login")

    # ❌ IDOR: se passi /profilo/<id>, NON verifica che tu sia il proprietario
    if utente_id is None:
        utente_id = session["utente_id"]

    conn = db()
    cur = conn.cursor()

    if request.method == "POST":
        # ❌ MASS ASSIGNMENT: applico tutti i campi del form senza whitelist
        campi_ammessi = request.form.to_dict()  # prendo TUTTO quello che arriva
        set_clauses = []
        valori = []
        for campo, valore in campi_ammessi.items():
            # ❌ NESSUNA whitelist: l'utente puo' modificare anche 'ruolo'
            set_clauses.append(f"{campo} = ?")
            valori.append(valore)
        if set_clauses:
            valori.append(utente_id)
            # ❌ Anche SQLi potenziale: il nome del campo viene da input utente
            query = f"UPDATE utenti SET {', '.join(set_clauses)} WHERE id = ?"
            print(f"\n[DEBUG SQL] {query} con {valori}\n")
            try:
                cur.execute(query, valori)
                conn.commit()
            except sqlite3.Error as e:
                conn.close()
                return render("<h2>Errore</h2><pre>{{ e }}</pre>", e=str(e))

    cur.execute("SELECT id, username, email, nome, cognome, ruolo FROM utenti WHERE id = ?",
                (utente_id,))
    u = cur.fetchone()
    conn.close()

    if not u:
        abort(404)

    return render("""
        <h2>Profilo di {{ u['username'] }}</h2>
        <form method="POST">
          Nome: <input name="nome" value="{{ u['nome'] or '' }}"><br><br>
          Cognome: <input name="cognome" value="{{ u['cognome'] or '' }}"><br><br>
          Email: <input type="email" name="email" value="{{ u['email'] or '' }}"><br><br>
          <p>Ruolo attuale: <span class="ruolo-{{ u['ruolo'] }}">{{ u['ruolo'] }}</span></p>
          <button>Salva modifiche</button>
        </form>
    """, u=u)


# =============================================================================
#  PANNELLO ADMIN
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
#  API — ❌ VULNERABILE A BOLA/IDOR (Cap. 3-bis + Cap. 6)
# =============================================================================
@app.route("/api/utenti/<int:utente_id>")
def api_utente(utente_id):
    # ❌ Nessuna autenticazione, nessun controllo di proprieta'
    # Chiunque puo' recuperare i dati di qualsiasi utente
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
    # ❌ Idem: nessun controllo di proprieta'
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT f.id, f.numero, f.data, f.descrizione, f.importo, u.username
        FROM fatture f JOIN utenti u ON f.utente_id = u.id
        WHERE f.id = ?
    """, (fattura_id,))
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
    print("🏦  BancaPiccola-VULN in esecuzione su http://127.0.0.1:5000")
    print("=" * 70)
    print("⚠️  Applicazione DIDATTICA con vulnerabilita' intenzionali.")
    print("⚠️  Non esporre su rete pubblica.\n")
    print("Credenziali di test: admin/admin123, mario/mario123,")
    print("                     giulia/giulia2025, luca/passwordLuca!\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
