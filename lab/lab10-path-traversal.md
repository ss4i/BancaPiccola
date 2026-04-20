# Laboratorio Capitolo 10 — Path Traversal

> **Prerequisito:** Capitolo 10 della dispensa.
> **Tempo:** 60 minuti.
> **Obiettivo:** sfruttare Path Traversal per leggere file fuori dalla cartella consentita, applicare tre difese sovrapposte, verificare che il file "segreto" non sia più accessibile.

---

## Setup

Lancia `BancaPiccola-vuln`. Al primo avvio, l'app crea automaticamente:

- La cartella `documenti/` con 9 file PDF (gli allegati delle fatture)
- Il file `SEGRETO.txt` nella cartella principale (un file "esca" **fuori** da `documenti/`)

Verifica:

```bash
ls BancaPiccola-vuln/documenti/
ls BancaPiccola-vuln/SEGRETO.txt
```

---

## Attacco 1 — Lettura del file SEGRETO.txt

### Istruzioni

Fai login come qualsiasi utente. Dalla dashboard, clicca su una fattura, poi su "Scarica documento PDF". L'URL nella barra del browser è:

```
http://127.0.0.1:5000/download?file=fattura-001.pdf
```

Il file viene scaricato. Normale.

Ora **modifica il parametro `file`**. Prova:

```
http://127.0.0.1:5000/download?file=../SEGRETO.txt
```

Scarica un file chiamato `SEGRETO.txt` con contenuto:

```
CHIAVE CEO BancaPiccola: TOPSECRET-CEO-2025
Se leggi questo file, stai sfruttando una vulnerabilita' Path Traversal...
```

**Sei uscito dalla cartella `documenti/`** e hai letto un file che non dovevi vedere.

---

## Attacco 2 — Lettura di file di sistema

Su Linux/macOS, prova:

```
http://127.0.0.1:5000/download?file=../../../../etc/passwd
```

Il server tenta di aprire `/etc/passwd`. Se il processo Flask è in esecuzione come utente normale (non `root`), leggerà comunque il file perché `/etc/passwd` è leggibile da tutti gli utenti del sistema.

Vedrai il contenuto: lista degli utenti del sistema operativo, shell preferite, home directory.

### Su Windows

```
http://127.0.0.1:5000/download?file=../../Windows/win.ini
```

Apparirà `win.ini`, un file di configurazione di sistema.

### Obiettivi più ambiziosi (non tutti funzioneranno, dipende dai permessi)

| Path | Contiene |
|---|---|
| `../bancapiccola.db` | L'intero database SQLite (puoi aprirlo con DB Browser) |
| `../app.py` | Il codice sorgente dell'applicazione (con la secret_key e le credenziali di test) |
| `../../../../etc/shadow` | Hash delle password di sistema (solo se root — non lo sei, errore) |
| `../../../../root/.ssh/id_rsa` | Chiave privata SSH (solo se sei root, o hai una configurazione sbagliata) |

---

## Attacco 3 — Lettura del codice sorgente

Il caso realistico di un attacco Path Traversal in produzione: lettura del codice sorgente e dei file di configurazione.

```bash
curl "http://127.0.0.1:5000/download?file=../app.py" -b /tmp/cookie -o app-rubata.py
```

(Richiede di essere loggato, perché l'endpoint `/download` richiede autenticazione. Fai prima login, salva il cookie, poi usa il cookie.)

Apri `app-rubata.py`: è l'intera applicazione, inclusa:

- `app.secret_key = "bancapiccola-secret-2024"` → l'attaccante ora può **forgiare** cookie di sessione validi
- struttura del database, query SQL, endpoint nascosti
- eventuali chiavi API / credenziali di servizi esterni (se ci fossero)

Con la secret_key, puoi costruire un cookie di sessione che afferma di essere admin:

```python
import itsdangerous, json
secret = "bancapiccola-secret-2024"
signer = itsdangerous.URLSafeTimedSerializer(secret, "cookie-session")
# Payload amministratore
payload = {"utente_id": 1, "username": "admin", "ruolo": "admin"}
cookie = signer.dumps(payload)
print(cookie)
```

(Non è esattamente il formato Flask ma ci assomiglia: Flask usa la libreria `itsdangerous` con un formato specifico. Con 15 minuti di lettura del codice Flask lo riproduci.) **Risultato: accesso come admin senza password.**

---

## Correzione

Apri `BancaPiccola-vuln/app.py`. Trova la funzione `download()`:

```python
# ❌ VULNERABILE
@app.route("/download")
def download():
    if "utente_id" not in session:
        return redirect("/login")
    filename = request.args.get("file", "")
    percorso = os.path.join(DOCUMENTI_DIR, filename)
    return send_file(percorso, as_attachment=True)
```

**Sostituisci con:**

```python
# ✅ SICURO — 3 difese sovrapposte + ownership check
ESTENSIONI_AMMESSE = {".pdf"}

@app.route("/download")
def download():
    if "utente_id" not in session:
        return redirect("/login")

    filename = request.args.get("file", "")

    # Difesa 1 — basename: rimuove qualsiasi componente di percorso
    nome_base = os.path.basename(filename)
    if not nome_base:
        abort(400)

    # Difesa 2 — whitelist estensioni
    estensione = os.path.splitext(nome_base)[1].lower()
    if estensione not in ESTENSIONI_AMMESSE:
        abort(403)

    # Difesa 3 — realpath + verifica prefisso (protegge da symlink, doppia codifica, ...)
    percorso_proposto = os.path.join(DOCUMENTI_DIR, nome_base)
    percorso_reale = os.path.realpath(percorso_proposto)
    if not percorso_reale.startswith(DOCUMENTI_DIR + os.sep):
        abort(403)

    if not os.path.isfile(percorso_reale):
        abort(404)

    # Bonus — ownership check: la risorsa deve essere associata a una fattura dell'utente
    conn = db()
    cur = conn.cursor()
    if session.get("ruolo") == "admin":
        cur.execute("SELECT 1 FROM fatture WHERE allegato = ?", (nome_base,))
    else:
        cur.execute("SELECT 1 FROM fatture WHERE allegato = ? AND utente_id = ?",
                    (nome_base, session["utente_id"]))
    trovato = cur.fetchone()
    conn.close()
    if not trovato:
        abort(404)

    return send_file(percorso_reale, as_attachment=True)
```

E assicurati che in cima al file ci sia:

```python
DOCUMENTI_DIR = os.path.realpath(
    os.path.join(os.path.dirname(__file__), "documenti")
)
```

(Il `realpath` iniziale è importante: se lo salviamo già "canonico", il confronto `startswith` è più affidabile.)

Salva e riavvia.

### Verifica

1. Scarica una tua fattura normalmente → funziona
2. `?file=../SEGRETO.txt` → 403 Forbidden
3. `?file=../../../../etc/passwd` → 403 Forbidden
4. `?file=../app.py` → 403 Forbidden (niente `.pdf`)
5. `?file=../documenti/fattura-001.pdf` → 403 Forbidden (anche se finisce in `.pdf`, dopo il `basename` diventa `fattura-001.pdf`, ma se tenti `/fattura/altrui` non passa l'ownership)

**Hai chiuso Path Traversal a 4 livelli.**

---

## Domande di riflessione

1. Perché `os.path.basename` da solo non basta? Fai un esempio di attacco che lo aggira.
2. Perché la whitelist delle estensioni è "in supporto" e non una difesa primaria? (Suggerimento: cosa succede se esiste un file `file.pdf.txt` con contenuto sensibile?)
3. `os.path.realpath` risolve gli anelli di symlink. Perché è importante farlo **prima** di verificare il prefisso, e non dopo?
4. Il **principio di difesa in profondità** dice di sovrapporre più livelli. Se la whitelist estensioni da sola bloccasse il 99% degli attacchi e `realpath` il 99%, insieme arriverebbero al 99,99%. Perché nelle applicazioni bancarie/mediche/etc. si applicano comunque **tutte** le difese, non solo quelle più efficaci?
5. Il metodo "preferibile" (sezione 10.2 della dispensa) è **non esporre mai nomi file dall'utente**, passando l'ID del record. Implementa questa variante: modifica l'endpoint in `/download/<int:fattura_id>` e recupera il nome del file dal database. Quali difese precedenti puoi rimuovere, e quali rimangono comunque utili?
