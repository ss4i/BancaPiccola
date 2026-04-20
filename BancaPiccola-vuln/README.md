# BancaPiccola-vuln

**Applicazione web didattica INTENZIONALMENTE VULNERABILE** per il corso "Sviluppo Sicuro del Software" (ITS Prodigi / ITS Empoli / SS4I).

---

## ⚠️ Avvertenza

Questa applicazione contiene vulnerabilità di sicurezza **deliberate** a scopo didattico. **Non eseguirla mai su una rete pubblica o esposta a internet.** È progettata esclusivamente per girare in `localhost` (127.0.0.1) durante i laboratori.

Se la esponi accidentalmente su una rete condivisa (Wi-Fi universitario, rete aziendale, VPS cloud), chiunque può:

- accedere al database utenti tramite SQL Injection
- leggere file di sistema tramite Path Traversal
- eseguire JavaScript nei browser altrui tramite XSS
- impersonare altri utenti tramite furto di cookie

Usa solo in ambiente locale isolato.

---

## Requisiti

- Python 3.10 o superiore (testato fino a 3.13)
- pip (incluso in Python)
- Un browser (Firefox o Chrome)

Strumenti consigliati per i laboratori:

- [DB Browser for SQLite](https://sqlitebrowser.org/) per esplorare il database
- `curl` (incluso in Windows 10+, macOS, Linux)
- Estensione [REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client) per VS Code

---

## Installazione

Da terminale, nella cartella `BancaPiccola-vuln/`:

**1. Crea un ambiente virtuale**

```bash
python -m venv venv
```

**2. Attiva l'ambiente virtuale**

- Windows (PowerShell): `.\venv\Scripts\Activate.ps1`
- Windows (cmd): `.\venv\Scripts\activate.bat`
- macOS/Linux: `source venv/bin/activate`

**3. Installa le dipendenze**

```bash
pip install -r requirements.txt
```

> ⚠️ Le versioni in `requirements.txt` sono **deliberatamente vecchie** (con CVE noti) per il Lab del Capitolo 9. Se `pip` si lamenta di compatibilità Python, aggiorna le versioni (vedi il lab del Cap. 9 per la procedura corretta).

**4. Avvia l'app**

```bash
python app.py
```

Apri nel browser: <http://127.0.0.1:5000>

Al primo avvio l'app crea automaticamente:

- `bancapiccola.db` (il database SQLite)
- 9 file PDF di esempio in `documenti/`
- `SEGRETO.txt` nella cartella principale (file "esca" per Path Traversal)

---

## Credenziali di test

| Username | Password | Ruolo | Scopo |
|---|---|---|---|
| `admin` | `admin123` | admin | Accesso al pannello amministrativo |
| `mario` | `mario123` | cliente | Utente base con 3 fatture |
| `giulia` | `giulia2025` | cliente | Utente con 4 fatture |
| `luca` | `passwordLuca!` | cliente | Utente con 2 fatture |

---

## Mappa delle vulnerabilità

| # | Capitolo | Vulnerabilità | Endpoint | Tipo |
|---|---|---|---|---|
| 1 | Cap. 5 | SQL Injection | `POST /login` | Login bypass |
| 2 | Cap. 5 | SQL Injection | `GET /cerca?q=` | UNION-based |
| 3 | Cap. 6 | IDOR | `GET /fattura/<id>` | Lettura |
| 4 | Cap. 6 | IDOR | `GET /profilo/<id>` | Lettura |
| 5 | Cap. 6 | IDOR + Mass Assignment | `POST /profilo/<id>` | Modifica ruolo |
| 6 | Cap. 6 | BOLA (IDOR su API) | `GET /api/utenti/<id>` | No autenticazione |
| 7 | Cap. 6 | BOLA (IDOR su API) | `GET /api/fatture/<id>` | No autenticazione |
| 8 | Cap. 7 | Crypto Failures | Hash MD5 senza salt | Tabella `utenti.password` |
| 9 | Cap. 7 | Crypto Failures | Secret_key debole | `"bancapiccola-secret-2024"` |
| 10 | Cap. 8 | Reflected XSS | `GET /cerca?q=` | Output senza escape |
| 11 | Cap. 8 | Stored XSS | `POST /prodotto/<id>` | Commento salvato e mostrato |
| 12 | Cap. 9 | Supply Chain | `requirements.txt` | 6 dipendenze con CVE |
| 13 | Cap. 10 | Path Traversal | `GET /download?file=` | Lettura arbitraria |

---

## Istruzioni dettagliate dei laboratori

Le istruzioni passo-passo di ogni laboratorio sono nella cartella [`../lab/`](../lab/) del repository:

- `lab05-sqli.md` — SQL Injection (login bypass + UNION)
- `lab06-idor.md` — IDOR + esfiltrazione automatica
- `lab07-crypto.md` — Cracking MD5 con wordlist
- `lab08-xss.md` — XSS Reflected e Stored + furto sessione
- `lab09-supplychain.md` — `pip-audit` e aggiornamento dipendenze
- `lab10-path-traversal.md` — Lettura file di sistema

---

## Output di debug

L'app stampa nel terminale:

- `[DEBUG SQL] <query>` — ogni query SQL effettivamente eseguita (utile per vedere "in diretta" come SQLi trasforma la query)
- `[DEBUG PATH] <percorso>` — ogni tentativo di apertura file (utile per Path Traversal)

Tieni aperto il terminale accanto al browser durante i laboratori: la maggior parte dell'apprendimento sta nel vedere cosa arriva al server.

---

## Pulire e ricominciare

Se vuoi resettare il database e i file di esempio:

```bash
# Cancella il database e i file generati
rm bancapiccola.db SEGRETO.txt
rm -f documenti/*.pdf

# Rilancia l'app (ricrea tutto)
python app.py
```

Su Windows usa `del` al posto di `rm`.

---

## Confronto con la versione sicura

La cartella `../BancaPiccola-secure/` contiene la **stessa applicazione** con tutte le vulnerabilità corrette. Dopo aver completato un laboratorio, confronta la tua correzione con quella di riferimento:

```bash
# Confronto diretto fra i due file
diff ../BancaPiccola-vuln/app.py ../BancaPiccola-secure/app.py | less
```

Vedrai esattamente quali righe sono cambiate per chiudere ogni vulnerabilità.

---

## Licenza

MIT License. Vedi `../LICENSE`. Ambiente didattico fornito "as is" senza garanzia alcuna, uso a rischio dell'utilizzatore.
