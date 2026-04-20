# BancaPiccola

Applicazione web didattica intenzionalmente vulnerabile (+ versione corretta) usata nel corso **"Sviluppo Sicuro del Software"** per studenti del primo anno ITS (ITS Prodigi / ITS Empoli / SS4I S.r.l.).

---

## ⚠️ Avvertenza

Questo repository contiene software **deliberatamente insicuro** per scopi educativi. **Non eseguirlo mai esposto su internet** o su reti pubbliche. Va eseguito solo in locale (`127.0.0.1`) durante le esercitazioni.

Se lo esponi per errore, chiunque sulla rete può:

- rubare credenziali, cookie di sessione, dati personali degli utenti di test
- leggere il codice sorgente e i file di sistema
- iniettare JavaScript che esegue codice nei browser altrui

Le responsabilità di un uso improprio ricadono sull'utilizzatore (vedi `LICENSE`).

---

## Contenuto del repository

```
BancaPiccola/
├── README.md                    # questo file
├── LICENSE                      # MIT
├── .gitignore                   # file da non committare (db, venv, cache)
├── BancaPiccola-vuln/           # applicazione INTENZIONALMENTE VULNERABILE
│   ├── app.py                   #   — 1 file con tutta l'app + vulnerabilità
│   ├── requirements.txt         #   — dipendenze DELIBERATAMENTE VECCHIE (con CVE)
│   ├── README.md                #   — setup, credenziali, mappa vulnerabilità
│   └── documenti/               #   — PDF generati al primo avvio
├── BancaPiccola-secure/         # stessa app, con tutte le difese applicate
│   ├── app.py                   #   — versione sicura
│   ├── requirements.txt         #   — dipendenze aggiornate
│   └── README.md                #   — mappa delle difese applicate
└── lab/                         # istruzioni passo-passo dei laboratori
    ├── lab05-sqli.md            # Cap. 5 — SQL Injection
    ├── lab06-idor.md            # Cap. 6 — IDOR e Broken Access Control
    ├── lab07-crypto.md          # Cap. 7 — Password e crittografia
    ├── lab08-xss.md             # Cap. 8 — Cross-Site Scripting
    ├── lab09-supplychain.md     # Cap. 9 — Software Supply Chain
    └── lab10-path-traversal.md  # Cap. 10 — Path Traversal
```

---

## Quick start

### Requisiti

- **Python 3.10+** (testato fino a 3.13)
- `pip`, `venv` (inclusi in Python)
- Un browser moderno (Firefox o Chrome)

### Installazione (versione vulnerabile, per i laboratori)

```bash
git clone https://github.com/ss4i/BancaPiccola.git
cd BancaPiccola/BancaPiccola-vuln

python -m venv venv
source venv/bin/activate                # Linux/macOS
.\venv\Scripts\Activate.ps1             # Windows PowerShell

pip install -r requirements.txt
python app.py
```

Apri: <http://127.0.0.1:5000>

Al primo avvio l'app crea automaticamente il database SQLite e i PDF di esempio.

### Credenziali di test

| Username | Password | Ruolo |
|---|---|---|
| `admin` | `admin123` | admin |
| `mario` | `mario123` | cliente |
| `giulia` | `giulia2025` | cliente |
| `luca` | `passwordLuca!` | cliente |

---

## Mappa capitolo → vulnerabilità → laboratorio

| Capitolo | Vulnerabilità OWASP | Endpoint vulnerabile | Lab |
|---|---|---|---|
| 5 | A05 SQL Injection | `POST /login`, `GET /cerca` | [lab05-sqli.md](lab/lab05-sqli.md) |
| 6 | A01 Broken Access Control | `GET /fattura/<id>`, `POST /profilo`, `GET /api/*` | [lab06-idor.md](lab/lab06-idor.md) |
| 7 | A04 Cryptographic Failures | Hashing MD5 delle password, secret_key debole | [lab07-crypto.md](lab/lab07-crypto.md) |
| 8 | A05 XSS (Injection) | `GET /cerca` (Reflected), `POST /prodotto/<id>` (Stored) | [lab08-xss.md](lab/lab08-xss.md) |
| 9 | A03 Software Supply Chain | `requirements.txt` con CVE noti | [lab09-supplychain.md](lab/lab09-supplychain.md) |
| 10 | A01 (Path Traversal) | `GET /download?file=` | [lab10-path-traversal.md](lab/lab10-path-traversal.md) |

---

## Flusso di un laboratorio

Ogni laboratorio segue la stessa struttura:

1. **Attacco** — istruzioni passo-passo per sfruttare la vulnerabilità su `BancaPiccola-vuln`
2. **Correzione** — diff preciso del codice, prima/dopo, con spiegazione
3. **Verifica** — rieseguire gli attacchi e confermare che ora falliscono
4. **Confronto** con `BancaPiccola-secure` (riferimento della correzione ottimale)
5. **Domande di riflessione** — non c'è autovalutazione nel codice; il docente assegna e valuta

---

## Confronto vuln ↔ secure

Per vedere a colpo d'occhio tutte le modifiche applicate:

```bash
diff -u BancaPiccola-vuln/app.py BancaPiccola-secure/app.py | less
```

Il diff mostra ~200 righe di differenze, ogni riga è una difesa applicata.

---

## Link utili

- **Dispensa del corso**: documento Word fornito dal docente (`dispensa-sviluppo-sicuro-software.docx`)
- **OWASP Top 10:2025**: <https://owasp.org/Top10/>
- **CWE (Common Weakness Enumeration)**: <https://cwe.mitre.org/>
- **National Vulnerability Database**: <https://nvd.nist.gov/>
- **DB Browser for SQLite**: <https://sqlitebrowser.org/>

---

## Contatti

**Alessandro Manneschi**
SS4I S.r.l. — ITS Prodigi — ITS Empoli
Corso *Sistemistica Cybersecurity*, A.F. 2024/2025

Segnalazioni di errori nella dispensa o nel codice: apri una **Issue** su GitHub (preferibile) o scrivi all'indirizzo email del docente fornito in classe.

---

## Licenza

**MIT License** — vedi [LICENSE](LICENSE). Materiale didattico fornito "as is" senza garanzia di alcun tipo. Il software contiene vulnerabilità deliberate: usa a tuo rischio, solo in ambiente locale controllato.
