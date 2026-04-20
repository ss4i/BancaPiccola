# Laboratorio Capitolo 9 — Software Supply Chain

> **Prerequisito:** Capitolo 9 della dispensa.
> **Tempo:** 60 minuti.
> **Obiettivo:** scansionare le dipendenze con `pip-audit`, vedere decine di CVE, aggiornare a versioni sicure, generare la SBOM.

---

## Setup

Per questo lab **serve un ambiente virtuale dedicato**: vogliamo installare versioni volutamente vecchie delle librerie senza "contaminare" il setup che hai usato per gli altri lab.

```bash
cd BancaPiccola-vuln/
python -m venv venv-lab9
# Attiva:
source venv-lab9/bin/activate          # Linux/macOS
.\venv-lab9\Scripts\Activate.ps1       # Windows

pip install -r requirements.txt
```

Se pip si lamenta di incompatibilità con la tua versione di Python (le versioni vecchie di Flask possono non supportare Python 3.12+), prova con Python 3.10 o 3.11. In ultima istanza, aggiorna solo le versioni che pip rifiuta — l'importante è avere versioni *obsolete*, non necessariamente *le più antiche possibili*.

---

## Attacco — vedere le vulnerabilità

### Installa pip-audit

```bash
pip install pip-audit
```

### Scansiona

```bash
pip-audit
```

### Output atteso

Vedrai una lista come:

```
Found X known vulnerabilities in Y packages
Name      Version  ID                    Fix Versions
--------  -------  --------------------  --------------
flask     1.0.0    PYSEC-2019-179        1.0.3
flask     1.0.0    PYSEC-2023-62         2.2.5, 2.3.2
jinja2    2.10     GHSA-462w-v97r-4m45   2.11.3
jinja2    2.10     GHSA-h75v-3vvj-5mfj   2.10.1
pyyaml    5.1      GHSA-rprw-h62v-c2w7   5.4
pyyaml    5.1      GHSA-8q59-q68h-6hv4   5.4
requests  2.20.0   GHSA-x84v-xcm2-53pg   2.20.0
werkzeug  0.14.1   PYSEC-2019-83         0.15.3
werkzeug  0.14.1   GHSA-xg9f-g7g7-2323   1.0.1
...
```

Il tuo progetto ha **un numero a due cifre di CVE pendenti**. In produzione, significa che stai esponendo un attaccante a opportunità note, tutte documentate e sfruttabili.

### Esplora un CVE

Prendine uno, per esempio `PYSEC-2019-179`. Cercalo su:

- **PyPI Advisory**: <https://github.com/pypa/advisory-database/tree/main/vulns>
- **GitHub Advisory**: <https://github.com/advisories>
- **CVE di MITRE**: <https://www.cvedetails.com>

Trova: descrizione tecnica, CVSS score, versioni affette, versione che risolve, eventuali exploit pubblici.

---

## Correzione

### Aggiorna `requirements.txt`

Sostituisci il contenuto con:

```
flask>=3.0.3
werkzeug>=3.0.4
jinja2>=3.1.4
markupsafe>=2.1.5
itsdangerous>=2.2.0
bcrypt>=4.2.0
```

### Reinstalla

```bash
pip install -r requirements.txt --upgrade
```

### Riscansiona

```bash
pip-audit
```

Output:

```
No known vulnerabilities found
```

**Ci hai messo 3 minuti a sistemare decine di CVE** — ed è il "minimo sindacale" della gestione supply chain. Il fatto che nel mondo reale così tanti team non lo facciano è una delle ragioni per cui A03 (Supply Chain Failures) è al terzo posto della OWASP 2025.

---

## Generare la SBOM

### Installa lo strumento

```bash
pip install cyclonedx-bom
```

### Genera

```bash
cyclonedx-py environment -o sbom.json
```

### Esamina

Apri `sbom.json` in VS Code. Vedrai un JSON con:

- **bomFormat / specVersion**: formato e versione dello standard
- **serialNumber**: identificatore univoco di questa SBOM
- **metadata.timestamp**: quando è stata generata
- **components**: array di tutti i pacchetti, con nome, versione, licenza, `purl` (Package URL)

Esempio di una voce:

```json
{
  "type": "library",
  "name": "Flask",
  "version": "3.0.3",
  "licenses": [{"license": {"id": "BSD-3-Clause"}}],
  "purl": "pkg:pypi/flask@3.0.3"
}
```

### Cosa ne fai

- **Oggi**: la alleghi alle release dell'applicazione. Uno strumento come **Dependency-Track** (<https://dependencytrack.org/>) la importa in continuo e ti notifica via email/webhook quando esce un nuovo CVE che riguarda una delle tue dipendenze.
- **Dal 2027**: è **obbligatoria** per chi vende software nell'UE secondo il **Cyber Resilience Act**. La allegherai a ogni release formale del prodotto.

---

## CI/CD — audit automatico

Per impedire che nuove vulnerabilità vengano introdotte, configura una pipeline GitHub Actions.

Crea `.github/workflows/security.yml` nella **root del repository**:

```yaml
name: Security Audit
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 8 * * 1'  # ogni lunedì alle 8:00 UTC

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install
        run: |
          python -m pip install --upgrade pip
          pip install -r BancaPiccola-secure/requirements.txt
          pip install pip-audit
      - name: Audit
        run: pip-audit -r BancaPiccola-secure/requirements.txt --strict
```

`--strict` fa **fallire** la pipeline se trova qualunque CVE. Combinato con la branch protection di GitHub, impedisce il merge se qualcuno tenta di aggiungere una dipendenza con CVE pendenti.

---

## Dependabot

Configura Dependabot per aggiornamenti automatici. Crea `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/BancaPiccola-secure"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
  - package-ecosystem: "pip"
    directory: "/BancaPiccola-vuln"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "monthly"
```

Dependabot scansionerà settimanalmente e aprirà PR con aggiornamenti. Per vulnerabilità di sicurezza, le PR vengono aperte **immediatamente** (non solo settimanalmente).

---

## Domande di riflessione

1. Perché `pip-audit` trova CVE anche in dipendenze che tu non hai scritto in `requirements.txt` (es. `markupsafe` se tu hai scritto solo `flask`)?
2. Cosa fa esattamente `cyclonedx-py environment`? È diverso da `cyclonedx-py requirements`? Quando useresti uno o l'altro?
3. Supponi che un CVE sia segnalato in una dipendenza ma **non esiste ancora una patch**. Come ti comporti nel frattempo?
4. Il caso **XZ Utils** (CVE-2024-3094, marzo 2024) non sarebbe stato rilevato da `pip-audit` anche se quella libreria fosse stata fra le tue dipendenze. Perché?
5. Hai un progetto che usa 47 librerie. 43 hanno licenza MIT/BSD (permissive). 4 hanno licenza GPL. Pubblichi il tuo software come servizio SaaS. Hai obblighi legali?
