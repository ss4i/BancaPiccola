#!/usr/bin/env bash
# =============================================================================
#  push-iniziale.sh — Setup e push iniziale del repository BancaPiccola
#  su https://github.com/ss4i/BancaPiccola
# =============================================================================
#
#  PREREQUISITI:
#  1. Hai installato git e sei autenticato su GitHub (con SSH key o
#     credential helper di HTTPS, es. gh auth login)
#  2. Il repository "BancaPiccola" e' gia' stato creato su GitHub:
#       - vai su https://github.com/organizations/ss4i/repositories/new
#       - nome: BancaPiccola
#       - descrizione: "Applicazione didattica vulnerabile per il corso..."
#       - Pubblico
#       - NON inizializzare con README/LICENSE/.gitignore (ce li abbiamo gia')
#
#  USO:
#    chmod +x push-iniziale.sh
#    ./push-iniziale.sh
#
#  Nota: lo script usa HTTPS. Se preferisci SSH, modifica la riga REMOTE_URL.
# =============================================================================

set -euo pipefail

REMOTE_URL="https://github.com/ss4i/BancaPiccola.git"
# Per SSH commenta sopra e decommenta sotto:
# REMOTE_URL="git@github.com:ss4i/BancaPiccola.git"

BRANCH="main"

echo "============================================================"
echo "  Setup iniziale repository BancaPiccola"
echo "  Remote: $REMOTE_URL"
echo "============================================================"
echo

# 1. Verifica di essere nella cartella giusta
if [ ! -f "README.md" ] || [ ! -d "BancaPiccola-vuln" ]; then
  echo "❌ Errore: lancia questo script dalla cartella radice di BancaPiccola/"
  echo "   (quella che contiene README.md, BancaPiccola-vuln/, BancaPiccola-secure/, lab/)"
  exit 1
fi

# 2. Inizializza git (se non e' gia' un repo)
if [ ! -d ".git" ]; then
  echo "→ Inizializzo repository git..."
  git init -b "$BRANCH"
else
  echo "→ Repository git gia' inizializzato, continuo..."
  # Mi assicuro che il branch primario si chiami "main"
  git branch -M "$BRANCH" 2>/dev/null || true
fi

# 3. Configura remote (sostituisce se esiste gia')
if git remote get-url origin >/dev/null 2>&1; then
  echo "→ Aggiorno remote origin..."
  git remote set-url origin "$REMOTE_URL"
else
  echo "→ Aggiungo remote origin..."
  git remote add origin "$REMOTE_URL"
fi

# 4. Verifica configurazione utente git
if [ -z "$(git config user.email || true)" ]; then
  echo
  echo "⚠️  Nessuna user.email configurata in git."
  echo "   Configurala con:"
  echo "     git config user.email \"alessandro@ss4i.it\""
  echo "     git config user.name  \"Alessandro Manneschi\""
  echo
  echo "   Oppure --global se vuoi che valga per tutti i repo."
  exit 1
fi

# 5. Stage di tutti i file (escludendo quelli in .gitignore)
echo "→ Stage dei file..."
git add .

# 6. Mostra cosa sta per essere committato
echo
echo "============================================================"
echo "  File che verranno committati:"
echo "============================================================"
git status --short
echo

# 7. Conferma
read -p "Procedo con il commit e il push? [y/N] " conferma
if [[ ! "$conferma" =~ ^[Yy]$ ]]; then
  echo "Annullato."
  exit 0
fi

# 8. Commit
echo "→ Creazione commit iniziale..."
git commit -m "Initial release — BancaPiccola v1.0

Applicazione web didattica per il corso 'Sviluppo Sicuro del Software'
(ITS Prodigi / ITS Empoli / SS4I S.r.l. - A.F. 2024/2025).

Contenuto:
- BancaPiccola-vuln: applicazione INTENZIONALMENTE VULNERABILE
  con vulnerabilita' mappate ai capitoli 5-10 della dispensa
  (SQL Injection, IDOR, Crypto Failures, XSS, Supply Chain,
  Path Traversal)
- BancaPiccola-secure: stessa applicazione con tutte le difese
  applicate (query parametrizzate, bcrypt, ownership check,
  CSP, escape automatico, basename+realpath)
- lab/: 6 laboratori passo-passo (uno per capitolo)

Stack: Python 3.10+ / Flask / SQLite / bcrypt"

# 9. Push
echo "→ Push su origin/$BRANCH..."
git push -u origin "$BRANCH"

echo
echo "============================================================"
echo "  ✅ Push completato!"
echo "  Repository: $REMOTE_URL"
echo "============================================================"
echo
echo "Prossimi passi consigliati:"
echo "  1. Vai su GitHub e verifica che tutti i file siano presenti"
echo "  2. Aggiungi una descrizione e i topic al repo"
echo "  3. Configura Dependabot:  Settings > Code security > Dependabot"
echo "  4. Abilita branch protection su main"
echo "  5. Comunica l'URL agli studenti"
