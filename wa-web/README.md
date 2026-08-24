# RealProfit — Servicio WhatsApp Web (Baileys)

Servicio Node chico que habla WhatsApp Web (protocolo, sin navegador). Da el **QR**, mantiene
**una sesión por cuenta** (aislada) y trae **chats con foto**. RealProfit (Flask) le habla por HTTP.

## Deploy en Render (segundo servicio, aparte de RealProfit)

1. Render → **New → Web Service** → mismo repo (`cristianacostabtw-glitch/realprofit`).
2. **Root Directory:** `wa-web`
3. **Runtime:** Node · **Build Command:** `npm install` · **Start Command:** `node index.js`
4. **Disk:** agregá un disco (ej. 1 GB) montado en **`/var/data`** (para no re-escanear el QR).
5. **Environment:**
   - `WA_WEB_SECRET` = una clave larga inventada (la misma va en RealProfit).
   - `WA_DATA_DIR` = `/var/data/wa-web`
   - `WA_WEB_HOOK` = `https://realprofitapp.com/wa-web-hook` (para que el **bot** conteste fuera de horario; opcional, se puede agregar después).
6. Deploy → copiá la **URL** del servicio (ej. `https://realprofit-wa-web.onrender.com`).

## En RealProfit (el servicio Flask), agregá en Environment:

- `WA_WEB_URL` = la URL del servicio de arriba
- `WA_WEB_SECRET` = la misma clave

Con eso, la pestaña **Web** de la sección WhatsApp de RealProfit levanta el QR y los chats.

## Endpoints (uso interno, header `x-wa-secret`)

- `POST /connect {acc}` → arranca/retoma sesión → `{status, qr?}`
- `GET /status?acc=` → estado
- `GET /qr?acc=` → QR (data URL) mientras espera escaneo
- `GET /chats?acc=&limit=` → `[{id, tel, name, photo, last, ts, unread}]`
- `POST /send {acc, to, text}` → envía un mensaje (lo usa el bot para responder)
- `POST /logout {acc}` → cierra sesión

`acc` = el email de la cuenta de RealProfit (aislación por cuenta).

## El bot fuera de horario

Cuando `WA_WEB_HOOK` apunta a RealProfit, cada mensaje entrante nuevo le llega a RealProfit.
Ahí RealProfit mira la **config del bot de esa cuenta** (horarios de atención humana / 24h / apagado):
si está fuera de horario y el bot está prendido, genera la respuesta con Claude (con el contexto
de **esa** tienda) y la manda de vuelta por `POST /send`. Todo aislado por cuenta.
