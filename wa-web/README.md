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
- `POST /logout {acc}` → cierra sesión

`acc` = el email de la cuenta de RealProfit (aislación por cuenta).
