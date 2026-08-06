# ProfitFlow — App independiente

Dashboard de ProfitFlow **en blanco**, como app aparte (nada de METAFY/VisionPure).
Pensado para subir a la web y que cada usuario conecte **su propio MercadoPago**.

## Correr local

```bash
cd "PROFITFLOW-APP"
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
# abre http://127.0.0.1:8010
```

## Estado

- **Fase 1 (hecho):** dashboard limpio, todo en cero. Sirve `pf.html` con datos vacíos
  y endpoints stub para que no rompa nada.
- **Fase 2 (pendiente):** "Conectar MercadoPago" — OAuth de MP por usuario; con el token
  de cada uno se leen sus pagos/ventas y se llenan los números del dashboard. Requiere:
  crear una app en Mercado Pago Developers (Client ID + Secret + redirect URL) y un
  dominio/hosting con HTTPS.

## Subir a la web

Cualquier host de Python sirve (Render, Railway, Fly.io, un VPS…). Producción:

```bash
gunicorn -b 0.0.0.0:8010 app:app
```
