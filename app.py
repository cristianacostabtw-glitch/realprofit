"""
ProfitFlow (app independiente) — sirve SOLO el dashboard, EN BLANCO.

Fase 1: dashboard limpio, sin métricas (todo en cero). Pensado para subir a la web
y que cada usuario conecte SU PROPIO MercadoPago (Fase 2: OAuth de MP → llena los datos).

Corre en su propio puerto (8010), sin nada de METAFY/VisionPure.
"""
from __future__ import annotations

import datetime as _dt
import json as _json
import secrets as _secrets
import urllib.parse as _url
from pathlib import Path

import requests
from flask import Flask, Response, jsonify, redirect, request, session

import os as _os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

RAIZ = Path(__file__).resolve().parent
app = Flask(__name__)
app.secret_key = _os.getenv("SECRET_KEY", "profitflow-dev-key-cambiar-en-produccion")

# Rate limiting: frena a quien intente martillar los endpoints sensibles (OAuth) para tirar
# la app o abusar. NO limita el dashboard (así no se rompe la carga normal).
limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")


@app.after_request
def _headers_seguridad(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp

# ---------------- MercadoPago OAuth (conectar con un click) ----------------
MP_SECRETS = RAIZ / "mp_secrets.json"     # tu Client ID + Secret (los pega el dueño de la app)
MP_TOKENS = RAIZ / "mp_tokens.json"       # tokens de cada usuario que se conecta


def _mp_cfg() -> dict:
    # En la web (Render) usamos variables de entorno; en local, el archivo mp_secrets.json.
    import os
    try:
        c = _json.loads(MP_SECRETS.read_text(encoding="utf-8"))
    except Exception:
        c = {}
    return {"client_id": os.getenv("MP_CLIENT_ID") or c.get("client_id", ""),
            "client_secret": os.getenv("MP_CLIENT_SECRET") or c.get("client_secret", ""),
            "redirect_uri": os.getenv("MP_REDIRECT_URI") or c.get("redirect_uri",
                                                                    "http://127.0.0.1:8010/mp/callback")}


def _mp_tokens() -> dict:
    try:
        return _json.loads(MP_TOKENS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _mp_save_token(key, data) -> None:
    d = _mp_tokens()
    d[str(key)] = data
    MP_TOKENS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


# ---------------- Cuentas de usuario (email + contraseña) ----------------
USERS = RAIZ / "users.json"   # cada usuario de la app; su MP se guarda por email en mp_tokens


def _users() -> dict:
    try:
        return _json.loads(USERS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _users_save(d: dict) -> None:
    USERS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def _user_actual():
    """Email del usuario logueado (o None)."""
    return session.get("email")


# Deja SOLO "Dashboard" e "Integraciones" en el menú, y saca el logo. Como pf.html es React
# compilado, no lo editamos: ocultamos con CSS/JS inyectado + MutationObserver (aguanta los
# re-render del SPA sin romper nada).
_SOLO_DASH = """
<style>
 aside > a[aria-label="Ir al Dashboard"]{display:none!important}      /* logo de arriba */
</style>
<script>
(function(){
 function strip(){
  var nav=document.querySelector('aside nav'); if(!nav)return;
  var kids=nav.querySelectorAll(':scope > *');
  for(var i=0;i<kids.length;i++){
   var ch=kids[i];
   var keep=ch.querySelector('a[href="/dashboard"],a[href="/integraciones"]');
   ch.style.display = keep ? '' : 'none';   // oculta cada opción y los títulos de grupo
  }
 }
 function boot(){ strip(); try{ new MutationObserver(strip).observe(document.body,{childList:true,subtree:true}); }catch(e){} }
 if(document.readyState!=='loading') boot(); else document.addEventListener('DOMContentLoaded', boot);
})();
</script>
<div id="mpConnect" style="position:fixed;right:20px;bottom:20px;z-index:99999;font-family:system-ui,-apple-system,sans-serif">
 <a id="mpBtn" href="/conectar-mp" onclick="window.location.assign('/conectar-mp');return false;" style="display:inline-flex;align-items:center;gap:9px;background:#009ee3;color:#fff;font-weight:700;font-size:14px;padding:13px 20px;border-radius:13px;text-decoration:none;box-shadow:0 10px 28px rgba(0,158,227,.45);cursor:pointer">🔗 Conectar con MercadoPago</a>
</div>
<script>
(function(){
 if(new URLSearchParams(location.search).get('conectado')==='1'){ try{history.replaceState({},'','/');}catch(e){} }
 fetch('/mp/estado').then(function(r){return r.json();}).then(function(j){
  var b=document.getElementById('mpBtn'); if(!b)return;
  if(j&&j.conectado){ b.textContent='✓ MercadoPago conectado'; b.style.background='#16a34a'; b.style.boxShadow='0 10px 28px rgba(22,163,74,.4)'; b.removeAttribute('href'); b.onclick=function(){return false;}; b.style.cursor='default'; }
 }).catch(function(){});
})();
</script>
"""


def _hoy() -> str:
    # zona Argentina (UTC-3) sin depender de tz del server
    return (_dt.datetime.utcnow() - _dt.timedelta(hours=3)).strftime("%Y-%m-%d")


# --- Resumen VACÍO: misma forma que espera el dashboard, todo en cero ---
def resumen_vacio() -> dict:
    h = _hoy()
    ceros_int = ["ordenes", "unidades", "reemb_cantidad", "reemb_monto", "reemb_despachados",
                 "ventas_recompras", "ventas_periodo", "meli_ventas", "meli_unidades"]
    ceros_float = ["facturado", "cobrado", "costo_prod", "envio", "comision", "impuestos",
                   "com_plataforma", "com_pago", "fullfilment", "envios", "envio_prom",
                   "costos_extra", "reemb_perdida", "gan_por_venta", "cpa", "publi_ars",
                   "publi_cuenta", "ganancia", "margen", "roas", "roas_be", "ticket",
                   "tasa_recompra", "facturacion_recompras", "meli_facturado"]
    r = {"fecha": h, "desde": h, "hasta": h, "actualizado": h,
         "moneda": "ARS", "dolar": 1200.0}
    for k in ceros_int:
        r[k] = 0
    for k in ceros_float:
        r[k] = 0.0
    return r


def _blob_vacio() -> dict:
    return {"raw": resumen_vacio(), "prod": [], "ords": []}


# ---------------- Login / Registro ----------------
_LOGIN_PAGE = """<!doctype html><html lang=es><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>RealProfit — Ingresá</title>
<style>
*{box-sizing:border-box} body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#0b1220;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#0f1826;border:1px solid #1e2b3d;border-radius:18px;padding:34px 30px;width:100%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,.45)}
.logo{font-size:24px;font-weight:800;text-align:center;color:#fff}
.sub{text-align:center;color:#94a3b8;font-size:13px;margin:4px 0 24px}
.tabs{display:flex;gap:8px;margin-bottom:18px}
.tab{flex:1;padding:10px;border-radius:10px;background:#111c2b;color:#94a3b8;text-align:center;cursor:pointer;font-weight:600;font-size:14px;border:1px solid transparent}
.tab.on{background:#137fec;color:#fff}
label{display:block;font-size:12px;color:#94a3b8;margin:12px 0 6px}
input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid #1e2b3d;background:#0b1220;color:#e2e8f0;font-size:15px;outline:none}
input:focus{border-color:#137fec}
.btn{width:100%;margin-top:20px;padding:13px;border-radius:10px;border:0;background:#137fec;color:#fff;font-weight:700;font-size:15px;cursor:pointer}
.btn:hover{background:#0f6ad0}
.err{color:#f87171;font-size:13px;margin-top:12px;text-align:center;min-height:18px}
</style></head><body>
<div class=card>
 <div class=logo>📊 RealProfit</div>
 <div class=sub>Tu ganancia real, en tiempo real</div>
 <div class=tabs>
  <div class=tab id=tLogin onclick="modo('login')">Ingresar</div>
  <div class=tab id=tReg onclick="modo('registro')">Crear cuenta</div>
 </div>
 <form id=f onsubmit="return enviar(event)">
  <label>Email</label><input id=email type=email autocomplete=email required placeholder="tu@email.com">
  <label>Contraseña</label><input id=password type=password autocomplete=current-password required placeholder="Mínimo 4 caracteres">
  <button class=btn id=submit type=submit>Ingresar</button>
  <div class=err id=err></div>
 </form>
</div>
<script>
var M='login';
function modo(m){M=m;
 document.getElementById('tLogin').classList.toggle('on',m==='login');
 document.getElementById('tReg').classList.toggle('on',m==='registro');
 document.getElementById('submit').textContent=m==='login'?'Ingresar':'Crear cuenta';
 document.getElementById('err').textContent='';}
modo('login');
async function enviar(e){e.preventDefault();
 var err=document.getElementById('err');err.textContent='';
 var fd=new FormData();
 fd.append('email',document.getElementById('email').value);
 fd.append('password',document.getElementById('password').value);
 try{var r=await fetch('/'+(M==='login'?'login':'registro'),{method:'POST',body:fd});
  var j=await r.json();
  if(j.ok){location.href='/';}else{err.textContent=j.msg||'Error';}
 }catch(x){err.textContent='Error de conexión';}
 return false;}
</script></body></html>"""


@app.post("/registro")
@limiter.limit("20 per hour")
def registro():
    email = (request.form.get("email") or "").strip().lower()
    pw = request.form.get("password") or ""
    if not email or "@" not in email or "." not in email:
        return jsonify({"ok": False, "msg": "Ingresá un email válido."})
    if len(pw) < 4:
        return jsonify({"ok": False, "msg": "La contraseña necesita al menos 4 caracteres."})
    us = _users()
    if email in us:
        return jsonify({"ok": False, "msg": "Ya existe una cuenta con ese email. Iniciá sesión."})
    us[email] = {"pass": generate_password_hash(pw), "creado": _hoy()}
    _users_save(us)
    session.clear()
    session["email"] = email
    return jsonify({"ok": True})


@app.post("/login")
@limiter.limit("30 per hour")
def login():
    email = (request.form.get("email") or "").strip().lower()
    pw = request.form.get("password") or ""
    u = _users().get(email)
    if not u or not check_password_hash(u.get("pass", ""), pw):
        return jsonify({"ok": False, "msg": "Email o contraseña incorrectos."})
    session.clear()
    session["email"] = email
    return jsonify({"ok": True})


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- Dashboard ----------------
@app.get("/")
def home():
    email = _user_actual()
    if not email:                       # sin login → pantalla de ingreso
        return Response(_LOGIN_PAGE, mimetype="text/html")
    try:
        html = (RAIZ / "pf.html").read_text(encoding="utf-8")
    except Exception as e:
        return Response(f"<p style='color:#fff;font-family:sans-serif;padding:20px'>"
                        f"No se pudo cargar pf.html: {e}</p>", mimetype="text/html")
    import json as _json
    blob = _json.dumps(_blob_vacio(), ensure_ascii=False)
    # Inyectamos datos VACÍOS (sin esto el dashboard haría fetch y mostraría error).
    if "</head>" in html:
        html = html.replace("</head>", "<script>window.__MFY__=" + blob + ";</script></head>", 1)
    # Caja de usuario abajo a la izquierda (email + cerrar sesión).
    inicial = (email[0] if email else "?").upper()
    userbox = ('<div style="position:fixed;left:16px;bottom:16px;z-index:99998;font-family:system-ui,'
               'sans-serif;display:flex;align-items:center;gap:10px;background:rgba(15,23,42,.92);'
               'backdrop-filter:blur(6px);border:1px solid rgba(255,255,255,.08);padding:9px 13px;'
               'border-radius:12px;color:#e2e8f0">'
               '<div style="width:34px;height:34px;border-radius:50%;background:#137fec;display:flex;'
               'align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:15px">'
               + inicial + '</div><div style="line-height:1.25">'
               '<div style="font-weight:600;font-size:13px;max-width:160px;overflow:hidden;'
               'text-overflow:ellipsis;white-space:nowrap">' + email + '</div>'
               '<a href="/logout" style="color:#94a3b8;font-size:11px;text-decoration:none">Cerrar sesión</a>'
               '</div></div>')
    # Dejar solo Dashboard + Integraciones, sacar el logo, botón MP y caja de usuario.
    extra = _SOLO_DASH + userbox
    if "</body>" in html:
        html = html.replace("</body>", extra + "</body>", 1)
    else:
        html = html + extra
    resp = Response(html, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


# ---------------- Endpoints en blanco (para que no rompa nada) ----------------
@app.get("/pf-periodo")
def pf_periodo():
    return jsonify({"ok": True, **_blob_vacio()})


@app.get("/pf-marketing")
def pf_marketing():
    return jsonify({"ok": True, "mk": {}})


@app.get("/pf-stock")
def pf_stock():
    return jsonify({"ok": True, "st": []})


@app.get("/pf-despachos")
def pf_despachos():
    return jsonify({"ok": True, "desp": []})


@app.get("/pf-ventas-nuevas")
def pf_ventas_nuevas():
    return jsonify({"ok": True, "ventas": []})


@app.get("/pf-opciones")
def pf_opciones():
    return jsonify({"ok": True, "op": {"pages": [], "cuentas": [], "igs": [], "pixels": [],
                                       "titulo_default": "", "url_default": ""}})


@app.get("/pf-ordenes")
def pf_ordenes():
    return jsonify({"ok": True, "ordenes": []})


@app.get("/conectar-mp")
@limiter.limit("30 per hour")
def conectar_mp():
    """Manda al usuario a la pantalla oficial de MercadoPago para que autorice (OAuth)."""
    if not _user_actual():                # hay que estar logueado para conectar SU cuenta
        return redirect("/")
    cfg = _mp_cfg()
    if not cfg["client_id"]:
        return ("Falta configurar el Client ID de MercadoPago en mp_secrets.json "
                "(seguí la guía).", 400)
    state = _secrets.token_urlsafe(16)
    session["mp_state"] = state
    qs = _url.urlencode({"client_id": cfg["client_id"], "response_type": "code",
                         "platform_id": "mp", "redirect_uri": cfg["redirect_uri"], "state": state})
    return redirect("https://auth.mercadopago.com.ar/authorization?" + qs, code=302)


@app.get("/mp/callback")
@limiter.limit("30 per hour")
def mp_callback():
    """MercadoPago devuelve acá con un 'code'. Lo cambiamos por el token del usuario."""
    cfg = _mp_cfg()
    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        # Visita SIN código = MercadoPago validando la URL (o alguien la abrió directo).
        # Devolvemos 200 OK para pasar la validación de MP (si damos 400, rechaza la Redirect URL).
        return ("RealProfit — punto de conexión con MercadoPago. "
                "Volvé a la app y usá el botón «Conectar con MercadoPago».", 200)
    # Anti-CSRF: el state tiene que coincidir con el que generamos al iniciar.
    if not state or state != session.get("mp_state"):
        return ("La conexión no pasó el control de seguridad. Reintentá desde el botón.", 400)
    try:
        r = requests.post("https://api.mercadopago.com/oauth/token", json={
            "client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": cfg["redirect_uri"]}, timeout=30)
        tok = r.json() if r.content else {}
    except Exception:
        return ("No pudimos conectar con MercadoPago en este momento. Probá de nuevo.", 502)
    if not tok.get("access_token"):
        # No exponemos la respuesta cruda de MP (podría filtrar detalles).
        return ("MercadoPago no autorizó la conexión. Reintentá.", 400)
    email = _user_actual()
    if not email:
        return redirect("/")
    # El token de MP se guarda BAJO EL EMAIL del usuario → cada uno ve solo lo suyo.
    _mp_save_token(email, tok)
    session.pop("mp_state", None)                 # el state es de un solo uso
    return redirect("/?conectado=1", code=302)


@app.get("/mp/estado")
def mp_estado():
    """¿ESTE usuario (su email logueado) tiene su MercadoPago conectado? Cada uno ve SOLO lo suyo."""
    email = _user_actual()
    conectado = bool(email and email in _mp_tokens())
    return jsonify({"ok": True, "conectado": conectado})


# Catch-all defensivo: cualquier otro fetch del dashboard responde vacío (no 404, no error).
@app.route("/<path:_ruta>", methods=["GET", "POST"])
def _stub(_ruta):
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8010, debug=False)
