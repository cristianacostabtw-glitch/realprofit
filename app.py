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
# Carpeta de datos persistentes (usuarios + tokens de MP). En Render apuntamos DATA_DIR a un
# disco persistente (ej. /var/data) → las cuentas NO se borran en los deploys. Local: la raíz.
DATA_DIR = Path(_os.getenv("DATA_DIR", str(RAIZ)))
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    DATA_DIR = RAIZ
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
MP_TOKENS = DATA_DIR / "mp_tokens.json"   # tokens de cada usuario que se conecta (persistente)


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
USERS = DATA_DIR / "users.json"   # cada usuario de la app (persistente); su MP se guarda por email


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
  try{
   var aside=document.querySelector('aside'); if(!aside)return;
   var nav=aside.querySelector('nav'); if(!nav)return;
   // dejar SOLO Dashboard en el menú de pf.html (el resto oculto)
   var kids=nav.querySelectorAll(':scope > *');
   for(var i=0;i<kids.length;i++){
    var ch=kids[i];
    ch.style.display = ch.querySelector('a[href="/dashboard"]') ? '' : 'none';
   }
   // ocultar el footer propio de pf.html (CUENTA/avatar) — usamos el nuestro
   Array.prototype.forEach.call(aside.children,function(c){
    if(c.tagName!=='NAV' && !c.querySelector('nav') && !(c.tagName==='A' && c.getAttribute('aria-label'))) c.style.display='none';
   });
  }catch(e){}
 }
 function boot(){ strip(); try{ new MutationObserver(strip).observe(document.body,{childList:true,subtree:true}); }catch(e){} }
 if(document.readyState!=='loading') boot(); else document.addEventListener('DOMContentLoaded', boot);
})();
</script>
<!-- Trigger "Integraciones" (abajo a la izquierda, arriba de la cuenta) -->
<div style="position:fixed;left:16px;bottom:74px;z-index:99998;font-family:system-ui,sans-serif">
 <a href="#" onclick="rpInteg(true);return false;" style="display:inline-flex;align-items:center;gap:9px;background:rgba(15,23,42,.92);backdrop-filter:blur(6px);border:1px solid rgba(255,255,255,.09);color:#e2e8f0;font-weight:600;font-size:13px;padding:10px 14px;border-radius:12px;text-decoration:none;cursor:pointer"><span style="font-size:15px">⚙️</span> Integraciones</a>
</div>

<!-- OVERLAY Integraciones (se abre ADENTRO, sin cambiar de página) -->
<div id="rp-integ-ov" style="position:fixed;inset:0;z-index:100000;background:#0b1220;display:none;overflow:auto;font-family:system-ui,-apple-system,sans-serif">
 <div style="max-width:1000px;margin:0 auto;padding:32px 28px 60px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px">
   <div><h1 style="margin:0;font-size:26px;color:#f1f5f9">Integraciones</h1>
    <div style="color:#94a3b8;font-size:14px;margin-top:6px">Conectá tus ventas, pagos y anuncios para ver, en un solo lugar, si tu negocio gana o pierde plata.</div></div>
   <button onclick="rpInteg(false)" title="Cerrar" style="flex:none;background:#111c2b;border:1px solid #1e2b3d;color:#cbd5e1;width:40px;height:40px;border-radius:11px;font-size:17px;cursor:pointer">✕</button>
  </div>
  <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.6px;margin:28px 0 14px;font-weight:700">Plataformas disponibles</div>
  <div id="rp-integ-cards"></div>
 </div>
</div>
<script>
(function(){
 // Logos (SVG inline, estilo marca)
 var L={
  mp:'<svg width=27 height=27 viewBox="0 0 24 24" fill="#fff"><path d="M11.115 16.479a.93.927 0 0 1-.939-.886c-.002-.042-.006-.155-.103-.155-.04 0-.074.023-.113.059-.112.103-.254.206-.46.206a.816.814 0 0 1-.305-.066c-.535-.214-.542-.578-.521-.725.006-.038.007-.08-.02-.11l-.032-.03h-.034c-.027 0-.055.012-.093.039a.788.786 0 0 1-.454.16.7.699 0 0 1-.253-.05c-.708-.27-.65-.928-.617-1.126.005-.041-.005-.072-.03-.092l-.05-.04-.047.043a.728.726 0 0 1-.505.203.73.728 0 0 1-.732-.725c0-.4.328-.722.732-.722.364 0 .675.27.721.63l.026.195.11-.165c.01-.018.307-.46.852-.46.102 0 .21.016.316.05.434.13.508.52.519.68.008.094.075.1.09.1.037 0 .064-.024.083-.045a.746.744 0 0 1 .54-.225c.128 0 .263.03.402.09.69.293.379 1.158.374 1.167-.058.144-.061.207-.005.244l.027.013h.02c.03 0 .07-.014.134-.035.093-.032.235-.08.367-.08a.944.942 0 0 1 .94.93.936.934 0 0 1-.94.928zm7.302-4.171c-1.138-.98-3.768-3.24-4.481-3.77-.406-.302-.685-.462-.928-.533a1.559 1.554 0 0 0-.456-.07c-.182 0-.376.032-.58.095-.46.145-.918.505-1.362.854l-.023.018c-.414.324-.84.66-1.164.73a1.986 1.98 0 0 1-.43.049c-.362 0-.687-.104-.81-.258-.02-.025-.007-.066.04-.125l.008-.008 1-1.067c.783-.774 1.525-1.506 3.23-1.545h.085c1.062 0 2.12.469 2.24.524a7.03 7.03 0 0 0 3.056.724c1.076 0 2.188-.263 3.354-.795a9.135 9.11 0 0 0-.405-.317c-1.025.44-2.003.66-2.946.66-.962 0-1.925-.229-2.858-.68-.05-.022-1.22-.567-2.44-.57-.032 0-.065 0-.096.002-1.434.033-2.24.536-2.782.976-.528.013-.982.138-1.388.25-.361.1-.673.186-.979.185-.125 0-.35-.01-.37-.012-.35-.01-2.115-.437-3.518-.962-.143.1-.28.203-.415.31 1.466.593 3.25 1.053 3.812 1.089.157.01.323.027.491.027.372 0 .744-.103 1.104-.203.213-.059.446-.123.692-.17l-.196.194-1.017 1.087c-.08.08-.254.294-.14.557a.705.703 0 0 0 .268.292c.243.162.677.27 1.08.271.152 0 .297-.015.43-.044.427-.095.874-.448 1.349-.82.377-.296.913-.672 1.323-.782a1.494 1.49 0 0 1 .37-.05.611.61 0 0 1 .095.005c.27.034.533.125 1.003.472.835.62 4.531 3.815 4.566 3.846.002.002.238.203.22.537-.007.186-.11.352-.294.466a.902.9 0 0 1-.484.15.804.802 0 0 1-.428-.124c-.014-.01-1.28-1.157-1.746-1.543-.074-.06-.146-.115-.22-.115a.122.122 0 0 0-.096.045c-.073.09.01.212.105.294l1.48 1.47c.002 0 .184.17.204.395.012.244-.106.447-.35.606a.957.955 0 0 1-.526.171.766.764 0 0 1-.42-.127l-.214-.206a21.035 20.978 0 0 0-1.08-1.009c-.072-.058-.148-.112-.221-.112a.127.127 0 0 0-.094.038c-.033.037-.056.103.028.212a.698.696 0 0 0 .075.083l1.078 1.198c.01.01.222.26.024.511l-.038.048a1.18 1.178 0 0 1-.1.096c-.184.15-.43.164-.527.164a.8.798 0 0 1-.147-.012c-.106-.018-.178-.048-.212-.089l-.013-.013c-.06-.06-.602-.609-1.054-.98-.059-.05-.133-.11-.21-.11a.128.128 0 0 0-.096.042c-.09.096.044.24.1.293l.92 1.003a.204.204 0 0 1-.033.062c-.033.044-.144.155-.479.196a.91.907 0 0 1-.122.007c-.345 0-.712-.164-.902-.264a1.343 1.34 0 0 0 .13-.576 1.368 1.365 0 0 0-1.42-1.357c.024-.342-.025-.99-.697-1.274a1.455 1.452 0 0 0-.575-.125c-.146 0-.287.025-.42.075a1.153 1.15 0 0 0-.671-.564 1.52 1.515 0 0 0-.494-.085c-.28 0-.537.08-.767.242a1.168 1.165 0 0 0-.903-.43 1.173 1.17 0 0 0-.82.335c-.287-.217-1.425-.93-4.467-1.613a17.39 17.344 0 0 1-.692-.189 4.822 4.82 0 0 0-.077.494l.67.157c3.108.682 4.136 1.391 4.309 1.525a1.145 1.142 0 0 0-.09.442 1.16 1.158 0 0 0 1.378 1.132c.096.467.406.821.879 1.003a1.165 1.162 0 0 0 .415.08c.09 0 .179-.012.266-.034.086.22.282.493.722.668a1.233 1.23 0 0 0 .457.094c.122 0 .241-.022.355-.063a1.373 1.37 0 0 0 1.269.841c.37.002.726-.147.985-.41.221.121.688.341 1.163.341.06 0 .118-.002.175-.01.47-.059.689-.24.789-.382a.571.57 0 0 0 .048-.078c.11.032.234.058.373.058.255 0 .501-.086.75-.265.244-.174.418-.424.444-.637v-.01c.083.017.167.026.251.026.265 0 .527-.082.773-.242.48-.31.562-.715.554-.98a1.28 1.279 0 0 0 .978-.194 1.04 1.04 0 0 0 .502-.808 1.088 1.085 0 0 0-.16-.653c.804-.342 2.636-1.003 4.795-1.483a4.734 4.721 0 0 0-.067-.492 27.742 27.667 0 0 0-5.049 1.62zm5.123-.763c0 4.027-5.166 7.293-11.537 7.293-6.372 0-11.538-3.266-11.538-7.293 0-4.028 5.165-7.293 11.539-7.293 6.371 0 11.537 3.265 11.537 7.293zm.46.004c0-4.272-5.374-7.755-12-7.755S.002 7.277.002 11.55L0 12.004c0 4.533 4.695 8.203 11.999 8.203 7.347 0 12-3.67 12-8.204z"/></svg>',
  meli:'<svg width=27 height=27 viewBox="0 0 24 24" fill="#2d3436"><path d="M11.115 16.479a.93.927 0 0 1-.939-.886c-.002-.042-.006-.155-.103-.155-.04 0-.074.023-.113.059-.112.103-.254.206-.46.206a.816.814 0 0 1-.305-.066c-.535-.214-.542-.578-.521-.725.006-.038.007-.08-.02-.11l-.032-.03h-.034c-.027 0-.055.012-.093.039a.788.786 0 0 1-.454.16.7.699 0 0 1-.253-.05c-.708-.27-.65-.928-.617-1.126.005-.041-.005-.072-.03-.092l-.05-.04-.047.043a.728.726 0 0 1-.505.203.73.728 0 0 1-.732-.725c0-.4.328-.722.732-.722.364 0 .675.27.721.63l.026.195.11-.165c.01-.018.307-.46.852-.46.102 0 .21.016.316.05.434.13.508.52.519.68.008.094.075.1.09.1.037 0 .064-.024.083-.045a.746.744 0 0 1 .54-.225c.128 0 .263.03.402.09.69.293.379 1.158.374 1.167-.058.144-.061.207-.005.244l.027.013h.02c.03 0 .07-.014.134-.035.093-.032.235-.08.367-.08a.944.942 0 0 1 .94.93.936.934 0 0 1-.94.928zm7.302-4.171c-1.138-.98-3.768-3.24-4.481-3.77-.406-.302-.685-.462-.928-.533a1.559 1.554 0 0 0-.456-.07c-.182 0-.376.032-.58.095-.46.145-.918.505-1.362.854l-.023.018c-.414.324-.84.66-1.164.73a1.986 1.98 0 0 1-.43.049c-.362 0-.687-.104-.81-.258-.02-.025-.007-.066.04-.125l.008-.008 1-1.067c.783-.774 1.525-1.506 3.23-1.545h.085c1.062 0 2.12.469 2.24.524a7.03 7.03 0 0 0 3.056.724c1.076 0 2.188-.263 3.354-.795a9.135 9.11 0 0 0-.405-.317c-1.025.44-2.003.66-2.946.66-.962 0-1.925-.229-2.858-.68-.05-.022-1.22-.567-2.44-.57-.032 0-.065 0-.096.002-1.434.033-2.24.536-2.782.976-.528.013-.982.138-1.388.25-.361.1-.673.186-.979.185-.125 0-.35-.01-.37-.012-.35-.01-2.115-.437-3.518-.962-.143.1-.28.203-.415.31 1.466.593 3.25 1.053 3.812 1.089.157.01.323.027.491.027.372 0 .744-.103 1.104-.203.213-.059.446-.123.692-.17l-.196.194-1.017 1.087c-.08.08-.254.294-.14.557a.705.703 0 0 0 .268.292c.243.162.677.27 1.08.271.152 0 .297-.015.43-.044.427-.095.874-.448 1.349-.82.377-.296.913-.672 1.323-.782a1.494 1.49 0 0 1 .37-.05.611.61 0 0 1 .095.005c.27.034.533.125 1.003.472.835.62 4.531 3.815 4.566 3.846.002.002.238.203.22.537-.007.186-.11.352-.294.466a.902.9 0 0 1-.484.15.804.802 0 0 1-.428-.124c-.014-.01-1.28-1.157-1.746-1.543-.074-.06-.146-.115-.22-.115a.122.122 0 0 0-.096.045c-.073.09.01.212.105.294l1.48 1.47c.002 0 .184.17.204.395.012.244-.106.447-.35.606a.957.955 0 0 1-.526.171.766.764 0 0 1-.42-.127l-.214-.206a21.035 20.978 0 0 0-1.08-1.009c-.072-.058-.148-.112-.221-.112a.127.127 0 0 0-.094.038c-.033.037-.056.103.028.212a.698.696 0 0 0 .075.083l1.078 1.198c.01.01.222.26.024.511l-.038.048a1.18 1.178 0 0 1-.1.096c-.184.15-.43.164-.527.164a.8.798 0 0 1-.147-.012c-.106-.018-.178-.048-.212-.089l-.013-.013c-.06-.06-.602-.609-1.054-.98-.059-.05-.133-.11-.21-.11a.128.128 0 0 0-.096.042c-.09.096.044.24.1.293l.92 1.003a.204.204 0 0 1-.033.062c-.033.044-.144.155-.479.196a.91.907 0 0 1-.122.007c-.345 0-.712-.164-.902-.264a1.343 1.34 0 0 0 .13-.576 1.368 1.365 0 0 0-1.42-1.357c.024-.342-.025-.99-.697-1.274a1.455 1.452 0 0 0-.575-.125c-.146 0-.287.025-.42.075a1.153 1.15 0 0 0-.671-.564 1.52 1.515 0 0 0-.494-.085c-.28 0-.537.08-.767.242a1.168 1.165 0 0 0-.903-.43 1.173 1.17 0 0 0-.82.335c-.287-.217-1.425-.93-4.467-1.613a17.39 17.344 0 0 1-.692-.189 4.822 4.82 0 0 0-.077.494l.67.157c3.108.682 4.136 1.391 4.309 1.525a1.145 1.142 0 0 0-.09.442 1.16 1.158 0 0 0 1.378 1.132c.096.467.406.821.879 1.003a1.165 1.162 0 0 0 .415.08c.09 0 .179-.012.266-.034.086.22.282.493.722.668a1.233 1.23 0 0 0 .457.094c.122 0 .241-.022.355-.063a1.373 1.37 0 0 0 1.269.841c.37.002.726-.147.985-.41.221.121.688.341 1.163.341.06 0 .118-.002.175-.01.47-.059.689-.24.789-.382a.571.57 0 0 0 .048-.078c.11.032.234.058.373.058.255 0 .501-.086.75-.265.244-.174.418-.424.444-.637v-.01c.083.017.167.026.251.026.265 0 .527-.082.773-.242.48-.31.562-.715.554-.98a1.28 1.279 0 0 0 .978-.194 1.04 1.04 0 0 0 .502-.808 1.088 1.085 0 0 0-.16-.653c.804-.342 2.636-1.003 4.795-1.483a4.734 4.721 0 0 0-.067-.492 27.742 27.667 0 0 0-5.049 1.62zm5.123-.763c0 4.027-5.166 7.293-11.537 7.293-6.372 0-11.538-3.266-11.538-7.293 0-4.028 5.165-7.293 11.539-7.293 6.371 0 11.537 3.265 11.537 7.293zm.46.004c0-4.272-5.374-7.755-12-7.755S.002 7.277.002 11.55L0 12.004c0 4.533 4.695 8.203 11.999 8.203 7.347 0 12-3.67 12-8.204z"/></svg>',
  tn:'<svg width=27 height=27 viewBox="0 0 24 24" fill="#fff"><path d="M6.5 20q-2.28 0-3.89-1.57Q1 16.85 1 14.58q0-1.95 1.17-3.48Q3.35 9.57 5.25 9.15q.63-2.3 2.5-3.72Q9.63 4 12 4q2.93 0 4.96 2.04Q19 8.07 19 11q1.73.2 2.86 1.5Q23 13.78 23 15.5q0 1.87-1.31 3.19Q20.37 20 18.5 20z"/></svg>',
  shopify:'<svg width=27 height=27 viewBox="0 0 24 24" fill="#fff"><path d="M15.337 23.979l7.216-1.561s-2.604-17.613-2.625-17.73c-.018-.116-.114-.192-.211-.192s-1.929-.136-1.929-.136-1.275-1.274-1.439-1.411c-.045-.037-.075-.057-.121-.074l-.914 21.104h.023zM11.71 11.305s-.81-.424-1.774-.424c-1.447 0-1.504.906-1.504 1.141 0 1.232 3.24 1.715 3.24 4.629 0 2.295-1.44 3.76-3.406 3.76-2.354 0-3.54-1.465-3.54-1.465l.646-2.086s1.245 1.066 2.28 1.066c.675 0 .975-.545.975-.932 0-1.619-2.654-1.694-2.654-4.359-.034-2.237 1.571-4.416 4.827-4.416 1.257 0 1.875.361 1.875.361l-.945 2.715-.02.01zM11.17.83c.136 0 .271.038.405.135-.984.465-2.064 1.639-2.508 3.992-.656.213-1.293.405-1.889.578C7.697 3.75 8.951.84 11.17.84V.83zm1.235 2.949v.135c-.754.232-1.583.484-2.394.736.466-1.777 1.333-2.645 2.085-2.971.193.501.309 1.176.309 2.1zm.539-2.234c.694.074 1.141.867 1.429 1.755-.349.114-.735.231-1.158.366v-.252c0-.752-.096-1.371-.271-1.871v.002zm2.992 1.289c-.02 0-.06.021-.078.021s-.289.075-.714.21c-.423-1.233-1.176-2.37-2.508-2.37h-.115C12.135.209 11.669 0 11.265 0 8.159 0 6.675 3.877 6.21 5.846c-1.194.365-2.063.636-2.16.674-.675.213-.694.232-.772.87-.075.462-1.83 14.063-1.83 14.063L15.009 24l.927-21.166z"/></svg>',
  meta:'<svg width=27 height=27 viewBox="0 0 24 24" fill="#fff"><path d="M6.915 4.03c-1.968 0-3.683 1.28-4.871 3.113C.704 9.208 0 11.883 0 14.449c0 .706.07 1.369.21 1.973a6.624 6.624 0 0 0 .265.86 5.297 5.297 0 0 0 .371.761c.696 1.159 1.818 1.927 3.593 1.927 1.497 0 2.633-.671 3.965-2.444.76-1.012 1.144-1.626 2.663-4.32l.756-1.339.186-.325c.061.1.121.196.183.3l2.152 3.595c.724 1.21 1.665 2.556 2.47 3.314 1.046.987 1.992 1.22 3.06 1.22 1.075 0 1.876-.355 2.455-.843a3.743 3.743 0 0 0 .81-.973c.542-.939.861-2.127.861-3.745 0-2.72-.681-5.357-2.084-7.45-1.282-1.912-2.957-2.93-4.716-2.93-1.047 0-2.088.467-3.053 1.308-.652.57-1.257 1.29-1.82 2.05-.69-.875-1.335-1.547-1.958-2.056-1.182-.966-2.315-1.303-3.454-1.303zm10.16 2.053c1.147 0 2.188.758 2.992 1.999 1.132 1.748 1.647 4.195 1.647 6.4 0 1.548-.368 2.9-1.839 2.9-.58 0-1.027-.23-1.664-1.004-.496-.601-1.343-1.878-2.832-4.358l-.617-1.028a44.908 44.908 0 0 0-1.255-1.98c.07-.109.141-.224.211-.327 1.12-1.667 2.118-2.602 3.358-2.602zm-10.201.553c1.265 0 2.058.791 2.675 1.446.307.327.737.871 1.234 1.579l-1.02 1.566c-.757 1.163-1.882 3.017-2.837 4.338-1.191 1.649-1.81 1.817-2.486 1.817-.524 0-1.038-.237-1.383-.794-.263-.426-.464-1.13-.464-2.046 0-2.221.63-4.535 1.66-6.088.454-.687.964-1.226 1.533-1.533a2.264 2.264 0 0 1 1.088-.285z"/></svg>'
 };
 var PLAT=[
  {key:'mp',   nm:'Mercado Pago', tag:'Pagos',    desc:'Trae tus pagos y movimientos para calcular tu ganancia real.', col:'#009ee3', real:true},
  {key:'meli', nm:'Mercado Libre',tag:'Ventas',   desc:'Incluye tus ventas de marketplace en el cálculo de beneficio.', col:'#ffe600'},
  {key:'tn',   nm:'Tiendanube',   tag:'Ventas',   desc:'Trae tus ventas online de tu tienda para el beneficio real.', col:'#2d6cdf'},
  {key:'shopify',nm:'Shopify',    tag:'Ventas',   desc:'Conectá tu tienda para centralizar ventas y costos por orden.', col:'#95bf47'},
  {key:'meta', nm:'Meta Ads',     tag:'Anuncios', desc:'Trae tus campañas de Facebook e Instagram Ads.', col:'#0866ff'}
 ];
 function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');}
 function cards(mpOn){
  var h='';
  PLAT.forEach(function(p){
   var conn=(p.key==='mp'&&mpOn);
   var estado=conn?'<span style="font-size:12.5px;font-weight:600;color:#34d399;display:inline-flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:50%;background:#34d399"></span>Conectado</span>'
                  :'<span style="font-size:12.5px;font-weight:600;color:#94a3b8;display:inline-flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:50%;background:#475569"></span>No conectado</span>';
   var btn;
   if(p.key==='mp'){
    btn=conn?'<a href="/desconectar-mp" onclick="window.location.assign(\\'/desconectar-mp\\');return false;" style="background:#241a10;color:#ffb35a;border:1px solid #4a3a1a;border-radius:10px;padding:10px 16px;font-weight:700;font-size:13.5px;text-decoration:none">Desconectar</a>'
            :'<a href="/conectar-mp" onclick="window.location.assign(\\'/conectar-mp\\');return false;" style="background:#137fec;color:#fff;border-radius:10px;padding:10px 18px;font-weight:700;font-size:13.5px;text-decoration:none;display:inline-flex;align-items:center;gap:6px">⚡ Conectar</a>';
   } else {
    btn='<button onclick="alert(\\'Muy pronto podés conectar '+esc(p.nm)+'. Lo estamos activando.\\')" style="background:#1a2536;color:#8fa2bd;border:0;border-radius:10px;padding:10px 18px;font-weight:700;font-size:13.5px;cursor:pointer">Conectar</button>';
   }
   var dark=(p.key==='meli');
   h+='<div style="display:flex;align-items:center;gap:16px;background:#0f1826;border:1px solid #1e2b3d;border-radius:14px;padding:16px 20px;margin-bottom:12px">'
     +'<div style="width:50px;height:50px;border-radius:13px;flex:none;display:flex;align-items:center;justify-content:center;background:'+p.col+'">'+L[p.key]+'</div>'
     +'<div style="flex:1;min-width:0"><div style="font-weight:700;font-size:16px;color:#f1f5f9;display:flex;align-items:center;gap:9px">'+esc(p.nm)+' <span style="font-size:11px;color:#94a3b8;background:#111c2b;border:1px solid #1e2b3d;padding:2px 9px;border-radius:20px;font-weight:600">'+p.tag+'</span></div>'
     +'<div style="color:#94a3b8;font-size:13px;margin-top:3px">'+esc(p.desc)+'</div></div>'
     +'<div style="display:flex;align-items:center;gap:14px;flex:none">'+estado+btn+'</div></div>';
  });
  document.getElementById('rp-integ-cards').innerHTML=h;
 }
 function load(){ cards(false); fetch('/mp/estado').then(function(r){return r.json();}).then(function(j){ cards(!!(j&&j.conectado)); }).catch(function(){}); }
 window.rpInteg=function(open){ var o=document.getElementById('rp-integ-ov'); if(!o)return; o.style.display=open?'block':'none'; if(open) load(); };
 // Si volvés de conectar MP, abrimos Integraciones y mostramos conectado.
 if(new URLSearchParams(location.search).get('integ')==='1'){ try{history.replaceState({},'','/');}catch(e){} setTimeout(function(){ window.rpInteg(true); },400); }
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


# ---------------- Página de Integraciones (Mercado Pago, Mercado Libre, Tiendanube, Shopify, Meta) ----------------
_INTEGRACIONES_PAGE = """<!doctype html><html lang=es><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>RealProfit — Integraciones</title>
<style>
*{box-sizing:border-box} body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#0b1220;color:#e2e8f0;min-height:100vh}
.wrap{display:flex;min-height:100vh}
.side{width:230px;flex:none;background:#0f1826;border-right:1px solid #1e2b3d;display:flex;flex-direction:column;padding:20px 14px;position:sticky;top:0;height:100vh}
.brand{font-size:19px;font-weight:800;color:#fff;padding:6px 10px 20px}
.nav a{display:flex;align-items:center;gap:10px;padding:11px 12px;border-radius:10px;color:#94a3b8;text-decoration:none;font-weight:600;font-size:14px;margin-bottom:4px}
.nav a.on{background:#137fec;color:#fff} .nav a:hover:not(.on){background:#111c2b;color:#e2e8f0}
.userbox{margin-top:auto;display:flex;align-items:center;gap:10px;background:#111c2b;border:1px solid #1e2b3d;padding:9px 11px;border-radius:12px}
.av{width:34px;height:34px;border-radius:50%;background:#137fec;display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff}
.main{flex:1;padding:34px 40px;max-width:1000px}
h1{margin:0;font-size:26px;color:#f1f5f9} .lead{color:#94a3b8;margin:6px 0 28px;font-size:14px}
.sechead{font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin:0 0 14px;font-weight:700}
.card{display:flex;align-items:center;gap:16px;background:#0f1826;border:1px solid #1e2b3d;border-radius:14px;padding:18px 20px;margin-bottom:12px}
.ic{width:46px;height:46px;border-radius:12px;flex:none;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800}
.info{flex:1;min-width:0} .nm{font-weight:700;font-size:16px;color:#f1f5f9;display:flex;align-items:center;gap:8px}
.tag{font-size:11px;color:#94a3b8;background:#111c2b;border:1px solid #1e2b3d;padding:2px 8px;border-radius:20px;font-weight:600}
.desc{color:#94a3b8;font-size:13px;margin-top:3px}
.right{display:flex;align-items:center;gap:12px;flex:none}
.pill{font-size:12px;font-weight:600;display:flex;align-items:center;gap:6px;color:#94a3b8}
.dot{width:8px;height:8px;border-radius:50%;background:#475569}
.pill.on{color:#34d399}.pill.on .dot{background:#34d399}
.btn{background:#137fec;color:#fff;border:0;border-radius:10px;padding:10px 18px;font-weight:700;font-size:14px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:7px}
.btn:hover{background:#0f6ad0}
.btn.soon{background:#1a2536;color:#7b8aa0}
.btn.off{background:#241a10;color:#ffb35a;border:1px solid #4a3a1a}
@media(max-width:720px){.side{display:none}.main{padding:22px 18px}.card{flex-wrap:wrap}}
</style></head><body>
<div class=wrap>
 <div class=side>
  <div class=brand>📊 RealProfit</div>
  <div class=nav>
   <a href="/">▦ Dashboard</a>
   <a href="/integraciones" class=on>⚙ Integraciones</a>
  </div>
  <div class=userbox><div class=av>{{INICIAL}}</div>
   <div style="line-height:1.25;min-width:0"><div style="font-weight:600;font-size:13px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{EMAIL}}</div>
   <a href="/logout" style="color:#94a3b8;font-size:11px;text-decoration:none">Cerrar sesión</a></div></div>
 </div>
 <div class=main>
  <h1>Integraciones</h1>
  <div class=lead>Conectá tus ventas, pagos y anuncios para ver, en un solo lugar, si tu negocio gana o pierde plata.</div>
  <div class=sechead>Plataformas disponibles</div>
  <div id=cards></div>
 </div>
</div>
<script>
var PLAT=[
 {key:'mp',   nm:'Mercado Pago', tag:'Pagos',    desc:'Trae tus pagos y movimientos para calcular tu ganancia real.', col:'#009ee3', ic:'💳', real:true},
 {key:'meli', nm:'Mercado Libre',tag:'Ventas',   desc:'Incluye tus ventas de marketplace en el cálculo de beneficio.', col:'#ffe600', ic:'🛒'},
 {key:'tn',   nm:'Tiendanube',   tag:'Ventas',   desc:'Trae tus ventas online de tu tienda para el beneficio real.', col:'#2d6cdf', ic:'🌩️'},
 {key:'shopify',nm:'Shopify',    tag:'Ventas',   desc:'Conectá tu tienda para centralizar ventas y costos por orden.', col:'#95bf47', ic:'🛍️'},
 {key:'meta', nm:'Meta Ads',     tag:'Anuncios', desc:'Trae tus campañas de Facebook e Instagram Ads.', col:'#0866ff', ic:'📣'},
];
function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');}
function render(mpOn){
 var h='';
 PLAT.forEach(function(p){
  var conectado = (p.key==='mp' && mpOn);
  var estado = conectado
    ? '<span class="pill on"><span class=dot></span>Conectado</span>'
    : '<span class=pill><span class=dot></span>No conectado</span>';
  var boton;
  if(p.key==='mp'){
   boton = conectado
     ? '<a class="btn off" href="/desconectar-mp" onclick="window.location.assign(\\'/desconectar-mp\\');return false;">Desconectar</a>'
     : '<a class="btn" href="/conectar-mp" onclick="window.location.assign(\\'/conectar-mp\\');return false;">⚡ Conectar</a>';
  } else {
   boton = '<button class="btn soon" onclick="alert(\\'Muy pronto podés conectar '+esc(p.nm)+'. Lo estamos activando.\\')">Conectar</button>';
  }
  var dark = (p.col==='#ffe600'||p.col==='#95bf47');
  h += '<div class=card>'
    + '<div class=ic style="background:'+p.col+(dark?';color:#0b1220':';color:#fff')+'">'+p.ic+'</div>'
    + '<div class=info><div class=nm>'+esc(p.nm)+' <span class=tag>'+p.tag+'</span></div><div class=desc>'+esc(p.desc)+'</div></div>'
    + '<div class=right>'+estado+boton+'</div></div>';
 });
 document.getElementById('cards').innerHTML=h;
}
render(false);
fetch('/mp/estado').then(function(r){return r.json();}).then(function(j){ render(!!(j&&j.conectado)); }).catch(function(){});
if(new URLSearchParams(location.search).get('conectado')==='1'){ try{history.replaceState({},'','/integraciones');}catch(e){} }
</script></body></html>"""


@app.get("/integraciones")
def integraciones():
    email = _user_actual()
    if not email:
        return redirect("/")
    inicial = (email[0] if email else "?").upper()
    html = _INTEGRACIONES_PAGE.replace("{{EMAIL}}", email).replace("{{INICIAL}}", inicial)
    resp = Response(html, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/desconectar-mp")
def desconectar_mp():
    email = _user_actual()
    if email:
        d = _mp_tokens()
        d.pop(email, None)
        MP_TOKENS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    return redirect("/integraciones")


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
    return redirect("/?integ=1", code=302)


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
