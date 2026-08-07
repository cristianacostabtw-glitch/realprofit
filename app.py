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


# ---------------- Shopify OAuth (conectar con un click) ----------------
SHOPIFY_SECRETS = RAIZ / "shopify_secrets.json"   # tu Client ID + Secret (dueño de la app)
SHOPIFY_TOKENS = DATA_DIR / "shopify_tokens.json"  # tokens por usuario (persistente)
SHOPIFY_SCOPES = ("read_orders,read_fulfillments,write_fulfillments,"
                  "read_assigned_fulfillment_orders,read_merchant_managed_fulfillment_orders,"
                  "read_third_party_fulfillment_orders,read_products,read_customers,"
                  "read_locations,read_shipping")


def _shop_cfg() -> dict:
    import os
    try:
        c = _json.loads(SHOPIFY_SECRETS.read_text(encoding="utf-8"))
    except Exception:
        c = {}
    return {"client_id": os.getenv("SHOPIFY_CLIENT_ID") or c.get("client_id", ""),
            "client_secret": os.getenv("SHOPIFY_CLIENT_SECRET") or c.get("client_secret", ""),
            "redirect_uri": os.getenv("SHOPIFY_REDIRECT_URI") or c.get("redirect_uri",
                                                                       "http://127.0.0.1:8010/shopify/callback"),
            "scopes": os.getenv("SHOPIFY_SCOPES") or c.get("scopes", SHOPIFY_SCOPES)}


def _shop_tokens() -> dict:
    try:
        return _json.loads(SHOPIFY_TOKENS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _shop_save_token(key, data) -> None:
    d = _shop_tokens()
    d[str(key)] = data
    SHOPIFY_TOKENS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def _shop_normalizar(shop: str) -> str:
    """Acepta 'mitienda', 'mitienda.myshopify.com' o con http(s):// y devuelve el dominio limpio."""
    shop = (shop or "").strip().lower()
    shop = shop.replace("https://", "").replace("http://", "")
    shop = shop.split("/")[0].split("?")[0]
    if shop and "." not in shop:
        shop = shop + ".myshopify.com"
    return shop


def _shop_valido(shop: str) -> bool:
    import re
    return bool(shop and re.match(r"^[a-z0-9][a-z0-9\-]*\.myshopify\.com$", shop))


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
_SOLO_DASH = r"""
<style>
 aside > a[aria-label="Ir al Dashboard"]{display:none!important}
 .rp-pill{position:fixed;left:0;z-index:99998;display:flex;align-items:center;justify-content:center;height:46px;box-sizing:border-box;cursor:pointer;text-decoration:none;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif}
 .rp-pill.rp-open{justify-content:flex-start;padding-left:16px}
 .rp-pill .rp-ic{width:34px;height:34px;flex:none;display:flex;align-items:center;justify-content:center;font-size:16px;border-radius:9px;background:rgba(255,255,255,.06)}
 .rp-pill .rp-lbl{max-width:0;opacity:0;overflow:hidden;white-space:nowrap;transition:max-width .25s ease,opacity .2s ease,margin .25s ease;font-size:13px;font-weight:600;line-height:1.25}
 .rp-pill.rp-open .rp-lbl{max-width:150px;opacity:1;margin-left:10px}
 .rp-pill.rp-active .rp-ic{background:#137fec;color:#fff}
 .rp-pill.rp-active .rp-lbl{color:#fff}
 .rp-pill .rp-lbl a{color:#94a3b8;font-size:11px;font-weight:500;text-decoration:none;display:block}
 .rp-pill .rp-lbl .em{display:block;max-width:150px;overflow:hidden;text-overflow:ellipsis}
</style>
<script>
(function(){
 function strip(){
  try{
   var aside=document.querySelector('aside'); if(!aside)return;
   var nav=aside.querySelector('nav'); if(!nav)return;
   var kids=nav.querySelectorAll(':scope > *');
   for(var i=0;i<kids.length;i++){ var ch=kids[i]; ch.style.display = ch.querySelector('a[href="/dashboard"]') ? '' : 'none'; }
   Array.prototype.forEach.call(aside.children,function(c){ if(c.tagName!=='NAV' && !c.querySelector('nav') && !(c.tagName==='A' && c.getAttribute('aria-label')) && !c.classList.contains('rp-pill')) c.style.display='none'; });
   // Ocultar la seccion demo "Top productos" (data hardcodeada del pf.html).
   if(aside._rpTopNode && document.contains(aside._rpTopNode)){ aside._rpTopNode.style.display='none'; }
   else { aside._rpTopNode=null; var cnd=document.querySelectorAll('h2,h3,h4,div,span');
    for(var ti=0;ti<cnd.length;ti++){ if((cnd[ti].textContent||'').trim()==='Top productos'){ var nd=cnd[ti];
      for(var up=0; up<9 && nd.parentElement; up++){ nd=nd.parentElement; var tc=nd.textContent||'';
       if(/Top productos/.test(tc) && /(ventas|ml)/.test(tc) && nd.parentElement && nd.parentElement.children.length>1){ nd.style.display='none'; aside._rpTopNode=nd; break; } } break; } } }
   // Meter los pills DENTRO del aside: al pasarles el mouse cuenta como hover de la barra y NO se cierra.
   var _pp=document.querySelectorAll('.rp-pill');
   for(var pi=0;pi<_pp.length;pi++){ if(_pp[pi].parentNode!==aside){ try{ aside.appendChild(_pp[pi]); }catch(e){} } }
   // Los pills (Integraciones + cuenta) se abren/cierran A LA PAR de la barra lateral.
   if(!aside._rpSync){ aside._rpSync=1;
    var expW=220;
    var apply=function(open,w){ var ps=document.querySelectorAll('.rp-pill'); for(var k=0;k<ps.length;k++){ ps[k].style.width=w+'px'; ps[k].classList.toggle('rp-open',open); } };
    var sync=function(){ var w=Math.round(aside.getBoundingClientRect().width); if(w>110)expW=w; apply(w>110,w); var ov=document.getElementById('rp-integ-ov'); if(ov) ov.style.left=w+'px'; };
    try{ new ResizeObserver(sync).observe(aside); }catch(e){}
    var ps=document.querySelectorAll('.rp-pill');
    for(var k=0;k<ps.length;k++){ (function(p){ p.addEventListener('mouseenter',function(){ apply(true,expW); }); p.addEventListener('mouseleave',function(){ setTimeout(sync,40); }); })(ps[k]); }
    sync();
   }
  }catch(e){}
 }
 function boot(){ strip(); try{ new MutationObserver(strip).observe(document.body,{childList:true,subtree:true}); }catch(e){} }
 if(document.readyState!=='loading') boot(); else document.addEventListener('DOMContentLoaded', boot);
})();
</script>
<a class="rp-pill" id="rp-integ-btn" href="#" onclick="rpInteg(true);return false;" style="bottom:74px"><span class="rp-ic"><span class="material-symbols-outlined" style="font-size:20px">extension</span></span><span class="rp-lbl">Integraciones</span></a>
<div id="rp-integ-ov" style="position:fixed;top:0;right:0;bottom:0;left:72px;z-index:100000;background:#0b1220;display:none;overflow:auto;transition:left .18s ease;font-family:system-ui,-apple-system,sans-serif">
 <div style="max-width:960px;margin:0 auto;padding:26px 32px 60px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px">
   <div><h1 style="margin:0;font-size:22px;color:#f1f5f9">Integraciones</h1>
    <div style="color:#94a3b8;font-size:13px;margin-top:5px">Conect&aacute; tus ventas, pagos y anuncios para ver, en un solo lugar, si tu negocio gana o pierde plata.</div></div>
   <button onclick="rpInteg(false)" title="Cerrar" style="flex:none;background:#111c2b;border:1px solid #1e2b3d;color:#cbd5e1;width:38px;height:38px;border-radius:10px;font-size:16px;cursor:pointer">&#10005;</button>
  </div>
  <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin:24px 0 13px;font-weight:700">Plataformas disponibles</div>
  <div id="rp-integ-cards"></div>
 </div>
</div>
<script>
(function(){
  var L={mp:`<svg width="21" height="21" viewBox="0 0 24 24" fill="#00b1ea"><path d="M11.115 16.479a.93.927 0 0 1-.939-.886c-.002-.042-.006-.155-.103-.155-.04 0-.074.023-.113.059-.112.103-.254.206-.46.206a.816.814 0 0 1-.305-.066c-.535-.214-.542-.578-.521-.725.006-.038.007-.08-.02-.11l-.032-.03h-.034c-.027 0-.055.012-.093.039a.788.786 0 0 1-.454.16.7.699 0 0 1-.253-.05c-.708-.27-.65-.928-.617-1.126.005-.041-.005-.072-.03-.092l-.05-.04-.047.043a.728.726 0 0 1-.505.203.73.728 0 0 1-.732-.725c0-.4.328-.722.732-.722.364 0 .675.27.721.63l.026.195.11-.165c.01-.018.307-.46.852-.46.102 0 .21.016.316.05.434.13.508.52.519.68.008.094.075.1.09.1.037 0 .064-.024.083-.045a.746.744 0 0 1 .54-.225c.128 0 .263.03.402.09.69.293.379 1.158.374 1.167-.058.144-.061.207-.005.244l.027.013h.02c.03 0 .07-.014.134-.035.093-.032.235-.08.367-.08a.944.942 0 0 1 .94.93.936.934 0 0 1-.94.928zm7.302-4.171c-1.138-.98-3.768-3.24-4.481-3.77-.406-.302-.685-.462-.928-.533a1.559 1.554 0 0 0-.456-.07c-.182 0-.376.032-.58.095-.46.145-.918.505-1.362.854l-.023.018c-.414.324-.84.66-1.164.73a1.986 1.98 0 0 1-.43.049c-.362 0-.687-.104-.81-.258-.02-.025-.007-.066.04-.125l.008-.008 1-1.067c.783-.774 1.525-1.506 3.23-1.545h.085c1.062 0 2.12.469 2.24.524a7.03 7.03 0 0 0 3.056.724c1.076 0 2.188-.263 3.354-.795a9.135 9.11 0 0 0-.405-.317c-1.025.44-2.003.66-2.946.66-.962 0-1.925-.229-2.858-.68-.05-.022-1.22-.567-2.44-.57-.032 0-.065 0-.096.002-1.434.033-2.24.536-2.782.976-.528.013-.982.138-1.388.25-.361.1-.673.186-.979.185-.125 0-.35-.01-.37-.012-.35-.01-2.115-.437-3.518-.962-.143.1-.28.203-.415.31 1.466.593 3.25 1.053 3.812 1.089.157.01.323.027.491.027.372 0 .744-.103 1.104-.203.213-.059.446-.123.692-.17l-.196.194-1.017 1.087c-.08.08-.254.294-.14.557a.705.703 0 0 0 .268.292c.243.162.677.27 1.08.271.152 0 .297-.015.43-.044.427-.095.874-.448 1.349-.82.377-.296.913-.672 1.323-.782a1.494 1.49 0 0 1 .37-.05.611.61 0 0 1 .095.005c.27.034.533.125 1.003.472.835.62 4.531 3.815 4.566 3.846.002.002.238.203.22.537-.007.186-.11.352-.294.466a.902.9 0 0 1-.484.15.804.802 0 0 1-.428-.124c-.014-.01-1.28-1.157-1.746-1.543-.074-.06-.146-.115-.22-.115a.122.122 0 0 0-.096.045c-.073.09.01.212.105.294l1.48 1.47c.002 0 .184.17.204.395.012.244-.106.447-.35.606a.957.955 0 0 1-.526.171.766.764 0 0 1-.42-.127l-.214-.206a21.035 20.978 0 0 0-1.08-1.009c-.072-.058-.148-.112-.221-.112a.127.127 0 0 0-.094.038c-.033.037-.056.103.028.212a.698.696 0 0 0 .075.083l1.078 1.198c.01.01.222.26.024.511l-.038.048a1.18 1.178 0 0 1-.1.096c-.184.15-.43.164-.527.164a.8.798 0 0 1-.147-.012c-.106-.018-.178-.048-.212-.089l-.013-.013c-.06-.06-.602-.609-1.054-.98-.059-.05-.133-.11-.21-.11a.128.128 0 0 0-.096.042c-.09.096.044.24.1.293l.92 1.003a.204.204 0 0 1-.033.062c-.033.044-.144.155-.479.196a.91.907 0 0 1-.122.007c-.345 0-.712-.164-.902-.264a1.343 1.34 0 0 0 .13-.576 1.368 1.365 0 0 0-1.42-1.357c.024-.342-.025-.99-.697-1.274a1.455 1.452 0 0 0-.575-.125c-.146 0-.287.025-.42.075a1.153 1.15 0 0 0-.671-.564 1.52 1.515 0 0 0-.494-.085c-.28 0-.537.08-.767.242a1.168 1.165 0 0 0-.903-.43 1.173 1.17 0 0 0-.82.335c-.287-.217-1.425-.93-4.467-1.613a17.39 17.344 0 0 1-.692-.189 4.822 4.82 0 0 0-.077.494l.67.157c3.108.682 4.136 1.391 4.309 1.525a1.145 1.142 0 0 0-.09.442 1.16 1.158 0 0 0 1.378 1.132c.096.467.406.821.879 1.003a1.165 1.162 0 0 0 .415.08c.09 0 .179-.012.266-.034.086.22.282.493.722.668a1.233 1.23 0 0 0 .457.094c.122 0 .241-.022.355-.063a1.373 1.37 0 0 0 1.269.841c.37.002.726-.147.985-.41.221.121.688.341 1.163.341.06 0 .118-.002.175-.01.47-.059.689-.24.789-.382a.571.57 0 0 0 .048-.078c.11.032.234.058.373.058.255 0 .501-.086.75-.265.244-.174.418-.424.444-.637v-.01c.083.017.167.026.251.026.265 0 .527-.082.773-.242.48-.31.562-.715.554-.98a1.28 1.279 0 0 0 .978-.194 1.04 1.04 0 0 0 .502-.808 1.088 1.085 0 0 0-.16-.653c.804-.342 2.636-1.003 4.795-1.483a4.734 4.721 0 0 0-.067-.492 27.742 27.667 0 0 0-5.049 1.62zm5.123-.763c0 4.027-5.166 7.293-11.537 7.293-6.372 0-11.538-3.266-11.538-7.293 0-4.028 5.165-7.293 11.539-7.293 6.371 0 11.537 3.265 11.537 7.293zm.46.004c0-4.272-5.374-7.755-12-7.755S.002 7.277.002 11.55L0 12.004c0 4.533 4.695 8.203 11.999 8.203 7.347 0 12-3.67 12-8.204z"/></svg>`,meli:`<svg width="21" height="21" viewBox="0 0 24 24" fill="#ffe600"><path d="M11.115 16.479a.93.927 0 0 1-.939-.886c-.002-.042-.006-.155-.103-.155-.04 0-.074.023-.113.059-.112.103-.254.206-.46.206a.816.814 0 0 1-.305-.066c-.535-.214-.542-.578-.521-.725.006-.038.007-.08-.02-.11l-.032-.03h-.034c-.027 0-.055.012-.093.039a.788.786 0 0 1-.454.16.7.699 0 0 1-.253-.05c-.708-.27-.65-.928-.617-1.126.005-.041-.005-.072-.03-.092l-.05-.04-.047.043a.728.726 0 0 1-.505.203.73.728 0 0 1-.732-.725c0-.4.328-.722.732-.722.364 0 .675.27.721.63l.026.195.11-.165c.01-.018.307-.46.852-.46.102 0 .21.016.316.05.434.13.508.52.519.68.008.094.075.1.09.1.037 0 .064-.024.083-.045a.746.744 0 0 1 .54-.225c.128 0 .263.03.402.09.69.293.379 1.158.374 1.167-.058.144-.061.207-.005.244l.027.013h.02c.03 0 .07-.014.134-.035.093-.032.235-.08.367-.08a.944.942 0 0 1 .94.93.936.934 0 0 1-.94.928zm7.302-4.171c-1.138-.98-3.768-3.24-4.481-3.77-.406-.302-.685-.462-.928-.533a1.559 1.554 0 0 0-.456-.07c-.182 0-.376.032-.58.095-.46.145-.918.505-1.362.854l-.023.018c-.414.324-.84.66-1.164.73a1.986 1.98 0 0 1-.43.049c-.362 0-.687-.104-.81-.258-.02-.025-.007-.066.04-.125l.008-.008 1-1.067c.783-.774 1.525-1.506 3.23-1.545h.085c1.062 0 2.12.469 2.24.524a7.03 7.03 0 0 0 3.056.724c1.076 0 2.188-.263 3.354-.795a9.135 9.11 0 0 0-.405-.317c-1.025.44-2.003.66-2.946.66-.962 0-1.925-.229-2.858-.68-.05-.022-1.22-.567-2.44-.57-.032 0-.065 0-.096.002-1.434.033-2.24.536-2.782.976-.528.013-.982.138-1.388.25-.361.1-.673.186-.979.185-.125 0-.35-.01-.37-.012-.35-.01-2.115-.437-3.518-.962-.143.1-.28.203-.415.31 1.466.593 3.25 1.053 3.812 1.089.157.01.323.027.491.027.372 0 .744-.103 1.104-.203.213-.059.446-.123.692-.17l-.196.194-1.017 1.087c-.08.08-.254.294-.14.557a.705.703 0 0 0 .268.292c.243.162.677.27 1.08.271.152 0 .297-.015.43-.044.427-.095.874-.448 1.349-.82.377-.296.913-.672 1.323-.782a1.494 1.49 0 0 1 .37-.05.611.61 0 0 1 .095.005c.27.034.533.125 1.003.472.835.62 4.531 3.815 4.566 3.846.002.002.238.203.22.537-.007.186-.11.352-.294.466a.902.9 0 0 1-.484.15.804.802 0 0 1-.428-.124c-.014-.01-1.28-1.157-1.746-1.543-.074-.06-.146-.115-.22-.115a.122.122 0 0 0-.096.045c-.073.09.01.212.105.294l1.48 1.47c.002 0 .184.17.204.395.012.244-.106.447-.35.606a.957.955 0 0 1-.526.171.766.764 0 0 1-.42-.127l-.214-.206a21.035 20.978 0 0 0-1.08-1.009c-.072-.058-.148-.112-.221-.112a.127.127 0 0 0-.094.038c-.033.037-.056.103.028.212a.698.696 0 0 0 .075.083l1.078 1.198c.01.01.222.26.024.511l-.038.048a1.18 1.178 0 0 1-.1.096c-.184.15-.43.164-.527.164a.8.798 0 0 1-.147-.012c-.106-.018-.178-.048-.212-.089l-.013-.013c-.06-.06-.602-.609-1.054-.98-.059-.05-.133-.11-.21-.11a.128.128 0 0 0-.096.042c-.09.096.044.24.1.293l.92 1.003a.204.204 0 0 1-.033.062c-.033.044-.144.155-.479.196a.91.907 0 0 1-.122.007c-.345 0-.712-.164-.902-.264a1.343 1.34 0 0 0 .13-.576 1.368 1.365 0 0 0-1.42-1.357c.024-.342-.025-.99-.697-1.274a1.455 1.452 0 0 0-.575-.125c-.146 0-.287.025-.42.075a1.153 1.15 0 0 0-.671-.564 1.52 1.515 0 0 0-.494-.085c-.28 0-.537.08-.767.242a1.168 1.165 0 0 0-.903-.43 1.173 1.17 0 0 0-.82.335c-.287-.217-1.425-.93-4.467-1.613a17.39 17.344 0 0 1-.692-.189 4.822 4.82 0 0 0-.077.494l.67.157c3.108.682 4.136 1.391 4.309 1.525a1.145 1.142 0 0 0-.09.442 1.16 1.158 0 0 0 1.378 1.132c.096.467.406.821.879 1.003a1.165 1.162 0 0 0 .415.08c.09 0 .179-.012.266-.034.086.22.282.493.722.668a1.233 1.23 0 0 0 .457.094c.122 0 .241-.022.355-.063a1.373 1.37 0 0 0 1.269.841c.37.002.726-.147.985-.41.221.121.688.341 1.163.341.06 0 .118-.002.175-.01.47-.059.689-.24.789-.382a.571.57 0 0 0 .048-.078c.11.032.234.058.373.058.255 0 .501-.086.75-.265.244-.174.418-.424.444-.637v-.01c.083.017.167.026.251.026.265 0 .527-.082.773-.242.48-.31.562-.715.554-.98a1.28 1.279 0 0 0 .978-.194 1.04 1.04 0 0 0 .502-.808 1.088 1.085 0 0 0-.16-.653c.804-.342 2.636-1.003 4.795-1.483a4.734 4.721 0 0 0-.067-.492 27.742 27.667 0 0 0-5.049 1.62zm5.123-.763c0 4.027-5.166 7.293-11.537 7.293-6.372 0-11.538-3.266-11.538-7.293 0-4.028 5.165-7.293 11.539-7.293 6.371 0 11.537 3.265 11.537 7.293zm.46.004c0-4.272-5.374-7.755-12-7.755S.002 7.277.002 11.55L0 12.004c0 4.533 4.695 8.203 11.999 8.203 7.347 0 12-3.67 12-8.204z"/></svg>`,tn:`<svg width="21" height="21" viewBox="0 0 24 24" fill="#2d6cdf"><path d="M6.5 20q-2.28 0-3.89-1.57Q1 16.85 1 14.58q0-1.95 1.17-3.48Q3.35 9.57 5.25 9.15q.63-2.3 2.5-3.72Q9.63 4 12 4q2.93 0 4.96 2.04Q19 8.07 19 11q1.73.2 2.86 1.5Q23 13.78 23 15.5q0 1.87-1.31 3.19Q20.37 20 18.5 20z"/></svg>`,shopify:`<svg width="22" height="22" width="256px" height="292px" viewBox="0 0 256 292" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" preserveAspectRatio="xMidYMid"> <g> <path d="M223.773626,57.3402078 C223.572932,55.8793405 222.29409,55.0718963 221.236945,54.9832175 C220.182133,54.8945386 197.853734,53.2399781 197.853734,53.2399781 C197.853734,53.2399781 182.346604,37.8448639 180.64537,36.1412966 C178.941803,34.4377293 175.616346,34.9558004 174.325836,35.336186 C174.134476,35.3921937 170.937371,36.3793293 165.646977,38.0152206 C160.466266,23.1101737 151.325344,9.41162582 135.241802,9.41162582 C134.798408,9.41162582 134.341011,9.43029505 133.883615,9.45596525 C129.309654,3.40713457 123.643542,0.779440373 118.74987,0.779440373 C81.285392,0.779440373 63.3862673,47.6135387 57.7738299,71.414474 C43.2164974,75.9254268 32.8737437,79.1318671 31.5528956,79.5472575 C23.4271131,82.0956074 23.1704111,82.3523094 22.1039313,90.0090275 C21.2988208,95.8058236 0.0369009009,260.235071 0.0369009009,260.235071 L165.714653,291.277334 L255.485648,271.856667 C255.485648,271.856667 223.971987,58.8010751 223.773626,57.3402078 L223.773626,57.3402078 Z M156.48972,40.8482763 C152.328815,42.1364532 147.598499,43.5996542 142.471461,45.1865388 C142.476129,44.1994032 142.480796,43.2262696 142.480796,42.1644571 C142.480796,32.8998514 141.194953,25.4414939 139.132003,19.5280151 C147.418807,20.5688247 152.937899,29.9967861 156.48972,40.8482763 L156.48972,40.8482763 Z M128.852258,21.3646006 C131.155574,27.1380602 132.65378,35.4225312 132.65378,46.6030666 C132.65378,47.1748118 132.649112,47.6975503 132.644445,48.2272897 C123.52686,51.0510108 113.620499,54.1174319 103.690802,57.1931876 C109.265901,35.6768995 119.716003,25.2851391 128.852258,21.3646006 L128.852258,21.3646006 Z M117.720729,10.8281537 C119.337951,10.8281537 120.966841,11.3765623 122.525722,12.4500431 C110.519073,18.099819 97.6489725,32.3304399 92.2138928,60.7473424 C84.2701352,63.2070135 76.506069,65.6106769 69.3277499,67.834649 C75.6939575,46.1596724 90.8113669,10.8281537 117.720729,10.8281537 L117.720729,10.8281537 Z" fill="#95BF46"></path> <path d="M221.236945,54.9832175 C220.182133,54.8945386 197.853734,53.2399781 197.853734,53.2399781 C197.853734,53.2399781 182.346604,37.8448639 180.64537,36.1412966 C180.008283,35.5065427 179.149498,35.1821649 178.251042,35.0421456 L165.723988,291.275001 L255.485648,271.856667 C255.485648,271.856667 223.971987,58.8010751 223.773626,57.3402078 C223.572932,55.8793405 222.29409,55.0718963 221.236945,54.9832175" fill="#5E8E3E"></path> <path d="M135.241802,104.585029 L124.173282,137.510551 C124.173282,137.510551 114.474617,132.334507 102.586984,132.334507 C85.1592573,132.334507 84.2818035,143.272342 84.2818035,146.028387 C84.2818035,161.066452 123.48252,166.828244 123.48252,202.052414 C123.48252,229.764553 105.90544,247.610004 82.2048516,247.610004 C53.7646126,247.610004 39.2212821,229.90924 39.2212821,229.90924 L46.8359944,204.750118 C46.8359944,204.750118 61.7853808,217.585214 74.4011133,217.585214 C82.6435785,217.585214 85.9970391,211.095323 85.9970391,206.353338 C85.9970391,186.736644 53.8369559,185.861524 53.8369559,153.629098 C53.8369559,126.500372 73.3089633,100.246767 112.614694,100.246767 C127.760108,100.246767 135.241802,104.585029 135.241802,104.585029" fill="#FFFFFF"></path> </g> </svg>`,meta:`<svg width="22" height="22" width="256px" height="171px" viewBox="0 0 256 171" version="1.1" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid"> <title>Meta</title> <defs> <linearGradient x1="13.8784354%" y1="55.9337491%" x2="89.143574%" y2="58.6936324%" id="linearGradient-1"> <stop stop-color="#0064E1" offset="0%"></stop> <stop stop-color="#0064E1" offset="40%"></stop> <stop stop-color="#0073EE" offset="83%"></stop> <stop stop-color="#0082FB" offset="100%"></stop> </linearGradient> <linearGradient x1="54.3150272%" y1="82.782443%" x2="54.3150272%" y2="39.3067715%" id="linearGradient-2"> <stop stop-color="#0082FB" offset="0%"></stop> <stop stop-color="#0064E0" offset="100%"></stop> </linearGradient> </defs> <g> <path d="M27.6511337,112.135763 C27.6511337,121.910697 29.7966337,129.415496 32.6009181,133.955766 C36.2776464,139.902629 41.7615802,142.422034 47.3523439,142.422034 C54.5633607,142.422034 61.1601057,140.632633 73.8728613,123.050216 C84.0573098,108.957574 96.0578662,89.1762415 104.132425,76.775073 L117.806649,55.7651968 C127.305606,41.1740159 138.300181,24.9536792 150.906107,13.9591042 C161.197385,4.98539435 172.29879,0 183.471415,0 C202.228961,0 220.096258,10.8699402 233.770483,31.2566421 C248.735568,53.5840868 256,81.7070524 256,110.72917 C256,127.982195 252.599249,140.659341 246.81263,150.674642 C241.221867,160.360551 230.325219,170.037557 211.994992,170.037557 L211.994992,142.422034 C227.690082,142.422034 231.607178,128 231.607178,111.494784 C231.607178,87.9744053 226.123244,61.8723049 214.042565,43.2215885 C205.469467,29.9924885 194.35916,21.9090277 182.136041,21.9090277 C168.915844,21.9090277 158.277368,31.8798164 146.321324,49.6580887 C139.964946,59.1036305 133.439421,70.61455 126.112672,83.6032828 L118.047016,97.8917791 C101.844485,126.620114 97.7404368,133.163444 89.639171,143.962164 C75.4396995,162.871053 63.3145083,170.037557 47.3523439,170.037557 C28.4167478,170.037557 16.4428989,161.838364 9.02712477,149.481708 C2.97343163,139.412992 0,126.201697 0,111.147587 L27.6511337,112.135763 Z" fill="#0081FB"></path> <path d="M21.8021978,33.2062874 C34.4793434,13.665322 52.7739602,0 73.7571289,0 C85.9090277,0 97.9897065,3.59660593 110.604535,13.8967868 C124.403394,25.1584365 139.110307,43.702323 157.458339,74.2645709 L164.037279,85.2324384 C179.919321,111.690638 188.955348,125.302546 194.243427,131.721241 C201.04493,139.964946 205.807762,142.422034 211.994992,142.422034 C227.690082,142.422034 231.607178,128 231.607178,111.494784 L256,110.72917 C256,127.982195 252.599249,140.659341 246.81263,150.674642 C241.221867,160.360551 230.325219,170.037557 211.994992,170.037557 C200.599805,170.037557 190.504382,167.562665 179.340659,157.03102 C170.758659,148.947559 160.725553,134.587843 153.007094,121.679232 L130.047573,83.3273056 C118.527751,64.0801224 107.960495,49.7293087 101.844485,43.230491 C95.2655446,36.2420364 86.8081792,27.802476 73.3120045,27.802476 C62.3886493,27.802476 53.1122548,35.4675198 45.3492836,47.192099 L21.8021978,33.2062874 Z" fill="url(#linearGradient-1)"></path> <path d="M73.3120045,27.802476 C62.3886493,27.802476 53.1122548,35.4675198 45.3492836,47.192099 C34.3725136,63.7596328 27.6511337,88.4373348 27.6511337,112.135763 C27.6511337,121.910697 29.7966337,129.415496 32.6009181,133.955766 L9.02712477,149.481708 C2.97343163,139.412992 0,126.201697 0,111.147587 C0,83.7724301 7.51370149,55.2399499 21.8021978,33.2062874 C34.4793434,13.665322 52.7739602,0 73.7571289,0 L73.3120045,27.802476 Z" fill="url(#linearGradient-2)"></path> </g> </svg>`,gads:`<svg width="22" height="22" width="256px" height="230px" viewBox="0 0 256 230" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" preserveAspectRatio="xMidYMid"> <g> <path d="M5.888,166.405103 L90.88,20.9 C101.676138,27.2558621 156.115862,57.3844138 164.908138,63.1135172 L79.9161379,208.627448 C70.6206897,220.906621 -5.888,185.040138 5.888,166.396276 L5.888,166.405103 Z" fill="#FBBC04"></path> <path d="M250.084224,166.401789 L165.092224,20.9055131 C153.210293,1.13172 127.619121,-6.05393517 106.600638,5.62496138 C85.582155,17.3038579 79.182155,42.4624786 91.0640861,63.1190303 L176.056086,208.632961 C187.938017,228.397927 213.52919,235.583582 234.547672,223.904686 C254.648086,212.225789 261.966155,186.175582 250.084224,166.419444 L250.084224,166.401789 Z" fill="#4285F4"></path> <ellipse fill="#34A853" cx="42.6637241" cy="187.924414" rx="42.6637241" ry="41.6044138"></ellipse> </g> </svg>`,tiktok:`<svg width="22" height="22" width="256px" height="290px" viewBox="0 0 256 290" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" preserveAspectRatio="xMidYMid"> <title>TikTok</title> <g> <path d="M189.720224,104.421475 C208.398189,117.766281 231.279538,125.618095 255.992548,125.618095 L255.992548,78.0872726 C251.315611,78.0882654 246.650588,77.6008156 242.074913,76.6318726 L242.074913,114.045382 C217.363889,114.045382 194.485518,106.193568 175.80259,92.8497541 L175.80259,189.846306 C175.80259,238.368905 136.447224,277.701437 87.902784,277.701437 C69.7897057,277.701437 52.9543216,272.228299 38.9691786,262.841664 C54.9309256,279.153859 77.1908018,289.273158 101.81744,289.273158 C150.364858,289.273158 189.72221,249.940626 189.72221,201.416041 L189.72221,104.421475 L189.720224,104.421475 Z M206.889179,56.4687254 C197.343701,46.0456391 191.076347,32.5757434 189.720224,17.6842019 L189.720224,11.5707278 L176.531282,11.5707278 C179.851103,30.497877 191.174632,46.6681056 206.889179,56.4687254 L206.889179,56.4687254 Z M69.6735517,225.606854 C64.3403943,218.617757 61.4583846,210.068027 61.4712906,201.277053 C61.4712906,179.084685 79.472186,161.090739 101.680438,161.090739 C105.819294,161.089747 109.933331,161.723134 113.877603,162.974023 L113.877603,114.380938 C109.268175,113.749536 104.616057,113.481488 99.9659254,113.579773 L99.9659254,151.402303 C96.0186741,150.151413 91.9026521,149.516041 87.7628035,149.520012 C65.5545513,149.520012 47.5546487,167.511972 47.5546487,189.707318 C47.5546487,205.401018 56.552118,218.98806 69.6735517,225.606854 Z" fill="#FF004F"></path> <path d="M175.80259,92.8487613 C194.485518,106.192575 217.363889,114.044389 242.074913,114.044389 L242.074913,76.6308799 C228.281375,73.6942679 216.070311,66.4897401 206.889179,56.4687254 C191.173639,46.6671128 179.851103,30.4968842 176.531282,11.5707278 L141.8876,11.5707278 L141.8876,201.414056 C141.809172,223.545865 123.839052,241.466346 101.678453,241.466346 C88.6195635,241.466346 77.0180599,235.24466 69.6705734,225.606854 C56.5501325,218.98806 47.5526631,205.400025 47.5526631,189.708311 C47.5526631,167.51495 65.5525657,149.521004 87.760818,149.521004 C92.0158278,149.521004 96.1169583,150.183182 99.9639399,151.403295 L99.9639399,113.580765 C52.272289,114.565593 13.9166419,153.513923 13.9166419,201.415048 C13.9166419,225.326893 23.4680767,247.004014 38.9701714,262.842657 C52.9553144,272.228299 69.7906985,277.70243 87.9037768,277.70243 C136.449209,277.70243 175.803582,238.367912 175.803582,189.846306 L175.803582,92.8487613 L175.80259,92.8487613 Z" fill="#000000"></path> <path d="M242.074913,76.6308799 L242.074913,66.5145593 C229.636505,66.5334219 217.442318,63.0517795 206.889179,56.4677326 C216.231139,66.6902795 228.532545,73.7389425 242.074913,76.6308799 Z M176.531282,11.5707278 C176.214589,9.76190185 175.971361,7.9411627 175.80259,6.11347418 L175.80259,0 L127.968973,0 L127.968973,189.845313 C127.89253,211.974144 109.923403,229.894625 87.760818,229.894625 C81.2542071,229.894625 75.1109499,228.350869 69.6705734,225.607847 C77.0180599,235.24466 88.6195635,241.465353 101.678453,241.465353 C123.837066,241.465353 141.810164,223.546857 141.8876,201.415048 L141.8876,11.5707278 L176.531282,11.5707278 Z M99.9659254,113.580765 L99.9659254,102.811203 C95.9690357,102.265179 91.9393845,101.991175 87.9047695,101.99315 C39.3553659,101.99315 0,141.326686 0,189.845313 C0,220.263769 15.4673478,247.071522 38.9711641,262.840672 C23.4690694,247.003021 13.9176347,225.324907 13.9176347,201.414056 C13.9176347,153.513923 52.272289,114.565593 99.9659254,113.580765 Z" fill="#00F2EA"></path> </g> </svg>`};
 var PLAT=[
  {key:'mp',logo:'mp',nm:'Mercado Pago',tag:'Pagos',desc:'Trae tus pagos y movimientos para calcular tu ganancia real.',real:true},
  {key:'shopify',logo:'shopify',nm:'Shopify',tag:'Ventas',desc:'Conecta tu tienda para centralizar ventas y costos por orden.'},
  {key:'tn',logo:'tn',nm:'Tiendanube',tag:'Ventas',desc:'Trae tus ventas online de tu tienda para el beneficio real.'},
  {key:'meli',logo:'meli',nm:'Mercado Libre',tag:'Ventas',desc:'Incluye tus ventas de marketplace en el calculo de beneficio.'},
  {key:'meta',logo:'meta',nm:'Meta Ads',tag:'Anuncios',desc:'Trae tus campanas de Facebook e Instagram Ads.'},
  {key:'gads',logo:'gads',nm:'Google Ads',tag:'Anuncios',desc:'Trae tus campanas de Google Ads (Search, Performance Max, Shopping).'},
  {key:'tiktok',logo:'tiktok',nm:'TikTok Ads',tag:'Anuncios',desc:'Trae tus campanas de TikTok Ads para medir su rentabilidad real.',soon:true}
 ];
 function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');}
 function chip(txt,color,bg,bd){return '<span style="display:inline-flex;align-items:center;gap:7px;background:'+bg+';border:1px solid '+bd+';color:'+color+';border-radius:20px;padding:7px 14px;font-size:12.5px;font-weight:600"><span style="width:7px;height:7px;border-radius:50%;background:'+color+'"></span>'+txt+'</span>';}
 function cards(mpOn, shopOn){
  var h='';
  var bs='background:#137fec;color:#fff;border-radius:10px;padding:9px 17px;font-weight:700;font-size:13px;text-decoration:none';
  var ds='background:#111c2b;border:1px solid #1e2b3d;color:#cbd5e1;border-radius:10px;padding:9px 15px;font-weight:600;font-size:13px;text-decoration:none';
  PLAT.forEach(function(p){
   var right, on=(p.key==='mp'&&mpOn)||(p.key==='shopify'&&shopOn);
   if(p.soon){ right='<span style="display:inline-flex;align-items:center;gap:6px;background:#241a10;border:1px solid #4a3a1a;color:#ffb35a;border-radius:20px;padding:7px 14px;font-size:12.5px;font-weight:700">&#128336; Proximamente</span>'; }
   else if(on){ var du=(p.key==='shopify')?'/desconectar-shopify':'/desconectar-mp'; right=chip('Conectado','#34d399','#0e2a1c','#17492f')+'<a href="'+du+'" onclick="window.location.assign(\''+du+'\');return false;" style="'+ds+'">Desconectar</a>'; }
   else { var b;
    if(p.key==='mp'){ b='<a href="/conectar-mp" onclick="window.location.assign(\'/conectar-mp\');return false;" style="'+bs+'">&#9889; Conectar</a>'; }
    else if(p.key==='shopify'){ b='<a href="#" onclick="rpShopToken();return false;" style="'+bs+'">&#9889; Conectar</a>'; }
    else { b='<a href="#" onclick="alert(\'Muy pronto podes conectar \'+esc(p.nm)+\'.\');return false;" style="'+bs+'">&#9889; Conectar</a>'; }
    right=chip('No conectado','#94a3b8','#141d2c','#1e2b3d')+b; }
   h+='<div style="display:flex;align-items:center;gap:13px;background:#0f1826;border:1px solid #1e2b3d;border-radius:12px;padding:13px 17px;margin-bottom:9px">'
     +'<div style="width:44px;height:44px;border-radius:11px;flex:none;display:flex;align-items:center;justify-content:center;background:#131c2b">'+L[p.logo]+'</div>'
     +'<div style="flex:1;min-width:0"><div style="font-weight:700;font-size:14.5px;color:#f1f5f9;display:flex;align-items:center;gap:8px">'+esc(p.nm)+' <span style="font-size:10px;color:#94a3b8;background:#111c2b;border:1px solid #1e2b3d;padding:2px 8px;border-radius:16px;font-weight:600">'+p.tag+'</span></div>'
     +'<div style="color:#94a3b8;font-size:12.5px;margin-top:2px">'+esc(p.desc)+'</div></div>'
     +'<div style="display:flex;align-items:center;gap:11px;flex:none">'+right+'</div></div>';
  });
  document.getElementById('rp-integ-cards').innerHTML=h;
 }
 function load(){ cards(!!window._rpMp,!!window._rpShop);
  fetch('/mp/estado').then(function(r){return r.json();}).then(function(j){ window._rpMp=!!(j&&j.conectado); cards(!!window._rpMp,!!window._rpShop); }).catch(function(){});
  fetch('/shopify/estado').then(function(r){return r.json();}).then(function(j){ window._rpShop=!!(j&&j.conectado); cards(!!window._rpMp,!!window._rpShop); }).catch(function(){}); }
 window.rpShopToken=function(){
  var s=prompt('1) Dominio de tu tienda Shopify (ej: mitienda.myshopify.com):'); if(!s)return;
  var t=prompt('2) Pegá el Admin API access token (empieza con shpat_):'); if(!t)return;
  fetch('/shopify/guardar-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({shop:s.trim(),token:t.trim()})})
   .then(function(r){return r.json();})
   .then(function(j){ if(j&&j.ok){ window._rpShop=true; load(); alert('¡Shopify conectado! ('+(j.shop||'')+')'); } else { alert((j&&j.error)||'No se pudo conectar.'); } })
   .catch(function(){ alert('Error de conexión. Probá de nuevo.'); }); };
 window.rpInteg=function(open){ var o=document.getElementById('rp-integ-ov'); if(!o)return; o.style.display=open?'block':'none'; var b=document.getElementById('rp-integ-btn'); if(b) b.classList.toggle('rp-active',!!open); if(open) load(); };
 if(new URLSearchParams(location.search).get('integ')==='1'){ try{history.replaceState({},'','/');}catch(e){} var _n=0,_t=setInterval(function(){ _n++; var o=document.getElementById('rp-integ-ov'); if(o){ window.rpInteg(true); o.style.display='block'; } if(_n>50)clearInterval(_t); },300); }
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
    userbox = ('<div class="rp-pill" style="bottom:16px">'
               '<span class="rp-ic" style="background:#137fec;color:#fff;font-weight:700;font-size:14px">'
               + inicial + '</span>'
               '<span class="rp-lbl"><span class="em">' + email + '</span>'
               '<a href="/logout">Cerrar sesión</a></span></div>')
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


@app.get("/conectar-shopify")
@limiter.limit("30 per hour")
def conectar_shopify():
    """Manda al usuario a autorizar SU tienda Shopify (OAuth)."""
    if not _user_actual():
        return redirect("/")
    cfg = _shop_cfg()
    if not cfg["client_id"]:
        return ("Falta configurar el Client ID de Shopify (variables en Render).", 400)
    shop = _shop_normalizar(request.args.get("shop", ""))
    if not _shop_valido(shop):
        return ("Dominio de tienda inválido. Usá el formato tutienda.myshopify.com", 400)
    state = _secrets.token_urlsafe(16)
    session["shop_state"] = state
    session["shop_dom"] = shop
    qs = _url.urlencode({"client_id": cfg["client_id"], "scope": cfg["scopes"],
                         "redirect_uri": cfg["redirect_uri"], "state": state})
    return redirect("https://" + shop + "/admin/oauth/authorize?" + qs, code=302)


@app.get("/shopify/callback")
@limiter.limit("30 per hour")
def shopify_callback():
    """Shopify vuelve acá con 'code' + 'hmac'. Verificamos la firma y cambiamos el code por el token."""
    import hmac as _hmac
    import hashlib as _hashlib
    cfg = _shop_cfg()
    code = request.args.get("code")
    shop = _shop_normalizar(request.args.get("shop", ""))
    state = request.args.get("state")
    hmac_recibido = request.args.get("hmac", "")
    if not code:
        return ("RealProfit — punto de conexión con Shopify. "
                "Volvé a la app y usá el botón «Conectar».", 200)
    if not state or state != session.get("shop_state"):
        return ("La conexión no pasó el control de seguridad. Reintentá desde el botón.", 400)
    if not _shop_valido(shop):
        return ("Tienda inválida.", 400)
    # Verificar HMAC: firma de todos los params (menos hmac/signature) ordenados, con el client_secret.
    params = {k: v for k, v in request.args.items() if k not in ("hmac", "signature")}
    mensaje = "&".join("%s=%s" % (k, params[k]) for k in sorted(params))
    calc = _hmac.new(cfg["client_secret"].encode(), mensaje.encode(), _hashlib.sha256).hexdigest()
    if not hmac_recibido or not _hmac.compare_digest(calc, hmac_recibido):
        return ("La firma de Shopify no es válida. Reintentá.", 400)
    try:
        r = requests.post("https://" + shop + "/admin/oauth/access_token", json={
            "client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
            "code": code}, timeout=30)
        tok = r.json() if r.content else {}
    except Exception:
        return ("No pudimos conectar con Shopify en este momento. Probá de nuevo.", 502)
    if not tok.get("access_token"):
        return ("Shopify no autorizó la conexión. Reintentá.", 400)
    email = _user_actual()
    if not email:
        return redirect("/")
    tok["shop"] = shop
    _shop_save_token(email, tok)          # token guardado BAJO EL EMAIL → cada uno ve solo lo suyo
    session.pop("shop_state", None)
    session.pop("shop_dom", None)
    return redirect("/?integ=1", code=302)


@app.get("/shopify/estado")
def shopify_estado():
    """¿ESTE usuario tiene su Shopify conectado? Devuelve también el dominio de la tienda."""
    email = _user_actual()
    d = _shop_tokens()
    conectado = bool(email and email in d)
    shop = (d.get(email) or {}).get("shop", "") if conectado else ""
    return jsonify({"ok": True, "conectado": conectado, "shop": shop})


@app.post("/shopify/guardar-token")
@limiter.limit("40 per hour")
def shopify_guardar_token():
    """Guarda la conexión de Shopify por TOKEN (app propia de cada tienda). Verifica el token antes."""
    if not _user_actual():
        return jsonify({"ok": False, "error": "Tenés que iniciar sesión."}), 401
    data = request.get_json(silent=True) or request.form
    shop = _shop_normalizar(data.get("shop", ""))
    token = (data.get("token", "") or "").strip()
    if not _shop_valido(shop):
        return jsonify({"ok": False, "error": "Dominio inválido. Usá el formato tutienda.myshopify.com"}), 400
    if not token:
        return jsonify({"ok": False, "error": "Falta pegar el token."}), 400
    # Verificar el token contra la tienda (si anda, es válido).
    try:
        r = requests.get("https://" + shop + "/admin/api/2026-07/shop.json",
                         headers={"X-Shopify-Access-Token": token}, timeout=20)
    except Exception:
        return jsonify({"ok": False, "error": "No pudimos contactar la tienda. Revisá el dominio."}), 502
    if r.status_code != 200:
        return jsonify({"ok": False, "error": "El token no es válido para esa tienda (revisá que lo copiaste completo)."}), 400
    email = _user_actual()
    _shop_save_token(email, {"access_token": token, "shop": shop, "modo": "token"})
    return jsonify({"ok": True, "shop": shop})


@app.get("/desconectar-shopify")
def desconectar_shopify():
    email = _user_actual()
    if email:
        d = _shop_tokens()
        d.pop(email, None)
        SHOPIFY_TOKENS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    return redirect("/?integ=1")


# Catch-all defensivo: cualquier otro fetch del dashboard responde vacío (no 404, no error).
@app.route("/<path:_ruta>", methods=["GET", "POST"])
def _stub(_ruta):
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8010, debug=False)
