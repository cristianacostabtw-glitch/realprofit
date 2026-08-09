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


# ---------------- Meta (Facebook / Instagram Ads) OAuth ----------------
META_SECRETS = RAIZ / "meta_secrets.json"     # App ID + App Secret (dueño de la app)
META_TOKENS = DATA_DIR / "meta_tokens.json"   # tokens por usuario (persistente)
META_API = "v21.0"


def _meta_cfg() -> dict:
    import os
    try:
        c = _json.loads(META_SECRETS.read_text(encoding="utf-8"))
    except Exception:
        c = {}
    return {"app_id": os.getenv("META_APP_ID") or c.get("app_id", ""),
            "app_secret": os.getenv("META_APP_SECRET") or c.get("app_secret", ""),
            "redirect_uri": os.getenv("META_REDIRECT_URI") or c.get("redirect_uri",
                                                                    "http://127.0.0.1:8010/meta/callback")}


def _meta_tokens() -> dict:
    try:
        return _json.loads(META_TOKENS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _meta_save_token(key, data) -> None:
    d = _meta_tokens()
    d[str(key)] = data
    META_TOKENS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


# ---------------- Shopify OAuth (conectar con un click) ----------------
SHOPIFY_SECRETS = RAIZ / "shopify_secrets.json"   # tu Client ID + Secret (dueño de la app)
SHOPIFY_TOKENS = DATA_DIR / "shopify_tokens.json"  # tokens por usuario (persistente)
SHOPIFY_SCOPES = ("read_orders,write_orders,write_order_edits,read_fulfillments,write_fulfillments,"
                  "read_merchant_managed_fulfillment_orders,write_merchant_managed_fulfillment_orders,"
                  "read_assigned_fulfillment_orders,read_third_party_fulfillment_orders,"
                  "read_shipping,write_shipping,read_products,read_inventory,read_customers,"
                  "write_customers,read_locations,read_checkouts,write_draft_orders,write_price_rules")


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
   for(var i=0;i<kids.length;i++){ var ch=kids[i]; ch.style.display = (ch.querySelector('a[href="/dashboard"]')||ch.id==='rp-prod-nav'||ch.id==='rp-comis-nav') ? '' : 'none'; }
   Array.prototype.forEach.call(aside.children,function(c){ if(c.tagName!=='NAV' && !c.querySelector('nav') && !(c.tagName==='A' && c.getAttribute('aria-label')) && !c.classList.contains('rp-pill')) c.style.display='none'; });
   // Agregar "Productos" en la barra: clon del item de Dashboard (queda idéntico y nativo).
   if(!nav.querySelector('#rp-prod-nav')){
    var di=null, kk=nav.querySelectorAll(':scope > *');
    for(var qi=0;qi<kk.length;qi++){ if(kk[qi].querySelector('a[href="/dashboard"]')){ di=kk[qi]; break; } }
    if(di){ var cl=di.cloneNode(true); cl.id='rp-prod-nav'; cl.style.display='';
     var ael=cl.querySelector('a'); if(ael){ ael.setAttribute('href','#'); ael.removeAttribute('aria-current'); ael.classList.remove('bg-white/[0.08]'); ael.classList.remove('text-primary'); ael.addEventListener('click',function(e){ e.preventDefault(); e.stopPropagation(); window.rpProd(true); }); }
     var icn=cl.querySelector('.material-symbols-outlined'); if(icn) icn.textContent='inventory_2';
     var sp2=cl.querySelectorAll('span'); for(var sj=0;sj<sp2.length;sj++){ var s2=sp2[sj]; if(!s2.classList.contains('material-symbols-outlined') && s2.children.length===0 && (s2.textContent||'').trim()){ s2.textContent='Productos'; } }
     di.parentNode.insertBefore(cl, di.nextSibling);
    }
   }
   // Agregar "Comisiones" en la barra (debajo de Productos).
   if(!nav.querySelector('#rp-comis-nav')){
    var pn=nav.querySelector('#rp-prod-nav');
    if(pn){ var cc=pn.cloneNode(true); cc.id='rp-comis-nav'; cc.style.display='';
     var ac=cc.querySelector('a'); if(ac){ ac.setAttribute('href','#'); ac.removeAttribute('aria-current'); ac.classList.remove('bg-white/[0.08]'); ac.classList.remove('text-primary');
      var newac=ac.cloneNode(true); ac.parentNode.replaceChild(newac,ac); newac.addEventListener('click',function(e){ e.preventDefault(); e.stopPropagation(); window.rpComis(true); }); ac=newac; }
     var ico=cc.querySelector('.material-symbols-outlined'); if(ico) ico.textContent='percent';
     var sp3=cc.querySelectorAll('span'); for(var sk=0;sk<sp3.length;sk++){ var s3=sp3[sk]; if(!s3.classList.contains('material-symbols-outlined') && s3.children.length===0 && (s3.textContent||'').trim()){ s3.textContent='Comisiones'; } }
     pn.parentNode.insertBefore(cc, pn.nextSibling);
    }
   }
   // Al tocar Dashboard (o el logo), cerrar los overlays abiertos (Productos/Integraciones).
   var dls=aside.querySelectorAll('a[href="/dashboard"]');
   for(var dz=0;dz<dls.length;dz++){ if(!dls[dz]._rpc){ dls[dz]._rpc=1; dls[dz].addEventListener('click',function(){ try{window.rpProd(false);}catch(e){} try{window.rpInteg(false);}catch(e){} try{window.rpComis(false);}catch(e){} }); } }
   // Ocultar TODAS las secciones demo "Top productos" (hardcodeadas del pf.html, una por panel).
   var tops=document.querySelectorAll('h1,h2,h3,h4');
   for(var ti=0;ti<tops.length;ti++){ if((tops[ti].textContent||'').indexOf('Top productos')>-1){ var nd=tops[ti];
     for(var up=0; up<8 && nd.parentElement; up++){ nd=nd.parentElement; var cn=(typeof nd.className==='string')?nd.className:'';
      if(/rounded/.test(cn) && /border/.test(cn)){ nd.style.display='none'; break; } } } }
   // Meter los pills DENTRO del aside: al pasarles el mouse cuenta como hover de la barra y NO se cierra.
   var _pp=document.querySelectorAll('.rp-pill');
   for(var pi=0;pi<_pp.length;pi++){ if(_pp[pi].parentNode!==aside){ try{ aside.appendChild(_pp[pi]); }catch(e){} } }
   // Los pills (Integraciones + cuenta) se abren/cierran A LA PAR de la barra lateral.
   if(!aside._rpSync){ aside._rpSync=1;
    var expW=220;
    var apply=function(open,w){ var ps=document.querySelectorAll('.rp-pill'); for(var k=0;k<ps.length;k++){ ps[k].style.width=w+'px'; ps[k].classList.toggle('rp-open',open); } };
    var sync=function(){ var w=Math.round(aside.getBoundingClientRect().width); if(w>110)expW=w; apply(w>110,w); var ov=document.getElementById('rp-integ-ov'); if(ov) ov.style.left=w+'px'; var ov2=document.getElementById('rp-prod-ov'); if(ov2) ov2.style.left=w+'px'; var ov3=document.getElementById('rp-comis-ov'); if(ov3) ov3.style.left=w+'px'; };
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
<div id="rp-prod-ov" style="position:fixed;top:0;right:0;bottom:0;left:72px;z-index:100000;background:#0a111e;display:none;overflow:auto;transition:left .18s ease;font-family:system-ui,-apple-system,sans-serif">
 <div style="max-width:1120px;margin:0 auto;padding:26px 30px 60px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px">
   <div style="display:flex;align-items:center;gap:12px">
    <div style="width:42px;height:42px;border-radius:11px;background:#101c2e;border:1px solid #1e2b3d;display:flex;align-items:center;justify-content:center"><span class="material-symbols-outlined" style="color:#60a5fa">description</span></div>
    <div><h1 style="margin:0;font-size:22px;color:#f1f5f9">Costos</h1><div style="color:#94a3b8;font-size:13px;margin-top:3px">Defin&iacute; el costo de cada producto. Alimenta el margen real del Dashboard.</div></div>
   </div>
   <button onclick="rpProd(false)" title="Cerrar" style="flex:none;background:#111c2b;border:1px solid #1e2b3d;color:#cbd5e1;width:38px;height:38px;border-radius:10px;font-size:16px;cursor:pointer">&#10005;</button>
  </div>
  <div style="background:#0f1826;border:1px solid #1e2b3d;border-radius:14px;margin-top:20px">
   <div style="display:flex;align-items:center;gap:9px;padding:15px 18px;border-bottom:1px solid #1a2636;font-weight:700;color:#f1f5f9;font-size:14.5px"><span class="material-symbols-outlined" style="color:#60a5fa;font-size:19px">inventory_2</span>Productos</div>
   <div style="padding:18px">
    <div style="display:flex;justify-content:space-between;align-items:center"><h2 style="font-size:16px;color:#f1f5f9;margin:0">Costos de productos</h2><div id="rp-prod-ref" style="color:#94a3b8;font-size:12px;cursor:pointer">&#8635; Actualizar</div></div>
    <div id="rp-prod-chip" style="margin-top:14px"></div>
    <div id="rp-prod-warn" style="margin-top:16px"></div>
    <div id="rp-prod-body" style="margin-top:8px"></div>
   </div>
  </div>
 </div>
</div>
<div id="rp-comis-ov" style="position:fixed;top:0;right:0;bottom:0;left:72px;z-index:100000;background:#0a111e;display:none;overflow:auto;transition:left .18s ease;font-family:system-ui,-apple-system,sans-serif">
 <div style="max-width:900px;margin:0 auto;padding:26px 30px 60px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px">
   <div style="display:flex;align-items:center;gap:12px">
    <div style="width:42px;height:42px;border-radius:11px;background:#101c2e;border:1px solid #1e2b3d;display:flex;align-items:center;justify-content:center"><span class="material-symbols-outlined" style="color:#60a5fa">percent</span></div>
    <div><h1 style="margin:0;font-size:22px;color:#f1f5f9">Costos</h1><div style="color:#94a3b8;font-size:13px;margin-top:3px">Comisiones e impuestos. Restan del margen real del Dashboard.</div></div>
   </div>
   <button onclick="rpComis(false)" title="Cerrar" style="flex:none;background:#111c2b;border:1px solid #1e2b3d;color:#cbd5e1;width:38px;height:38px;border-radius:10px;font-size:16px;cursor:pointer">&#10005;</button>
  </div>
  <div style="display:flex;align-items:center;gap:11px;margin:22px 0 4px"><span class="material-symbols-outlined" style="color:#60a5fa;font-size:22px">account_balance_wallet</span><div style="font-weight:800;color:#f1f5f9;font-size:16px">Comisiones e impuestos</div></div>
  <div style="color:#94a3b8;font-size:12.5px;margin-bottom:6px">Carg&aacute; una vez lo que se lleva cada venta. Se descuenta de tu ganancia real.</div>

  <div style="background:#0f1826;border:1px solid #1e2b3d;border-radius:14px;padding:18px 20px;margin-top:14px;display:flex;gap:15px">
   <div style="width:44px;height:44px;border-radius:11px;flex:none;background:#0d1b30;border:1px solid #1c3350;display:flex;align-items:center;justify-content:center"><span class="material-symbols-outlined" style="color:#5aa2f5;font-size:22px">credit_card</span></div>
   <div style="flex:1;min-width:0">
    <div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap"><div style="font-weight:700;color:#f1f5f9;font-size:15px">Mercado Pago</div><span style="background:#0d1b30;border:1px solid #1c3350;color:#7db3f5;font-size:10.5px;font-weight:700;border-radius:20px;padding:2px 9px">COBROS</span></div>
    <div style="color:#94a3b8;font-size:12.5px;margin-top:5px">Se usa la plata <b style="color:#7db3f5">REAL que entra</b> a tu MercadoPago. La comisi&oacute;n y las cuotas ya vienen descontadas por MP &mdash; no cargás nada ac&aacute;.</div>
    <input id="rp-c-mp" type="hidden" value="0"><input id="rp-c-cuotas" type="hidden" value="0">
   </div>
  </div>

  <div style="background:#0f1826;border:1px solid #1e2b3d;border-radius:14px;padding:18px 20px;margin-top:14px;display:flex;gap:15px">
   <div style="width:44px;height:44px;border-radius:11px;flex:none;background:#0e2a1c;border:1px solid #17492f;display:flex;align-items:center;justify-content:center"><span class="material-symbols-outlined" style="color:#34d399;font-size:22px">storefront</span></div>
   <div style="flex:1;min-width:0">
    <div style="font-weight:700;color:#f1f5f9;font-size:15px">Comisi&oacute;n de tienda</div>
    <div style="color:#94a3b8;font-size:12.5px;margin-top:5px">Lo que cobra tu plataforma (Shopify / Tiendanube). <b style="color:#34d399">Fijo 1%</b> por venta, no editable.</div>
    <div style="margin-top:14px"><div style="display:inline-flex;align-items:center;background:#0b1220;border:1px solid #1e2b3d;border-radius:10px;overflow:hidden"><span style="padding:9px 11px;color:#64748b;font-size:13px;border-right:1px solid #1e2b3d">%</span><input id="rp-c-tienda" type="number" step="0.01" placeholder="0" style="border:none;background:transparent;color:#f1f5f9;padding:9px 12px;width:120px;font-size:13px;text-align:right;outline:none"></div></div>
   </div>
  </div>

  <input id="rp-c-iva" type="hidden" value="0">

  <div style="background:#0f1826;border:1px solid #1e2b3d;border-radius:14px;padding:18px 20px;margin-top:14px;display:flex;gap:15px">
   <div style="width:44px;height:44px;border-radius:11px;flex:none;background:#1a1533;border:1px solid #322a5a;display:flex;align-items:center;justify-content:center"><span class="material-symbols-outlined" style="color:#a78bfa;font-size:22px">account_balance</span></div>
   <div style="flex:1;min-width:0">
    <div style="font-weight:700;color:#f1f5f9;font-size:15px">Ingresos Brutos</div>
    <div style="color:#94a3b8;font-size:12.5px;margin-top:5px">IIBB provincial sobre la venta. <b style="color:#a78bfa">Fijo 3,5%</b>, no editable. A este NO se le suma IVA.</div>
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-top:14px"><div style="display:inline-flex;align-items:center;background:#0b1220;border:1px solid #1e2b3d;border-radius:10px;overflow:hidden"><span style="padding:9px 11px;color:#64748b;font-size:13px;border-right:1px solid #1e2b3d">%</span><input id="rp-c-iibb" type="number" step="0.01" placeholder="0" style="border:none;background:transparent;color:#f1f5f9;padding:9px 12px;width:120px;font-size:13px;text-align:right;outline:none"></div><span style="color:#5b6b82;font-size:12px">Fijo 3,5%</span></div>
   </div>
  </div>

  <div style="background:#0f1826;border:1px solid #1e2b3d;border-radius:14px;padding:18px 20px;margin-top:14px;display:flex;gap:15px">
   <div style="width:44px;height:44px;border-radius:11px;flex:none;background:#10233a;border:1px solid #1c3f63;display:flex;align-items:center;justify-content:center"><span class="material-symbols-outlined" style="color:#5aa2f5;font-size:22px">local_shipping</span></div>
   <div style="flex:1;min-width:0">
    <div style="font-weight:700;color:#f1f5f9;font-size:15px">Env&iacute;o</div>
    <div style="color:#94a3b8;font-size:12.5px;margin-top:5px">Se resta autom&aacute;tico por pedido. Si ten&eacute;s <b style="color:#5aa2f5">Envialo</b> conectado, usa el <b style="color:#34d399">costo REAL</b> de cada env&iacute;o; si el pedido a&uacute;n no est&aacute; en Envialo, usa promedio (Domicilio $9.000 &middot; Sucursal $6.000).</div>
   </div>
  </div>

  <div style="display:flex;justify-content:space-between;align-items:center;margin-top:20px;gap:14px;flex-wrap:wrap;background:#0c1521;border:1px solid #1e2b3d;border-radius:14px;padding:16px 20px">
   <div><div style="color:#94a3b8;font-size:12px">Impuestos que sumamos por venta (aparte del neto de MP)</div><b id="rp-c-total" style="color:#34d399;font-size:24px;font-weight:800">0%</b></div>
   <div style="display:flex;gap:12px;align-items:center"><span id="rp-c-msg" style="font-size:12.5px;font-weight:600;display:none"></span><button id="rp-c-go" onclick="rpComisSave()" style="background:#137fec;border:none;color:#fff;border-radius:10px;padding:11px 26px;font-weight:700;font-size:13.5px;cursor:pointer">Guardar</button></div>
  </div>
 </div>
</div>
<script>
(function(){
  var L={envialo:`<svg width="22" height="22" viewBox="0 0 24 24" fill="#ff6b35"><path d="M3 4a1 1 0 0 0-1 1v11a1 1 0 0 0 1 1h1a3 3 0 0 0 6 0h4a3 3 0 0 0 6 0h1a1 1 0 0 0 1-1v-4a1 1 0 0 0-.29-.71l-3-3A1 1 0 0 0 18 8h-2V5a1 1 0 0 0-1-1H3zm13 6h1.59L20 12.41V13h-4v-3zM7 16.5A1.5 1.5 0 1 1 5.5 15 1.5 1.5 0 0 1 7 16.5zm10 0A1.5 1.5 0 1 1 15.5 15a1.5 1.5 0 0 1 1.5 1.5z"/></svg>`,mp:`<svg width="21" height="21" viewBox="0 0 24 24" fill="#00b1ea"><path d="M11.115 16.479a.93.927 0 0 1-.939-.886c-.002-.042-.006-.155-.103-.155-.04 0-.074.023-.113.059-.112.103-.254.206-.46.206a.816.814 0 0 1-.305-.066c-.535-.214-.542-.578-.521-.725.006-.038.007-.08-.02-.11l-.032-.03h-.034c-.027 0-.055.012-.093.039a.788.786 0 0 1-.454.16.7.699 0 0 1-.253-.05c-.708-.27-.65-.928-.617-1.126.005-.041-.005-.072-.03-.092l-.05-.04-.047.043a.728.726 0 0 1-.505.203.73.728 0 0 1-.732-.725c0-.4.328-.722.732-.722.364 0 .675.27.721.63l.026.195.11-.165c.01-.018.307-.46.852-.46.102 0 .21.016.316.05.434.13.508.52.519.68.008.094.075.1.09.1.037 0 .064-.024.083-.045a.746.744 0 0 1 .54-.225c.128 0 .263.03.402.09.69.293.379 1.158.374 1.167-.058.144-.061.207-.005.244l.027.013h.02c.03 0 .07-.014.134-.035.093-.032.235-.08.367-.08a.944.942 0 0 1 .94.93.936.934 0 0 1-.94.928zm7.302-4.171c-1.138-.98-3.768-3.24-4.481-3.77-.406-.302-.685-.462-.928-.533a1.559 1.554 0 0 0-.456-.07c-.182 0-.376.032-.58.095-.46.145-.918.505-1.362.854l-.023.018c-.414.324-.84.66-1.164.73a1.986 1.98 0 0 1-.43.049c-.362 0-.687-.104-.81-.258-.02-.025-.007-.066.04-.125l.008-.008 1-1.067c.783-.774 1.525-1.506 3.23-1.545h.085c1.062 0 2.12.469 2.24.524a7.03 7.03 0 0 0 3.056.724c1.076 0 2.188-.263 3.354-.795a9.135 9.11 0 0 0-.405-.317c-1.025.44-2.003.66-2.946.66-.962 0-1.925-.229-2.858-.68-.05-.022-1.22-.567-2.44-.57-.032 0-.065 0-.096.002-1.434.033-2.24.536-2.782.976-.528.013-.982.138-1.388.25-.361.1-.673.186-.979.185-.125 0-.35-.01-.37-.012-.35-.01-2.115-.437-3.518-.962-.143.1-.28.203-.415.31 1.466.593 3.25 1.053 3.812 1.089.157.01.323.027.491.027.372 0 .744-.103 1.104-.203.213-.059.446-.123.692-.17l-.196.194-1.017 1.087c-.08.08-.254.294-.14.557a.705.703 0 0 0 .268.292c.243.162.677.27 1.08.271.152 0 .297-.015.43-.044.427-.095.874-.448 1.349-.82.377-.296.913-.672 1.323-.782a1.494 1.49 0 0 1 .37-.05.611.61 0 0 1 .095.005c.27.034.533.125 1.003.472.835.62 4.531 3.815 4.566 3.846.002.002.238.203.22.537-.007.186-.11.352-.294.466a.902.9 0 0 1-.484.15.804.802 0 0 1-.428-.124c-.014-.01-1.28-1.157-1.746-1.543-.074-.06-.146-.115-.22-.115a.122.122 0 0 0-.096.045c-.073.09.01.212.105.294l1.48 1.47c.002 0 .184.17.204.395.012.244-.106.447-.35.606a.957.955 0 0 1-.526.171.766.764 0 0 1-.42-.127l-.214-.206a21.035 20.978 0 0 0-1.08-1.009c-.072-.058-.148-.112-.221-.112a.127.127 0 0 0-.094.038c-.033.037-.056.103.028.212a.698.696 0 0 0 .075.083l1.078 1.198c.01.01.222.26.024.511l-.038.048a1.18 1.178 0 0 1-.1.096c-.184.15-.43.164-.527.164a.8.798 0 0 1-.147-.012c-.106-.018-.178-.048-.212-.089l-.013-.013c-.06-.06-.602-.609-1.054-.98-.059-.05-.133-.11-.21-.11a.128.128 0 0 0-.096.042c-.09.096.044.24.1.293l.92 1.003a.204.204 0 0 1-.033.062c-.033.044-.144.155-.479.196a.91.907 0 0 1-.122.007c-.345 0-.712-.164-.902-.264a1.343 1.34 0 0 0 .13-.576 1.368 1.365 0 0 0-1.42-1.357c.024-.342-.025-.99-.697-1.274a1.455 1.452 0 0 0-.575-.125c-.146 0-.287.025-.42.075a1.153 1.15 0 0 0-.671-.564 1.52 1.515 0 0 0-.494-.085c-.28 0-.537.08-.767.242a1.168 1.165 0 0 0-.903-.43 1.173 1.17 0 0 0-.82.335c-.287-.217-1.425-.93-4.467-1.613a17.39 17.344 0 0 1-.692-.189 4.822 4.82 0 0 0-.077.494l.67.157c3.108.682 4.136 1.391 4.309 1.525a1.145 1.142 0 0 0-.09.442 1.16 1.158 0 0 0 1.378 1.132c.096.467.406.821.879 1.003a1.165 1.162 0 0 0 .415.08c.09 0 .179-.012.266-.034.086.22.282.493.722.668a1.233 1.23 0 0 0 .457.094c.122 0 .241-.022.355-.063a1.373 1.37 0 0 0 1.269.841c.37.002.726-.147.985-.41.221.121.688.341 1.163.341.06 0 .118-.002.175-.01.47-.059.689-.24.789-.382a.571.57 0 0 0 .048-.078c.11.032.234.058.373.058.255 0 .501-.086.75-.265.244-.174.418-.424.444-.637v-.01c.083.017.167.026.251.026.265 0 .527-.082.773-.242.48-.31.562-.715.554-.98a1.28 1.279 0 0 0 .978-.194 1.04 1.04 0 0 0 .502-.808 1.088 1.085 0 0 0-.16-.653c.804-.342 2.636-1.003 4.795-1.483a4.734 4.721 0 0 0-.067-.492 27.742 27.667 0 0 0-5.049 1.62zm5.123-.763c0 4.027-5.166 7.293-11.537 7.293-6.372 0-11.538-3.266-11.538-7.293 0-4.028 5.165-7.293 11.539-7.293 6.371 0 11.537 3.265 11.537 7.293zm.46.004c0-4.272-5.374-7.755-12-7.755S.002 7.277.002 11.55L0 12.004c0 4.533 4.695 8.203 11.999 8.203 7.347 0 12-3.67 12-8.204z"/></svg>`,meli:`<svg width="21" height="21" viewBox="0 0 24 24" fill="#ffe600"><path d="M11.115 16.479a.93.927 0 0 1-.939-.886c-.002-.042-.006-.155-.103-.155-.04 0-.074.023-.113.059-.112.103-.254.206-.46.206a.816.814 0 0 1-.305-.066c-.535-.214-.542-.578-.521-.725.006-.038.007-.08-.02-.11l-.032-.03h-.034c-.027 0-.055.012-.093.039a.788.786 0 0 1-.454.16.7.699 0 0 1-.253-.05c-.708-.27-.65-.928-.617-1.126.005-.041-.005-.072-.03-.092l-.05-.04-.047.043a.728.726 0 0 1-.505.203.73.728 0 0 1-.732-.725c0-.4.328-.722.732-.722.364 0 .675.27.721.63l.026.195.11-.165c.01-.018.307-.46.852-.46.102 0 .21.016.316.05.434.13.508.52.519.68.008.094.075.1.09.1.037 0 .064-.024.083-.045a.746.744 0 0 1 .54-.225c.128 0 .263.03.402.09.69.293.379 1.158.374 1.167-.058.144-.061.207-.005.244l.027.013h.02c.03 0 .07-.014.134-.035.093-.032.235-.08.367-.08a.944.942 0 0 1 .94.93.936.934 0 0 1-.94.928zm7.302-4.171c-1.138-.98-3.768-3.24-4.481-3.77-.406-.302-.685-.462-.928-.533a1.559 1.554 0 0 0-.456-.07c-.182 0-.376.032-.58.095-.46.145-.918.505-1.362.854l-.023.018c-.414.324-.84.66-1.164.73a1.986 1.98 0 0 1-.43.049c-.362 0-.687-.104-.81-.258-.02-.025-.007-.066.04-.125l.008-.008 1-1.067c.783-.774 1.525-1.506 3.23-1.545h.085c1.062 0 2.12.469 2.24.524a7.03 7.03 0 0 0 3.056.724c1.076 0 2.188-.263 3.354-.795a9.135 9.11 0 0 0-.405-.317c-1.025.44-2.003.66-2.946.66-.962 0-1.925-.229-2.858-.68-.05-.022-1.22-.567-2.44-.57-.032 0-.065 0-.096.002-1.434.033-2.24.536-2.782.976-.528.013-.982.138-1.388.25-.361.1-.673.186-.979.185-.125 0-.35-.01-.37-.012-.35-.01-2.115-.437-3.518-.962-.143.1-.28.203-.415.31 1.466.593 3.25 1.053 3.812 1.089.157.01.323.027.491.027.372 0 .744-.103 1.104-.203.213-.059.446-.123.692-.17l-.196.194-1.017 1.087c-.08.08-.254.294-.14.557a.705.703 0 0 0 .268.292c.243.162.677.27 1.08.271.152 0 .297-.015.43-.044.427-.095.874-.448 1.349-.82.377-.296.913-.672 1.323-.782a1.494 1.49 0 0 1 .37-.05.611.61 0 0 1 .095.005c.27.034.533.125 1.003.472.835.62 4.531 3.815 4.566 3.846.002.002.238.203.22.537-.007.186-.11.352-.294.466a.902.9 0 0 1-.484.15.804.802 0 0 1-.428-.124c-.014-.01-1.28-1.157-1.746-1.543-.074-.06-.146-.115-.22-.115a.122.122 0 0 0-.096.045c-.073.09.01.212.105.294l1.48 1.47c.002 0 .184.17.204.395.012.244-.106.447-.35.606a.957.955 0 0 1-.526.171.766.764 0 0 1-.42-.127l-.214-.206a21.035 20.978 0 0 0-1.08-1.009c-.072-.058-.148-.112-.221-.112a.127.127 0 0 0-.094.038c-.033.037-.056.103.028.212a.698.696 0 0 0 .075.083l1.078 1.198c.01.01.222.26.024.511l-.038.048a1.18 1.178 0 0 1-.1.096c-.184.15-.43.164-.527.164a.8.798 0 0 1-.147-.012c-.106-.018-.178-.048-.212-.089l-.013-.013c-.06-.06-.602-.609-1.054-.98-.059-.05-.133-.11-.21-.11a.128.128 0 0 0-.096.042c-.09.096.044.24.1.293l.92 1.003a.204.204 0 0 1-.033.062c-.033.044-.144.155-.479.196a.91.907 0 0 1-.122.007c-.345 0-.712-.164-.902-.264a1.343 1.34 0 0 0 .13-.576 1.368 1.365 0 0 0-1.42-1.357c.024-.342-.025-.99-.697-1.274a1.455 1.452 0 0 0-.575-.125c-.146 0-.287.025-.42.075a1.153 1.15 0 0 0-.671-.564 1.52 1.515 0 0 0-.494-.085c-.28 0-.537.08-.767.242a1.168 1.165 0 0 0-.903-.43 1.173 1.17 0 0 0-.82.335c-.287-.217-1.425-.93-4.467-1.613a17.39 17.344 0 0 1-.692-.189 4.822 4.82 0 0 0-.077.494l.67.157c3.108.682 4.136 1.391 4.309 1.525a1.145 1.142 0 0 0-.09.442 1.16 1.158 0 0 0 1.378 1.132c.096.467.406.821.879 1.003a1.165 1.162 0 0 0 .415.08c.09 0 .179-.012.266-.034.086.22.282.493.722.668a1.233 1.23 0 0 0 .457.094c.122 0 .241-.022.355-.063a1.373 1.37 0 0 0 1.269.841c.37.002.726-.147.985-.41.221.121.688.341 1.163.341.06 0 .118-.002.175-.01.47-.059.689-.24.789-.382a.571.57 0 0 0 .048-.078c.11.032.234.058.373.058.255 0 .501-.086.75-.265.244-.174.418-.424.444-.637v-.01c.083.017.167.026.251.026.265 0 .527-.082.773-.242.48-.31.562-.715.554-.98a1.28 1.279 0 0 0 .978-.194 1.04 1.04 0 0 0 .502-.808 1.088 1.085 0 0 0-.16-.653c.804-.342 2.636-1.003 4.795-1.483a4.734 4.721 0 0 0-.067-.492 27.742 27.667 0 0 0-5.049 1.62zm5.123-.763c0 4.027-5.166 7.293-11.537 7.293-6.372 0-11.538-3.266-11.538-7.293 0-4.028 5.165-7.293 11.539-7.293 6.371 0 11.537 3.265 11.537 7.293zm.46.004c0-4.272-5.374-7.755-12-7.755S.002 7.277.002 11.55L0 12.004c0 4.533 4.695 8.203 11.999 8.203 7.347 0 12-3.67 12-8.204z"/></svg>`,tn:`<svg width="21" height="21" viewBox="0 0 24 24" fill="#2d6cdf"><path d="M6.5 20q-2.28 0-3.89-1.57Q1 16.85 1 14.58q0-1.95 1.17-3.48Q3.35 9.57 5.25 9.15q.63-2.3 2.5-3.72Q9.63 4 12 4q2.93 0 4.96 2.04Q19 8.07 19 11q1.73.2 2.86 1.5Q23 13.78 23 15.5q0 1.87-1.31 3.19Q20.37 20 18.5 20z"/></svg>`,shopify:`<svg width="22" height="22" width="256px" height="292px" viewBox="0 0 256 292" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" preserveAspectRatio="xMidYMid"> <g> <path d="M223.773626,57.3402078 C223.572932,55.8793405 222.29409,55.0718963 221.236945,54.9832175 C220.182133,54.8945386 197.853734,53.2399781 197.853734,53.2399781 C197.853734,53.2399781 182.346604,37.8448639 180.64537,36.1412966 C178.941803,34.4377293 175.616346,34.9558004 174.325836,35.336186 C174.134476,35.3921937 170.937371,36.3793293 165.646977,38.0152206 C160.466266,23.1101737 151.325344,9.41162582 135.241802,9.41162582 C134.798408,9.41162582 134.341011,9.43029505 133.883615,9.45596525 C129.309654,3.40713457 123.643542,0.779440373 118.74987,0.779440373 C81.285392,0.779440373 63.3862673,47.6135387 57.7738299,71.414474 C43.2164974,75.9254268 32.8737437,79.1318671 31.5528956,79.5472575 C23.4271131,82.0956074 23.1704111,82.3523094 22.1039313,90.0090275 C21.2988208,95.8058236 0.0369009009,260.235071 0.0369009009,260.235071 L165.714653,291.277334 L255.485648,271.856667 C255.485648,271.856667 223.971987,58.8010751 223.773626,57.3402078 L223.773626,57.3402078 Z M156.48972,40.8482763 C152.328815,42.1364532 147.598499,43.5996542 142.471461,45.1865388 C142.476129,44.1994032 142.480796,43.2262696 142.480796,42.1644571 C142.480796,32.8998514 141.194953,25.4414939 139.132003,19.5280151 C147.418807,20.5688247 152.937899,29.9967861 156.48972,40.8482763 L156.48972,40.8482763 Z M128.852258,21.3646006 C131.155574,27.1380602 132.65378,35.4225312 132.65378,46.6030666 C132.65378,47.1748118 132.649112,47.6975503 132.644445,48.2272897 C123.52686,51.0510108 113.620499,54.1174319 103.690802,57.1931876 C109.265901,35.6768995 119.716003,25.2851391 128.852258,21.3646006 L128.852258,21.3646006 Z M117.720729,10.8281537 C119.337951,10.8281537 120.966841,11.3765623 122.525722,12.4500431 C110.519073,18.099819 97.6489725,32.3304399 92.2138928,60.7473424 C84.2701352,63.2070135 76.506069,65.6106769 69.3277499,67.834649 C75.6939575,46.1596724 90.8113669,10.8281537 117.720729,10.8281537 L117.720729,10.8281537 Z" fill="#95BF46"></path> <path d="M221.236945,54.9832175 C220.182133,54.8945386 197.853734,53.2399781 197.853734,53.2399781 C197.853734,53.2399781 182.346604,37.8448639 180.64537,36.1412966 C180.008283,35.5065427 179.149498,35.1821649 178.251042,35.0421456 L165.723988,291.275001 L255.485648,271.856667 C255.485648,271.856667 223.971987,58.8010751 223.773626,57.3402078 C223.572932,55.8793405 222.29409,55.0718963 221.236945,54.9832175" fill="#5E8E3E"></path> <path d="M135.241802,104.585029 L124.173282,137.510551 C124.173282,137.510551 114.474617,132.334507 102.586984,132.334507 C85.1592573,132.334507 84.2818035,143.272342 84.2818035,146.028387 C84.2818035,161.066452 123.48252,166.828244 123.48252,202.052414 C123.48252,229.764553 105.90544,247.610004 82.2048516,247.610004 C53.7646126,247.610004 39.2212821,229.90924 39.2212821,229.90924 L46.8359944,204.750118 C46.8359944,204.750118 61.7853808,217.585214 74.4011133,217.585214 C82.6435785,217.585214 85.9970391,211.095323 85.9970391,206.353338 C85.9970391,186.736644 53.8369559,185.861524 53.8369559,153.629098 C53.8369559,126.500372 73.3089633,100.246767 112.614694,100.246767 C127.760108,100.246767 135.241802,104.585029 135.241802,104.585029" fill="#FFFFFF"></path> </g> </svg>`,meta:`<svg width="22" height="22" width="256px" height="171px" viewBox="0 0 256 171" version="1.1" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid"> <title>Meta</title> <defs> <linearGradient x1="13.8784354%" y1="55.9337491%" x2="89.143574%" y2="58.6936324%" id="linearGradient-1"> <stop stop-color="#0064E1" offset="0%"></stop> <stop stop-color="#0064E1" offset="40%"></stop> <stop stop-color="#0073EE" offset="83%"></stop> <stop stop-color="#0082FB" offset="100%"></stop> </linearGradient> <linearGradient x1="54.3150272%" y1="82.782443%" x2="54.3150272%" y2="39.3067715%" id="linearGradient-2"> <stop stop-color="#0082FB" offset="0%"></stop> <stop stop-color="#0064E0" offset="100%"></stop> </linearGradient> </defs> <g> <path d="M27.6511337,112.135763 C27.6511337,121.910697 29.7966337,129.415496 32.6009181,133.955766 C36.2776464,139.902629 41.7615802,142.422034 47.3523439,142.422034 C54.5633607,142.422034 61.1601057,140.632633 73.8728613,123.050216 C84.0573098,108.957574 96.0578662,89.1762415 104.132425,76.775073 L117.806649,55.7651968 C127.305606,41.1740159 138.300181,24.9536792 150.906107,13.9591042 C161.197385,4.98539435 172.29879,0 183.471415,0 C202.228961,0 220.096258,10.8699402 233.770483,31.2566421 C248.735568,53.5840868 256,81.7070524 256,110.72917 C256,127.982195 252.599249,140.659341 246.81263,150.674642 C241.221867,160.360551 230.325219,170.037557 211.994992,170.037557 L211.994992,142.422034 C227.690082,142.422034 231.607178,128 231.607178,111.494784 C231.607178,87.9744053 226.123244,61.8723049 214.042565,43.2215885 C205.469467,29.9924885 194.35916,21.9090277 182.136041,21.9090277 C168.915844,21.9090277 158.277368,31.8798164 146.321324,49.6580887 C139.964946,59.1036305 133.439421,70.61455 126.112672,83.6032828 L118.047016,97.8917791 C101.844485,126.620114 97.7404368,133.163444 89.639171,143.962164 C75.4396995,162.871053 63.3145083,170.037557 47.3523439,170.037557 C28.4167478,170.037557 16.4428989,161.838364 9.02712477,149.481708 C2.97343163,139.412992 0,126.201697 0,111.147587 L27.6511337,112.135763 Z" fill="#0081FB"></path> <path d="M21.8021978,33.2062874 C34.4793434,13.665322 52.7739602,0 73.7571289,0 C85.9090277,0 97.9897065,3.59660593 110.604535,13.8967868 C124.403394,25.1584365 139.110307,43.702323 157.458339,74.2645709 L164.037279,85.2324384 C179.919321,111.690638 188.955348,125.302546 194.243427,131.721241 C201.04493,139.964946 205.807762,142.422034 211.994992,142.422034 C227.690082,142.422034 231.607178,128 231.607178,111.494784 L256,110.72917 C256,127.982195 252.599249,140.659341 246.81263,150.674642 C241.221867,160.360551 230.325219,170.037557 211.994992,170.037557 C200.599805,170.037557 190.504382,167.562665 179.340659,157.03102 C170.758659,148.947559 160.725553,134.587843 153.007094,121.679232 L130.047573,83.3273056 C118.527751,64.0801224 107.960495,49.7293087 101.844485,43.230491 C95.2655446,36.2420364 86.8081792,27.802476 73.3120045,27.802476 C62.3886493,27.802476 53.1122548,35.4675198 45.3492836,47.192099 L21.8021978,33.2062874 Z" fill="url(#linearGradient-1)"></path> <path d="M73.3120045,27.802476 C62.3886493,27.802476 53.1122548,35.4675198 45.3492836,47.192099 C34.3725136,63.7596328 27.6511337,88.4373348 27.6511337,112.135763 C27.6511337,121.910697 29.7966337,129.415496 32.6009181,133.955766 L9.02712477,149.481708 C2.97343163,139.412992 0,126.201697 0,111.147587 C0,83.7724301 7.51370149,55.2399499 21.8021978,33.2062874 C34.4793434,13.665322 52.7739602,0 73.7571289,0 L73.3120045,27.802476 Z" fill="url(#linearGradient-2)"></path> </g> </svg>`,gads:`<svg width="22" height="22" width="256px" height="230px" viewBox="0 0 256 230" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" preserveAspectRatio="xMidYMid"> <g> <path d="M5.888,166.405103 L90.88,20.9 C101.676138,27.2558621 156.115862,57.3844138 164.908138,63.1135172 L79.9161379,208.627448 C70.6206897,220.906621 -5.888,185.040138 5.888,166.396276 L5.888,166.405103 Z" fill="#FBBC04"></path> <path d="M250.084224,166.401789 L165.092224,20.9055131 C153.210293,1.13172 127.619121,-6.05393517 106.600638,5.62496138 C85.582155,17.3038579 79.182155,42.4624786 91.0640861,63.1190303 L176.056086,208.632961 C187.938017,228.397927 213.52919,235.583582 234.547672,223.904686 C254.648086,212.225789 261.966155,186.175582 250.084224,166.419444 L250.084224,166.401789 Z" fill="#4285F4"></path> <ellipse fill="#34A853" cx="42.6637241" cy="187.924414" rx="42.6637241" ry="41.6044138"></ellipse> </g> </svg>`,tiktok:`<svg width="22" height="22" width="256px" height="290px" viewBox="0 0 256 290" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" preserveAspectRatio="xMidYMid"> <title>TikTok</title> <g> <path d="M189.720224,104.421475 C208.398189,117.766281 231.279538,125.618095 255.992548,125.618095 L255.992548,78.0872726 C251.315611,78.0882654 246.650588,77.6008156 242.074913,76.6318726 L242.074913,114.045382 C217.363889,114.045382 194.485518,106.193568 175.80259,92.8497541 L175.80259,189.846306 C175.80259,238.368905 136.447224,277.701437 87.902784,277.701437 C69.7897057,277.701437 52.9543216,272.228299 38.9691786,262.841664 C54.9309256,279.153859 77.1908018,289.273158 101.81744,289.273158 C150.364858,289.273158 189.72221,249.940626 189.72221,201.416041 L189.72221,104.421475 L189.720224,104.421475 Z M206.889179,56.4687254 C197.343701,46.0456391 191.076347,32.5757434 189.720224,17.6842019 L189.720224,11.5707278 L176.531282,11.5707278 C179.851103,30.497877 191.174632,46.6681056 206.889179,56.4687254 L206.889179,56.4687254 Z M69.6735517,225.606854 C64.3403943,218.617757 61.4583846,210.068027 61.4712906,201.277053 C61.4712906,179.084685 79.472186,161.090739 101.680438,161.090739 C105.819294,161.089747 109.933331,161.723134 113.877603,162.974023 L113.877603,114.380938 C109.268175,113.749536 104.616057,113.481488 99.9659254,113.579773 L99.9659254,151.402303 C96.0186741,150.151413 91.9026521,149.516041 87.7628035,149.520012 C65.5545513,149.520012 47.5546487,167.511972 47.5546487,189.707318 C47.5546487,205.401018 56.552118,218.98806 69.6735517,225.606854 Z" fill="#FF004F"></path> <path d="M175.80259,92.8487613 C194.485518,106.192575 217.363889,114.044389 242.074913,114.044389 L242.074913,76.6308799 C228.281375,73.6942679 216.070311,66.4897401 206.889179,56.4687254 C191.173639,46.6671128 179.851103,30.4968842 176.531282,11.5707278 L141.8876,11.5707278 L141.8876,201.414056 C141.809172,223.545865 123.839052,241.466346 101.678453,241.466346 C88.6195635,241.466346 77.0180599,235.24466 69.6705734,225.606854 C56.5501325,218.98806 47.5526631,205.400025 47.5526631,189.708311 C47.5526631,167.51495 65.5525657,149.521004 87.760818,149.521004 C92.0158278,149.521004 96.1169583,150.183182 99.9639399,151.403295 L99.9639399,113.580765 C52.272289,114.565593 13.9166419,153.513923 13.9166419,201.415048 C13.9166419,225.326893 23.4680767,247.004014 38.9701714,262.842657 C52.9553144,272.228299 69.7906985,277.70243 87.9037768,277.70243 C136.449209,277.70243 175.803582,238.367912 175.803582,189.846306 L175.803582,92.8487613 L175.80259,92.8487613 Z" fill="#000000"></path> <path d="M242.074913,76.6308799 L242.074913,66.5145593 C229.636505,66.5334219 217.442318,63.0517795 206.889179,56.4677326 C216.231139,66.6902795 228.532545,73.7389425 242.074913,76.6308799 Z M176.531282,11.5707278 C176.214589,9.76190185 175.971361,7.9411627 175.80259,6.11347418 L175.80259,0 L127.968973,0 L127.968973,189.845313 C127.89253,211.974144 109.923403,229.894625 87.760818,229.894625 C81.2542071,229.894625 75.1109499,228.350869 69.6705734,225.607847 C77.0180599,235.24466 88.6195635,241.465353 101.678453,241.465353 C123.837066,241.465353 141.810164,223.546857 141.8876,201.415048 L141.8876,11.5707278 L176.531282,11.5707278 Z M99.9659254,113.580765 L99.9659254,102.811203 C95.9690357,102.265179 91.9393845,101.991175 87.9047695,101.99315 C39.3553659,101.99315 0,141.326686 0,189.845313 C0,220.263769 15.4673478,247.071522 38.9711641,262.840672 C23.4690694,247.003021 13.9176347,225.324907 13.9176347,201.414056 C13.9176347,153.513923 52.272289,114.565593 99.9659254,113.580765 Z" fill="#00F2EA"></path> </g> </svg>`};
 var PLAT=[
  {key:'mp',logo:'mp',nm:'Mercado Pago',tag:'Pagos',desc:'Trae tus pagos y movimientos para calcular tu ganancia real.',real:true},
  {key:'shopify',logo:'shopify',nm:'Shopify',tag:'Ventas',desc:'Conecta tu tienda para centralizar ventas y costos por orden.'},
  {key:'envialo',logo:'envialo',nm:'Envialo',tag:'Envios',desc:'Trae el costo real de cada envio para restarlo de la ganancia.'},
  {key:'tn',logo:'tn',nm:'Tiendanube',tag:'Ventas',desc:'Trae tus ventas online de tu tienda para el beneficio real.'},
  {key:'meli',logo:'meli',nm:'Mercado Libre',tag:'Ventas',desc:'Incluye tus ventas de marketplace en el calculo de beneficio.'},
  {key:'meta',logo:'meta',nm:'Meta Ads',tag:'Anuncios',desc:'Trae tus campanas de Facebook e Instagram Ads.'},
  {key:'gads',logo:'gads',nm:'Google Ads',tag:'Anuncios',desc:'Trae tus campanas de Google Ads (Search, Performance Max, Shopping).'},
  {key:'tiktok',logo:'tiktok',nm:'TikTok Ads',tag:'Anuncios',desc:'Trae tus campanas de TikTok Ads para medir su rentabilidad real.',soon:true}
 ];
 function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');}
 function chip(txt,color,bg,bd){return '<span style="display:inline-flex;align-items:center;gap:7px;background:'+bg+';border:1px solid '+bd+';color:'+color+';border-radius:20px;padding:7px 14px;font-size:12.5px;font-weight:600"><span style="width:7px;height:7px;border-radius:50%;background:'+color+'"></span>'+txt+'</span>';}
 function cards(mpOn, shopOn, metaOn){
  var h='';
  var bs='background:#137fec;color:#fff;border-radius:10px;padding:9px 17px;font-weight:700;font-size:13px;text-decoration:none';
  var ds='background:#111c2b;border:1px solid #1e2b3d;color:#cbd5e1;border-radius:10px;padding:9px 15px;font-weight:600;font-size:13px;text-decoration:none';
  PLAT.forEach(function(p){
   var right, on=(p.key==='mp'&&mpOn)||(p.key==='shopify'&&shopOn)||(p.key==='meta'&&metaOn)||(p.key==='envialo'&&window._rpEnv);
   if(p.soon){ right='<span style="display:inline-flex;align-items:center;gap:6px;background:#241a10;border:1px solid #4a3a1a;color:#ffb35a;border-radius:20px;padding:7px 14px;font-size:12.5px;font-weight:700">&#128336; Proximamente</span>'; }
   else if(on){ var du=(p.key==='shopify')?'/desconectar-shopify':(p.key==='meta')?'/desconectar-meta':(p.key==='envialo')?'/desconectar-envialo':'/desconectar-mp'; right=chip('Conectado','#34d399','#0e2a1c','#17492f')+'<a href="'+du+'" onclick="window.location.assign(\''+du+'\');return false;" style="'+ds+'">Desconectar</a>'; }
   else { var b;
    if(p.key==='mp'){ b='<a href="/conectar-mp" onclick="window.location.assign(\'/conectar-mp\');return false;" style="'+bs+'">&#9889; Conectar</a>'; }
    else if(p.key==='shopify'){ b='<a href="#" onclick="rpShopToggle();return false;" style="'+bs+'">&#9889; '+(window._rpShopOpen?'Cerrar':'Conectar')+'</a>'; }
    else if(p.key==='meta'){ b='<a href="/conectar-meta" onclick="window.location.assign(\'/conectar-meta\');return false;" style="'+bs+'">&#9889; Conectar</a>'; }
    else if(p.key==='envialo'){ b='<a href="#" onclick="rpEnvToggle();return false;" style="'+bs+'">&#9889; '+(window._rpEnvOpen?'Cerrar':'Conectar')+'</a>'; }
    else { b='<a href="#" onclick="alert(\'Muy pronto podes conectar \'+esc(p.nm)+\'.\');return false;" style="'+bs+'">&#9889; Conectar</a>'; }
    right=chip('No conectado','#94a3b8','#141d2c','#1e2b3d')+b; }
   var row='<div style="display:flex;align-items:center;gap:13px;padding:13px 17px">'
     +'<div style="width:44px;height:44px;border-radius:11px;flex:none;display:flex;align-items:center;justify-content:center;background:#131c2b">'+L[p.logo]+'</div>'
     +'<div style="flex:1;min-width:0"><div style="font-weight:700;font-size:14.5px;color:#f1f5f9;display:flex;align-items:center;gap:8px">'+esc(p.nm)+' <span style="font-size:10px;color:#94a3b8;background:#111c2b;border:1px solid #1e2b3d;padding:2px 8px;border-radius:16px;font-weight:600">'+p.tag+'</span></div>'
     +'<div style="color:#94a3b8;font-size:12.5px;margin-top:2px">'+esc(p.desc)+'</div></div>'
     +'<div style="display:flex;align-items:center;gap:11px;flex:none">'+right+'</div></div>';
   var panel='';
   if(p.key==='shopify' && window._rpShopOpen && !shopOn) panel=rpShopPanel();
   else if(p.key==='meta' && metaOn) panel=rpMetaPanel();
   else if(p.key==='envialo' && window._rpEnvOpen && !window._rpEnv) panel=rpEnvPanel();
   h+='<div style="background:#0f1826;border:1px solid #1e2b3d;border-radius:12px;margin-bottom:9px;overflow:hidden">'+row+panel+'</div>';
  });
  document.getElementById('rp-integ-cards').innerHTML=h;
  if(metaOn){ try{ rpMetaLoad(); }catch(e){} }
 }
 function rpMetaPanel(){ return '<div style="border-top:1px solid #1e2b3d;padding:14px 17px;background:#0c1521"><div style="font-weight:700;color:#e2e8f0;font-size:12.5px;margin-bottom:8px">Cuenta publicitaria <span style="color:#94a3b8;font-weight:400">(de ac&aacute; sale el gasto de ads)</span></div><div id="rp-meta-cuentas" style="color:#94a3b8;font-size:12.5px">Cargando cuentas...</div></div>'; }
 function rpMetaRender(cuentas,elegida){ var c=document.getElementById('rp-meta-cuentas'); if(!c)return;
  if(!cuentas.length){ c.innerHTML='<span style="color:#94a3b8;font-size:12px">No encontramos cuentas publicitarias en tu Meta (revis&aacute; permisos).</span>'; return; }
  var h='<select onchange="rpMetaSave(this.value)" style="background:#0b1220;border:1px solid #1e2b3d;color:#f1f5f9;border-radius:9px;padding:9px 12px;font-size:13px;min-width:280px;max-width:100%"><option value="">Eleg&iacute; una cuenta...</option>';
  cuentas.forEach(function(a){ var sel=(String(a.id)===String(elegida))?' selected':''; h+='<option value="'+a.id+'"'+sel+'>'+esc(a.name)+' (act_'+a.id+')</option>'; });
  h+='</select>'+(elegida?'<span style="color:#34d399;font-size:12px;margin-left:10px;font-weight:600">&#10003; guardada</span>':'');
  c.innerHTML=h; }
 window.rpMetaLoad=function(force){ var c=document.getElementById('rp-meta-cuentas'); if(!c)return;
  if(window._rpMetaCuentas && !force){ rpMetaRender(window._rpMetaCuentas.cuentas, window._rpMetaCuentas.elegida); return; }
  fetch('/meta/cuentas').then(function(r){return r.json();}).then(function(j){ window._rpMetaCuentas={cuentas:(j&&j.cuentas)||[],elegida:j&&j.elegida}; rpMetaRender(window._rpMetaCuentas.cuentas, window._rpMetaCuentas.elegida); }).catch(function(){ var e=document.getElementById('rp-meta-cuentas'); if(e)e.innerHTML='<span style="color:#f87171;font-size:12px">No se pudieron cargar las cuentas.</span>'; }); };
 window.rpMetaSave=function(cid){ if(!cid)return; fetch('/meta/cuenta',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cuenta:cid})}).then(function(r){return r.json();}).then(function(){ if(window._rpMetaCuentas)window._rpMetaCuentas.elegida=cid; rpMetaRender((window._rpMetaCuentas||{}).cuentas||[],cid); }).catch(function(){}); };
 function load(){ cards(!!window._rpMp,!!window._rpShop,!!window._rpMeta);
  fetch('/mp/estado').then(function(r){return r.json();}).then(function(j){ window._rpMp=!!(j&&j.conectado); cards(!!window._rpMp,!!window._rpShop,!!window._rpMeta); }).catch(function(){});
  fetch('/shopify/estado').then(function(r){return r.json();}).then(function(j){ window._rpShop=!!(j&&j.conectado); cards(!!window._rpMp,!!window._rpShop,!!window._rpMeta); }).catch(function(){});
  fetch('/meta/estado').then(function(r){return r.json();}).then(function(j){ window._rpMeta=!!(j&&j.conectado); cards(!!window._rpMp,!!window._rpShop,!!window._rpMeta); }).catch(function(){});
  fetch('/envialo/estado').then(function(r){return r.json();}).then(function(j){ window._rpEnv=!!(j&&j.conectado); cards(!!window._rpMp,!!window._rpShop,!!window._rpMeta); }).catch(function(){}); }
 function rpShopPanel(){ var CB='https://www.realprofitapp.com/shopify/callback'; return ''
  +'<div style="border-top:1px solid #1e2b3d;padding:16px 17px 18px;background:#0c1521">'
  +'<div style="font-weight:700;color:#e2e8f0;font-size:13px">1) Dominio de tu tienda</div>'
  +'<input id="rp-shop-dom" placeholder="mitienda.myshopify.com" style="width:100%;margin-top:6px;background:#0b1220;border:1px solid #1e2b3d;color:#f1f5f9;border-radius:8px;padding:9px 11px;font-size:13px;box-sizing:border-box">'
  +'<div style="font-weight:700;color:#e2e8f0;font-size:13px;margin-top:14px">2) En tu app de Shopify, peg&aacute; esta <b>URL de redireccionamiento</b>:</div>'
  +'<div style="position:relative;margin-top:6px">'
  +'<input id="rp-shop-redirect" readonly value="'+CB+'" style="width:100%;background:#0b1220;border:1px solid #1e2b3d;color:#93c5fd;border-radius:8px;padding:9px 64px 9px 11px;font-size:12px;font-family:ui-monospace,monospace;box-sizing:border-box">'
  +'<button onclick="rpCopy(\'rp-shop-redirect\',this)" style="position:absolute;top:6px;right:6px;background:#137fec;color:#fff;border:none;border-radius:6px;padding:5px 10px;font-size:11.5px;font-weight:600;cursor:pointer">Copiar</button>'
  +'</div>'
  +'<div style="color:#94a3b8;font-size:11.5px;margin-top:6px">Pon&eacute; la app en <b style="color:#cbd5e1">Distribuci&oacute;n personalizada</b> (NO p&uacute;blica) y tild&aacute; estos permisos:</div>'
  +'<div style="position:relative;margin-top:6px">'
  +'<textarea id="rp-shop-scopes" readonly rows="4" style="width:100%;background:#0b1220;border:1px solid #1e2b3d;color:#93c5fd;border-radius:8px;padding:9px 40px 9px 11px;font-size:11.5px;font-family:ui-monospace,monospace;box-sizing:border-box;resize:none">read_orders,write_orders,write_order_edits,read_fulfillments,write_fulfillments,read_merchant_managed_fulfillment_orders,write_merchant_managed_fulfillment_orders,read_assigned_fulfillment_orders,read_third_party_fulfillment_orders,read_shipping,write_shipping,read_products,read_inventory,read_customers,write_customers,read_locations,read_checkouts,write_draft_orders,write_price_rules</textarea>'
  +'<button onclick="rpCopy(\'rp-shop-scopes\',this)" style="position:absolute;top:7px;right:7px;background:#137fec;color:#fff;border:none;border-radius:6px;padding:4px 10px;font-size:11.5px;font-weight:600;cursor:pointer">Copiar</button>'
  +'</div>'
  +'<div style="font-weight:700;color:#e2e8f0;font-size:13px;margin-top:14px">3) Peg&aacute; el <b>Client ID</b> y el <b>Client Secret</b> de tu app:</div>'
  +'<input id="rp-shop-cid" placeholder="Client ID" style="width:100%;margin-top:6px;background:#0b1220;border:1px solid #1e2b3d;color:#f1f5f9;border-radius:8px;padding:9px 11px;font-size:13px;box-sizing:border-box">'
  +'<input id="rp-shop-secret" placeholder="Client Secret (shpss_...)" style="width:100%;margin-top:7px;background:#0b1220;border:1px solid #1e2b3d;color:#f1f5f9;border-radius:8px;padding:9px 11px;font-size:13px;box-sizing:border-box">'
  +'<div style="color:#94a3b8;font-size:11.5px;margin-top:6px">Al tocar Conectar te lleva a Shopify a <b style="color:#cbd5e1">aprobar</b>, y vuelve conectado.</div>'
  +'<div id="rp-shop-msg" style="margin-top:12px;font-size:12.5px;display:none;font-weight:600"></div>'
  +'<div style="display:flex;gap:9px;justify-content:flex-end;margin-top:14px">'
  +'<button onclick="rpShopToggle()" style="background:#111c2b;border:1px solid #1e2b3d;color:#cbd5e1;border-radius:8px;padding:9px 15px;font-weight:600;font-size:12.5px;cursor:pointer">Cancelar</button>'
  +'<button id="rp-shop-go" onclick="rpShopGo()" style="background:#137fec;border:none;color:#fff;border-radius:8px;padding:9px 20px;font-weight:700;font-size:12.5px;cursor:pointer">Conectar</button>'
  +'</div></div>'; }
 window.rpShopToggle=function(){ window._rpShopOpen=!window._rpShopOpen; cards(!!window._rpMp,!!window._rpShop,!!window._rpMeta); };
 window.rpEnvToggle=function(){ window._rpEnvOpen=!window._rpEnvOpen; cards(!!window._rpMp,!!window._rpShop,!!window._rpMeta); };
 function rpEnvPanel(){ return ''
  +'<div style="border-top:1px solid #1e2b3d;padding:16px 17px 18px;background:#0c1521">'
  +'<div style="font-weight:700;color:#e2e8f0;font-size:13px">Peg&aacute; tu <b>API Key</b> de Envialo</div>'
  +'<div style="color:#94a3b8;font-size:11.5px;margin-top:5px">La sac&aacute;s de Envialo &rarr; Configuraci&oacute;n &rarr; API. Con eso traemos el costo real de cada env&iacute;o.</div>'
  +'<input id="rp-env-key" placeholder="rl_..." style="width:100%;margin-top:9px;background:#0b1220;border:1px solid #1e2b3d;color:#f1f5f9;border-radius:8px;padding:9px 11px;font-size:13px;box-sizing:border-box;font-family:ui-monospace,monospace">'
  +'<div id="rp-env-msg" style="margin-top:12px;font-size:12.5px;display:none;font-weight:600"></div>'
  +'<div style="display:flex;gap:9px;justify-content:flex-end;margin-top:14px">'
  +'<button onclick="rpEnvToggle()" style="background:#111c2b;border:1px solid #1e2b3d;color:#cbd5e1;border-radius:8px;padding:9px 15px;font-weight:600;font-size:12.5px;cursor:pointer">Cancelar</button>'
  +'<button id="rp-env-go" onclick="rpEnvGo()" style="background:#137fec;border:none;color:#fff;border-radius:8px;padding:9px 20px;font-weight:700;font-size:12.5px;cursor:pointer">Vincular</button>'
  +'</div></div>'; }
 window.rpEnvGo=function(){ var k=(document.getElementById('rp-env-key').value||'').trim(); var msg=document.getElementById('rp-env-msg'); var go=document.getElementById('rp-env-go');
  function show(txt,ok){ msg.style.display='block'; msg.style.color=ok?'#34d399':'#f87171'; msg.textContent=txt; }
  if(!k){ show('Pegá tu API key de Envialo.',false); return; }
  go.disabled=true; go.textContent='Vinculando...';
  fetch('/envialo/conectar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({api_key:k})})
   .then(function(r){return r.json();})
   .then(function(j){ if(j&&j.ok){ window._rpEnv=true; window._rpEnvOpen=false; show('¡Vinculado!',true); cards(!!window._rpMp,!!window._rpShop,!!window._rpMeta); } else { go.disabled=false; go.textContent='Vincular'; show((j&&j.error)||'No se pudo vincular.',false); } })
   .catch(function(){ go.disabled=false; go.textContent='Vincular'; show('Error de conexión. Probá de nuevo.',false); }); };
 window.rpCopy=function(id,btn){ var t=document.getElementById(id); if(!t)return; var v=(t.value!==undefined&&t.value!=='')?t.value:t.textContent; try{ if(t.select)t.select(); document.execCommand('copy'); }catch(e){} try{ navigator.clipboard.writeText(v); }catch(e){} if(btn){ var o=btn.textContent; btn.textContent='¡Copiado!'; setTimeout(function(){ btn.textContent=o; },1200); } };
 window.rpShopGo=function(){ var d=document.getElementById('rp-shop-dom').value.trim(); var cid=document.getElementById('rp-shop-cid').value.trim(); var sec=document.getElementById('rp-shop-secret').value.trim(); var msg=document.getElementById('rp-shop-msg'); var go=document.getElementById('rp-shop-go');
  function show(txt,ok){ msg.style.display='block'; msg.style.color=ok?'#34d399':'#f87171'; msg.textContent=txt; }
  if(!d){ show('Poné el dominio de tu tienda (paso 1).',false); return; }
  if(!cid||!sec){ show('Pegá el Client ID y el Client Secret (paso 3).',false); return; }
  go.disabled=true; go.textContent='Conectando...';
  fetch('/shopify/byoa-start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({shop:d,client_id:cid,client_secret:sec})})
   .then(function(r){return r.json();})
   .then(function(j){ if(j&&j.ok&&j.url){ show('Redirigiendo a Shopify...',true); window.location.assign(j.url); } else { go.disabled=false; go.textContent='Conectar'; show((j&&j.error)||'No se pudo iniciar la conexión.',false); } })
   .catch(function(){ go.disabled=false; go.textContent='Conectar'; show('Error de conexión. Probá de nuevo.',false); }); };
 window.rpInteg=function(open){ var o=document.getElementById('rp-integ-ov'); if(!o)return; if(open){ var op=document.getElementById('rp-prod-ov'); if(op) op.style.display='none'; try{rpProdSetActive(false);}catch(e){} var oc=document.getElementById('rp-comis-ov'); if(oc) oc.style.display='none'; try{rpComisSetActive(false);}catch(e){} } o.style.display=open?'block':'none'; var b=document.getElementById('rp-integ-btn'); if(b) b.classList.toggle('rp-active',!!open); if(open) load(); };
 function rpProdSetActive(on){ try{ var pa=document.querySelector('#rp-prod-nav a'); if(pa){ pa.classList.toggle('bg-white/[0.08]',!!on); pa.classList.toggle('text-primary',!!on); }
   var das=document.querySelectorAll('aside nav a[href="/dashboard"]'), da=null; for(var i=0;i<das.length;i++){ if(das[i].querySelector('.material-symbols-outlined')){ da=das[i]; break; } }
   if(da){ da.classList.toggle('bg-white/[0.08]',!on); da.classList.toggle('text-primary',!on); }
   var pc=document.querySelector('#rp-comis-nav a'); if(pc && on){ pc.classList.remove('bg-white/[0.08]'); pc.classList.remove('text-primary'); } }catch(e){} }
 window.rpProd=function(open){ var o=document.getElementById('rp-prod-ov'); if(!o)return; if(open){ var oi=document.getElementById('rp-integ-ov'); if(oi) oi.style.display='none'; var ib=document.getElementById('rp-integ-btn'); if(ib) ib.classList.remove('rp-active'); var oc=document.getElementById('rp-comis-ov'); if(oc) oc.style.display='none'; try{rpComisSetActive(false);}catch(e){} } o.style.display=open?'block':'none'; rpProdSetActive(!!open); if(open) rpProdLoad(); };
 function rpComisSetActive(on){ try{ var pa=document.querySelector('#rp-comis-nav a'); if(pa){ pa.classList.toggle('bg-white/[0.08]',!!on); pa.classList.toggle('text-primary',!!on); }
   var das=document.querySelectorAll('aside nav a[href="/dashboard"]'), da=null; for(var i=0;i<das.length;i++){ if(das[i].querySelector('.material-symbols-outlined')){ da=das[i]; break; } }
   var pp=document.querySelector('#rp-prod-nav a');
   if(on){ if(da){ da.classList.remove('bg-white/[0.08]'); da.classList.remove('text-primary'); } if(pp){ pp.classList.remove('bg-white/[0.08]'); pp.classList.remove('text-primary'); } }
   else { if(da){ da.classList.add('bg-white/[0.08]'); da.classList.add('text-primary'); } } }catch(e){} }
 function rpComisTotal(){ var g=function(id){var el=document.getElementById(id); return el?(parseFloat(el.value||'0')||0):0;};
   var ti=g('rp-c-tienda'), iva=g('rp-c-iva'), iibb=g('rp-c-iibb'), t;
   if(window._rpMpReal!=null){ t=window._rpMpReal + ti + iibb; }
   else { t=(g('rp-c-mp')+g('rp-c-cuotas'))*(1+iva/100) + ti + iibb; }
   var el=document.getElementById('rp-c-total'); if(el) el.textContent=(Math.round(t*100)/100)+'%'; }
 window.rpComis=function(open){ var o=document.getElementById('rp-comis-ov'); if(!o)return; if(open){ var op=document.getElementById('rp-prod-ov'); if(op)op.style.display='none'; try{rpProdSetActive(false);}catch(e){} var oi=document.getElementById('rp-integ-ov'); if(oi){oi.style.display='none'; var ib=document.getElementById('rp-integ-btn'); if(ib)ib.classList.remove('rp-active');} } o.style.display=open?'block':'none'; rpComisSetActive(!!open); if(open) rpComisLoad(); };
 function rpComisLoad(){ fetch('/pf-comisiones').then(function(r){return r.json();}).then(function(j){ var c=(j&&j.comis)||{};
    var set=function(id,v){var el=document.getElementById(id); if(el)el.value=(!v||v===0)?'':v;};
    // 1% tienda y 3,5% Ingresos Brutos: FIJOS y no editables (pedido del usuario).
    var fix=function(id,v){var el=document.getElementById(id); if(!el)return; el.value=v; el.readOnly=true; el.style.opacity='.65'; el.style.cursor='not-allowed'; el.oninput=null; el.title='Fijo, no editable';};
    fix('rp-c-tienda',1); fix('rp-c-iibb',3.5);
    rpComisTotal();
   }).catch(function(){ rpComisTotal(); }); }
 window.rpComisSave=function(){ var g=function(id){var el=document.getElementById(id); return el?(parseFloat(el.value||'0')||0):0;};
   var body={mp_comision:g('rp-c-mp'),mp_cuotas:g('rp-c-cuotas'),comision_tienda:g('rp-c-tienda'),iva:g('rp-c-iva'),ingresos_brutos:g('rp-c-iibb')};
   var go=document.getElementById('rp-c-go'),msg=document.getElementById('rp-c-msg'); if(go){go.disabled=true; go.textContent='Guardando...';}
   fetch('/pf-comisiones',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json();}).then(function(j){ if(go){go.disabled=false; go.textContent='Guardar';} if(msg){msg.style.display='inline'; msg.style.color='#34d399'; msg.textContent='¡Guardado!'; setTimeout(function(){msg.style.display='none';},1500);} rpComisTotal(); }).catch(function(){ if(go){go.disabled=false; go.textContent='Guardar';} if(msg){msg.style.display='inline'; msg.style.color='#f87171'; msg.textContent='Error, probá de nuevo';} }); };
 function rpProdWarn(){ var warn=document.getElementById('rp-prod-warn'); if(!warn)return; var n=document.querySelectorAll('#rp-prod-body .rp-sincosto').length;
  warn.innerHTML = n>0 ? '<div style="display:flex;align-items:center;gap:14px;background:#1c1608;border:1px solid #4a3a1a;border-radius:12px;padding:13px 16px"><span style="font-size:18px">&#9888;&#65039;</span><div style="flex:1"><b style="color:#f1f5f9;font-size:13.5px">'+n+' '+(n===1?'producto':'productos')+' sin costo cargado</b><div style="color:#c9a35b;font-size:12.5px;margin-top:2px">Su ganancia se calcula de m&aacute;s. Carg&aacute; el costo para que el margen sea real.</div></div></div>' : ''; }
 window.rpSaveCosto=function(inp,id){ var v=parseFloat(String(inp.value||'').replace(/\./g,'').replace(',','.'))||0;
  fetch('/pf-guardar-costo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,costo:v})}).catch(function(){});
  var row=inp.closest('tr'); var b=row&&row.querySelector('.rp-badge');
  if(b){ if(v>0){ b.className='rp-badge rp-concosto'; b.style.cssText='background:#0e2a1c;border:1px solid #17492f;color:#34d399;border-radius:7px;padding:3px 9px;font-size:11.5px;font-weight:600'; b.innerHTML='&#10003; Cargado'; } else { b.className='rp-badge rp-sincosto'; b.style.cssText='background:#2a2210;border:1px solid #4a3a1a;color:#f0c674;border-radius:7px;padding:3px 9px;font-size:11.5px;font-weight:600'; b.innerHTML='&#9888;&#65039; Sin costo'; } }
  rpProdWarn(); };
 function rpProdLoad(){ var chip=document.getElementById('rp-prod-chip'), warn=document.getElementById('rp-prod-warn'), body=document.getElementById('rp-prod-body'); if(!body)return;
  body.innerHTML='<div style="color:#94a3b8;font-size:13px;padding:24px 4px">Cargando...</div>'; warn.innerHTML=''; chip.innerHTML='';
  fetch('/pf-productos').then(function(r){return r.json();}).then(function(j){
   var ps=(j&&j.productos)||[]; var tienda=j&&j.tienda;
   if(!tienda){ chip.innerHTML=''; warn.innerHTML=''; body.innerHTML='<div style="text-align:center;color:#94a3b8;font-size:13.5px;padding:46px 12px;border:1px dashed #24354c;border-radius:12px;margin-top:8px">A&uacute;n no conectaste una tienda.<br><span style="font-size:12.5px;line-height:1.9">Conect&aacute; <b style="color:#cbd5e1">Shopify</b> o <b style="color:#cbd5e1">Tiendanube</b> en Integraciones y ac&aacute; van a aparecer tus productos.</span></div>'; return; }
   chip.innerHTML='<span style="display:inline-flex;align-items:center;gap:9px;background:#0d1826;border:1px solid #29527e;color:#e2e8f0;border-radius:12px;padding:9px 14px;font-weight:600;font-size:13.5px">'+(tienda==='Shopify'?L.shopify:L.tn)+'<span>'+tienda+'</span><span style="background:#152238;border:1px solid #23344d;color:#93c5fd;border-radius:20px;padding:1px 9px;font-size:12px;font-weight:700">'+ps.length+'</span><span style="width:8px;height:8px;border-radius:50%;background:#22c55e"></span></span>';
   if(!ps.length){ warn.innerHTML=''; body.innerHTML='<div style="color:#94a3b8;font-size:13px;padding:24px 4px">Tu tienda no tiene productos cargados todav&iacute;a.</div>'; return; }
   var h='<table style="width:100%;border-collapse:collapse;margin-top:14px"><thead><tr><th style="text-align:left;color:#94a3b8;font-size:12px;font-weight:600;padding:9px 10px;border-bottom:1px solid #1a2636">Producto</th><th style="text-align:right;color:#94a3b8;font-size:12px;font-weight:600;padding:9px 10px;border-bottom:1px solid #1a2636">Precio de venta</th><th style="text-align:right;color:#94a3b8;font-size:12px;font-weight:600;padding:9px 10px;border-bottom:1px solid #1a2636">Costo</th></tr></thead><tbody>';
   ps.forEach(function(p){ var img=p.img?'<img src="'+p.img+'" style="width:100%;height:100%;object-fit:cover">':'&#128247;';
    var tiene=p.costo&&Number(p.costo)>0;
    var badge= tiene ? '<span class="rp-badge rp-concosto" style="background:#0e2a1c;border:1px solid #17492f;color:#34d399;border-radius:7px;padding:3px 9px;font-size:11.5px;font-weight:600">&#10003; Cargado</span>' : '<span class="rp-badge rp-sincosto" style="background:#2a2210;border:1px solid #4a3a1a;color:#f0c674;border-radius:7px;padding:3px 9px;font-size:11.5px;font-weight:600">&#9888;&#65039; Sin costo</span>';
    h+='<tr><td style="padding:14px 10px;border-bottom:1px solid #141f2e"><div style="display:flex;align-items:center;gap:13px"><div style="width:44px;height:44px;border-radius:9px;background:#101c2e;border:1px solid #1e2b3d;flex:none;overflow:hidden;display:flex;align-items:center;justify-content:center">'+img+'</div><div style="min-width:0"><div style="font-weight:600;color:#f1f5f9;font-size:14px">'+esc(p.nombre)+'</div><div style="margin-top:5px">'+badge+'</div>'+(p.sku?'<div style="color:#5b6b82;font-size:11.5px;margin-top:5px">SKU: '+esc(p.sku)+'</div>':'')+'</div></div></td>'
    +'<td style="padding:14px 10px;border-bottom:1px solid #141f2e;text-align:right;color:#f1f5f9;font-weight:600;font-size:14px">'+(p.precio?('$ '+Number(p.precio).toLocaleString('es-AR')):'&mdash;')+'</td>'
    +'<td style="padding:14px 10px;border-bottom:1px solid #141f2e;text-align:right"><input value="'+(tiene?Number(p.costo).toLocaleString('es-AR'):'')+'" placeholder="0" onchange="rpSaveCosto(this,\''+p.id+'\')" style="width:110px;background:#0b1220;border:1px solid #1e2b3d;color:#f1f5f9;border-radius:9px;padding:9px 12px;font-size:13px;text-align:right"></td></tr>'; });
   h+='</tbody></table>'; body.innerHTML=h; rpProdWarn();
   var rf=document.getElementById('rp-prod-ref'); if(rf) rf.onclick=rpProdLoad;
  }).catch(function(){ body.innerHTML='<div style="color:#f87171;font-size:13px;padding:24px 4px">No se pudieron cargar los productos.</div>'; }); }
 if(new URLSearchParams(location.search).get('integ')==='1'){ try{history.replaceState({},'','/');}catch(e){} var _n=0,_t=setInterval(function(){ _n++; var o=document.getElementById('rp-integ-ov'); if(o){ window.rpInteg(true); o.style.display='block'; } if(_n>50)clearInterval(_t); },300); }
})();
</script>
<script>
/* Parche breakeven: el dashboard compilado calcula mal el Break Even ROAS (0.00x) y CPA
   (costos viejos). Sobreescribo esas 2 tarjetas con los valores reales del backend
   (be_roas = facturación / contribución antes de ads · be_cpa = contribución antes de ads / pedidos). */
(function(){
  var _raw=null, _of=window.fetch;
  window.fetch=function(){ var args=arguments, p=_of.apply(this,args);
    try{ var u=(args[0]&&args[0].url)||args[0];
      if(typeof u==='string' && u.indexOf('/pf-periodo')>-1){
        p.then(function(res){ try{ res.clone().json().then(function(j){ var r=(j&&j.raw)||j;
          if(r && (r.be_cpa!=null || r.be_roas!=null)){ _raw=r; setTimeout(paint,80); setTimeout(paint,450); } }).catch(function(){}); }catch(e){} });
      } }catch(e){}
    return p; };
  function money(n){ try{ return '$'+Math.round(n).toLocaleString('es-AR'); }catch(e){ return '$'+Math.round(n); } }
  function set(label,text){ var all=document.querySelectorAll('span');
    for(var i=0;i<all.length;i++){ if((all[i].textContent||'').trim()===label){ var box=all[i].parentElement; if(!box)continue;
      var v=box.nextElementSibling; while(v && !(/font-bold/.test(v.className||''))) v=v.nextElementSibling;
      if(v && v.textContent!==text) v.textContent=text; } } }
  function paint(){ if(!_raw)return;
    try{ costos4(); }catch(e){}
    try{ metricas(); }catch(e){} }
  function num(n){ return (Math.round((n||0)*100)/100); }
  function esHeader(el){ return !!(el && /col-span-full/.test(el.className||'')); }
  // La grilla es PLANA: headers (Finanzas/Publicidad/Costos) son divs col-span-full y las tarjetas son hermanas.
  function findGrid(){ var sp=document.querySelectorAll('span');
    for(var i=0;i<sp.length;i++){ var cn=sp[i].className||''; if((sp[i].textContent||'').trim()==='Publicidad' && /uppercase/.test(cn) && /tracking/.test(cn)){
      var hdr=sp[i]; for(var k=0;k<6 && hdr;k++){ hdr=hdr.parentElement; if(esHeader(hdr)) break; }
      if(esHeader(hdr) && hdr.parentElement) return hdr.parentElement; } }
    return null; }
  function metricas(){ if(!_raw)return; var grid=findGrid(); if(!grid) return;
    // Recolecto las tarjetas de la sección PUBLICIDAD (entre su header y el próximo) y remapeo POR POSICIÓN.
    var inPub=false, cards=[], kids=grid.children;
    for(var i=0;i<kids.length;i++){ var el=kids[i];
      if(esHeader(el)){ inPub = (el.textContent||'').indexOf('Publicidad')>=0; continue; }
      if(inPub){ var c=/rounded-2xl/.test(el.className||'')?el:(el.querySelector?el.querySelector('[class*=\"rounded-2xl\"]'):null); if(c) cards.push(c); } }
    if(!cards.length) return;
    var seq=[['Gasto Ads',money(_raw.publi_ars||0),'Inversión en anuncios'],
             ['Margen',num(_raw.margen)+'%','Ganancia ÷ facturación'],
             ['ROAS',num(_raw.roas)+'x','Recuperás por cada $1 invertido'],
             ['Break Even ROAS',num(_raw.be_roas)+'x','Mínimo para no perder'],
             ['CPA',money(_raw.cpa||0),'Costo por cada venta'],
             ['Break Even CPA',money(_raw.be_cpa||0),'Tope por venta'],
             ['Recompras',String(_raw.recompras||0),'Clientes que recompraron'],
             ['Facturación Recompra',money(_raw.fact_recompra||0),'Ventas de clientes que volvieron']];
    for(var j=0;j<cards.length && j<seq.length;j++) setCard(cards[j], seq[j][0], seq[j][1], seq[j][2]); }
  // ESTRUCTURA (no depende de los datos → corre de entrada, evita el parpadeo):
  // esconde la sección FINANZAS entera y las tarjetas de PUBLICIDAD sobrantes (Reembolsos, etc.).
  function estructura(){ var grid=findGrid(); if(!grid) return; var kids=grid.children, sec='', pub=0;
    for(var i=0;i<kids.length;i++){ var el=kids[i], tgt='';
      if(esHeader(el)){ sec=el.textContent||''; pub=0; tgt=/Finanzas/.test(sec)?'none':''; if(el.style.display!==tgt) el.style.display=tgt; continue; }
      if(/Finanzas/.test(sec)) tgt='none';                       // tarjetas de Finanzas → fuera
      else if(/Publicidad/.test(sec)){ pub++; tgt = (pub>8)?'none':''; }  // más de 8 (Reembolsos) → fuera
      if(el.style.display!==tgt) el.style.display=tgt; } }
  function cardDe(label){ var sp=document.querySelectorAll('span');
    for(var i=0;i<sp.length;i++){ var s=sp[i], cn=s.className||'';
      // SOLO etiquetas de tarjeta (uppercase + tracking) → evita el sidebar y otros textos.
      if((s.textContent||'').trim()===label && /uppercase/.test(cn) && /tracking/.test(cn)){
        var card=s; for(var k=0;k<9 && card;k++){ card=card.parentElement; if(card && /rounded/.test(card.className||'')) break; }
        return (card && /rounded/.test(card.className||'')) ? card : null; } }
    return null; }
  function cardByAny(labels){ for(var i=0;i<labels.length;i++){ var c=cardDe(labels[i]); if(c) return c; } return null; }
  function costos4(){ if(!_raw)return;
    // SOLO la sección COSTOS: busco cada tarjeta por su etiqueta propia (nunca toca Finanzas).
    var viejo=document.getElementById('rp-costos4'); if(viejo) viejo.remove();
    var neto=(_raw.facturado||0)-(_raw.mp_costo_real||0)-(_raw.tienda_monto||0);
    var slots=[
      [['Costo producto','Productos'],'Productos',_raw.costo_prod,'Costo de los productos vendidos'],
      [['Comisiones','Envíos'],'Envíos',_raw.envio_monto,'Lo que pagás de envío'],
      [['Costo envíos','IIBB'],'IIBB',_raw.iibb_monto,'Impuesto a pagar al mes (3,5%)'],
      [['Logística','Neto por venta'],'Neto por venta',neto,'Lo que te queda tras MercadoPago + 1% tienda']
    ];
    for(var s=0;s<slots.length;s++){ var card=cardByAny(slots[s][0]);
      if(card){ if(card.style.display==='none') card.style.display=''; setCard(card, slots[s][1], money(slots[s][2]||0), slots[s][3]); } } }
  function setCard(card,label,val,sub){
    var sps=card.querySelectorAll('span'), lab=null;
    for(var i=0;i<sps.length;i++){ var cn=sps[i].className||''; if(/uppercase/.test(cn)&&/tracking/.test(cn)){ lab=sps[i]; break; } }
    if(lab && lab.textContent!==label) lab.textContent=label;
    var dvs=card.querySelectorAll('div'), v=null;
    for(var d=0;d<dvs.length;d++){ var cd=dvs[d].className||''; if(/font-bold/.test(cd)&&/(text-2xl|text-xl)/.test(cd)){ v=dvs[d]; break; } }
    if(v && v.textContent!==val) v.textContent=val;
    var ps=card.querySelectorAll('p'); if(ps.length){ var p=ps[ps.length-1]; if(p.textContent!==sub) p.textContent=sub; } }
  // ===== Modal de detalle de orden (al tocar una fila de "Últimas ventas") =====
  function esc(s){ return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function fmt(n){ try{ return '$'+Math.round(n||0).toLocaleString('es-AR'); }catch(e){ return '$'+Math.round(n||0); } }
  function fechaTxt(f){ try{ var d=new Date(f); return d.toLocaleDateString('es-AR')+' '+d.toLocaleTimeString('es-AR',{hour:'2-digit',minute:'2-digit'}); }catch(e){ return f||''; } }
  window.cerrarOrden=function(){ var ov=document.getElementById('rp-orden-ov'); if(ov) ov.style.display='none'; };
  window.abrirOrden=function(num){
    fetch('/pf-orden?num='+encodeURIComponent(num)).then(function(r){return r.json();}).then(function(j){
      if(!j||!j.ok||!j.orden) return; var o=j.orden;
      var items=(o.items||[]).map(function(it){
        var foto = it.foto ? '<img src=\"'+it.foto+'\" style=\"width:46px;height:46px;border-radius:9px;object-fit:cover;background:#101c2e;border:1px solid #1e2b3d\">' : '<div style=\"width:46px;height:46px;border-radius:9px;background:#101c2e;border:1px solid #1e2b3d\"></div>';
        return '<div style=\"display:flex;align-items:center;gap:12px;padding:10px 0;border-top:1px solid #16202e\">'+foto+'<div style=\"flex:1;min-width:0\"><div style=\"color:#e7edf5;font-size:13px;font-weight:600;line-height:1.3\">'+esc(it.nombre)+'</div><div style=\"color:#7a8aa0;font-size:12px;margin-top:2px\">'+fmt(it.precio)+' × '+it.cantidad+'</div></div><div style=\"color:#e7edf5;font-weight:700;font-size:13.5px\">'+fmt(it.precio*it.cantidad)+'</div></div>'; }).join('');
      function fila(l,v,neg,strong){ return '<div style=\"display:flex;justify-content:space-between;align-items:center;padding:11px 0;border-top:1px solid #16202e\"><span style=\"color:'+(strong?'#e7edf5':'#93a3b8')+';font-size:13px'+(strong?';font-weight:700':'')+'\">'+l+'</span><span style=\"color:'+(strong?'#34d399':(neg?'#fb7185':'#e7edf5'))+';font-weight:'+(strong?'800':'600')+';font-size:'+(strong?'16px':'13.5px')+'\">'+v+'</span></div>'; }
      var body='<div style=\"display:flex;align-items:center;justify-content:space-between;gap:10px\">'
        +'<div style=\"display:flex;align-items:center;gap:11px\"><div style=\"width:38px;height:38px;border-radius:11px;background:#0d1b30;border:1px solid #1c3350;display:flex;align-items:center;justify-content:center;font-size:18px\">🛍️</div>'
        +'<div><div style=\"color:#f1f5f9;font-weight:800;font-size:15px\">Venta en '+esc(o.origen)+'</div><div style=\"color:#7a8aa0;font-size:12px\">Orden #'+esc(o.num)+'</div></div></div>'
        +'<div style=\"display:flex;align-items:center;gap:8px\"><span style=\"background:#0e2a1c;border:1px solid #17492f;color:#34d399;font-size:11.5px;font-weight:700;border-radius:20px;padding:3px 11px\">'+esc(o.estado)+'</span>'
        +'<button onclick=\"cerrarOrden()\" style=\"background:#111c2b;border:1px solid #1e2b3d;color:#cbd5e1;border-radius:9px;width:30px;height:30px;cursor:pointer;font-size:14px\">✕</button></div></div>'
        +'<div style=\"margin-top:14px;color:#93a3b8;font-size:12.5px;line-height:1.9\">🕐 '+fechaTxt(o.fecha)+'<br>👤 '+esc(o.cliente)+' <span style=\"color:#5b6b82\">'+esc(o.email)+'</span><br>💳 '+esc(o.medio)+'</div>'
        +'<div style=\"margin-top:14px;background:#0b111b;border:1px solid #1a2636;border-radius:12px;padding:2px 14px 12px\"><div style=\"color:#7a8aa0;font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;padding-top:10px\">Productos · '+(o.items||[]).length+' item'+((o.items||[]).length===1?'':'s')+'</div>'+items+'</div>'
        +'<div style=\"margin-top:14px;background:#0b111b;border:1px solid #1a2636;border-radius:12px;padding:2px 14px 12px\"><div style=\"color:#7a8aa0;font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;padding-top:10px\">Resumen financiero</div>'
        +fila('Total',fmt(o.total))
        +(o.descuento?fila('Descuento','-'+fmt(o.descuento),true):'')
        +(o.fee_mp?fila('Comisión de pago · MercadoPago','-'+fmt(o.fee_mp),true):'')
        +(o.fee_cuotas?fila('Comisión de cuotas ('+o.cuotas+'x)','-'+fmt(o.fee_cuotas),true):'')
        +fila('Fee tienda (1%)','-'+fmt(o.fee_tienda),true)
        +(o.costo_prod?fila('Costo de productos','-'+fmt(o.costo_prod),true):fila('Costo de productos','cargá en Productos'))
        +fila('Neto',fmt(o.neto),false,true)+'</div>';
      var ov=document.getElementById('rp-orden-ov');
      if(!ov){ ov=document.createElement('div'); ov.id='rp-orden-ov'; ov.style.cssText='position:fixed;inset:0;z-index:100000;background:rgba(3,7,12,.72);display:flex;align-items:center;justify-content:center;padding:20px'; ov.addEventListener('click',function(e){ if(e.target===ov) cerrarOrden(); }); document.body.appendChild(ov); }
      ov.innerHTML='<div style=\"width:100%;max-width:440px;max-height:88vh;overflow:auto;background:#0b111b;border:1px solid #1e2b3d;border-radius:18px;padding:18px;box-shadow:0 24px 60px rgba(0,0,0,.6)\">'+body+'</div>';
      ov.style.display='flex';
    }).catch(function(){}); }
  // ===== Tabla "Últimas ventas" propia (la del dashboard es placeholder sin cablear) =====
  var _vt={dias:7,per:10,page:1,data:[],loading:false};
  function vtFecha(iso){ try{ var d=new Date(iso); return d.toLocaleDateString('es-AR',{day:'2-digit',month:'short'})+', '+d.toLocaleTimeString('es-AR',{hour:'2-digit',minute:'2-digit'}); }catch(e){ return iso||''; } }
  function cargarVentas(){ _vt.loading=true; renderVentas();
    fetch('/pf-ventas?dias='+_vt.dias).then(function(r){return r.json();}).then(function(j){ _vt.data=(j&&j.ventas)||[]; _vt.loading=false; _vt.page=1; renderVentas(); }).catch(function(){ _vt.loading=false; _vt.data=[]; renderVentas(); }); }
  function renderVentas(){ var tb=document.getElementById('rp-vt-body'); if(!tb) return;
    var all=_vt.data, tot=all.length, pages=Math.max(1,Math.ceil(tot/_vt.per));
    if(_vt.page>pages) _vt.page=pages; var ini=(_vt.page-1)*_vt.per, rows=all.slice(ini,ini+_vt.per);
    var tdb='padding:13px 10px;border-bottom:1px solid #131e2c;font-size:13px';
    if(_vt.loading) tb.innerHTML='<tr><td colspan=\"7\" style=\"color:#5b6b82;padding:20px 10px\">Cargando…</td></tr>';
    else if(!rows.length) tb.innerHTML='<tr><td colspan=\"7\" style=\"color:#5b6b82;padding:20px 10px\">Sin ventas en el período</td></tr>';
    else tb.innerHTML=rows.map(function(v){ var pend=(v.estado||'').toLowerCase().indexOf('pend')>=0;
      return '<tr style=\"cursor:pointer\" onmouseover=\"this.style.background=&#39;#0f1826&#39;\" onmouseout=\"this.style.background=&#39;&#39;\" onclick=\"abrirOrden(&#39;'+v.num+'&#39;)\">'
        +'<td style=\"'+tdb+';color:#cbd5e1;font-weight:700\">#'+esc(v.num)+'</td>'
        +'<td style=\"'+tdb+'\"><span style=\"background:#0d1b30;border:1px solid #1c3350;color:#9cc7f5;font-size:11.5px;font-weight:600;border-radius:16px;padding:3px 9px\">🛍️ '+esc(v.origen)+'</span></td>'
        +'<td style=\"'+tdb+'\"><span style=\"background:'+(pend?'#241a0e':'#0e2a1c')+';border:1px solid '+(pend?'#4a3a1a':'#17492f')+';color:'+(pend?'#f0b429':'#34d399')+';font-size:11px;font-weight:700;border-radius:14px;padding:2px 9px\">'+esc(v.estado)+'</span></td>'
        +'<td style=\"'+tdb+';color:#93a3b8\">'+vtFecha(v.fecha)+'</td>'
        +'<td style=\"'+tdb+';text-align:right\">'+fmt(v.total)+'</td>'
        +'<td style=\"'+tdb+';text-align:right;color:#34d399;font-weight:700\">'+fmt(v.neto)+'</td>'
        +'<td style=\"'+tdb+';text-align:right;color:#5aa2f5;font-size:12.5px\">ver ›</td></tr>'; }).join('');
    var cnt=document.getElementById('rp-vt-cnt'); if(cnt) cnt.textContent= tot? ((ini+1)+'–'+Math.min(ini+_vt.per,tot)+' de '+tot+' órdenes') : '0 órdenes';
    var pgn=document.getElementById('rp-vt-pgn'); if(pgn) pgn.textContent=_vt.page+' / '+pages;
    var db=document.querySelectorAll('#rp-vt-dias button'); for(var i=0;i<db.length;i++){ var on=(+db[i].getAttribute('data-d')===_vt.dias); db[i].style.background=on?'#5aa2f5':'transparent'; db[i].style.color=on?'#04121f':'#93a3b8'; }
    var pb=document.querySelectorAll('#rp-vt-pp button'); for(var j=0;j<pb.length;j++){ var o2=(+pb[j].getAttribute('data-n')===_vt.per); pb[j].style.background=o2?'#5aa2f5':'#0b1220'; pb[j].style.color=o2?'#04121f':'#93a3b8'; pb[j].style.borderColor=o2?'#5aa2f5':'#1e2b3d'; } }
  function vtCSV(){ var rows=[['N','Origen','Estado','Fecha','Total','Neto']].concat(_vt.data.map(function(v){return [v.num,v.origen,v.estado,v.fecha,v.total,v.neto];}));
    var csv=rows.map(function(r){return r.join(',');}).join('\n'); var a=document.createElement('a'); a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv); a.download='ventas.csv'; a.click(); }
  function tablaVentas(){
    var head=null, all=document.querySelectorAll('span,h2,h3,div,p');
    for(var i=0;i<all.length;i++){ var el=all[i]; if(el.childElementCount===0 && (el.textContent||'').trim()==='Últimas ventas'){ head=el; break; } }
    var mine=document.getElementById('rp-ventas-panel');
    if(mine){ if(head){ var pp=head; for(var k=0;k<10&&pp;k++){ pp=pp.parentElement; if(pp&&/rounded-2xl|rounded-xl/.test(pp.className||'')){ if(pp.style.display!=='none')pp.style.display='none'; break; } } } return; }
    if(!head) return;
    var panel=head; for(var k2=0;k2<10&&panel;k2++){ panel=panel.parentElement; if(panel&&/rounded-2xl|rounded-xl/.test(panel.className||'')) break; }
    if(!panel||!/rounded/.test(panel.className||'')) return;
    panel.style.display='none';
    var m=document.createElement('div'); m.id='rp-ventas-panel'; m.style.cssText='background:#0b111b;border:1px solid #1e2b3d;border-radius:18px;padding:18px';
    var TH='color:#5b6b82;font-size:10.5px;font-weight:800;letter-spacing:.6px;text-transform:uppercase;padding:12px 10px;border-bottom:1px solid #1e2b3d';
    m.innerHTML='<div style=\"display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:6px\">'
      +'<div style=\"display:flex;align-items:center;gap:9px;font-weight:800;font-size:15px;color:#e7edf5\"><span style=\"width:26px;height:26px;border-radius:8px;background:#0d1b30;border:1px solid #1c3350;display:flex;align-items:center;justify-content:center;color:#5aa2f5\">🧾</span>Últimas ventas</div>'
      +'<div style=\"display:flex;align-items:center;gap:8px;flex-wrap:wrap\"><span id=\"rp-vt-csv\" style=\"color:#93a3b8;font-size:12.5px;cursor:pointer\">⬇ CSV</span>'
      +'<div id=\"rp-vt-dias\" style=\"display:flex;background:#0b1220;border:1px solid #1e2b3d;border-radius:10px;overflow:hidden\">'
      +['7','14','30','60','90'].map(function(d){return '<button data-d=\"'+d+'\" style=\"background:transparent;border:0;color:#93a3b8;padding:7px 12px;font-size:12.5px;font-weight:700;cursor:pointer\">'+d+'d</button>';}).join('')+'</div></div></div>'
      +'<div style=\"overflow-x:auto\"><table style=\"width:100%;border-collapse:collapse\"><thead><tr>'
      +'<th style=\"'+TH+';text-align:left\">Nº Venta</th><th style=\"'+TH+';text-align:left\">Origen</th><th style=\"'+TH+';text-align:left\">Estado</th><th style=\"'+TH+';text-align:left\">Fecha</th>'
      +'<th style=\"'+TH+';text-align:right\">Total</th><th style=\"'+TH+';text-align:right\">Neto</th><th style=\"'+TH+';text-align:right\">Acción</th>'
      +'</tr></thead><tbody id=\"rp-vt-body\"></tbody></table></div>'
      +'<div style=\"display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:12px;color:#93a3b8;font-size:12.5px\"><span id=\"rp-vt-cnt\">—</span>'
      +'<div style=\"display:flex;gap:16px;align-items:center;flex-wrap:wrap\"><div id=\"rp-vt-pp\" style=\"display:flex;align-items:center;gap:6px\"><span>Por página</span>'
      +['5','10','25','50'].map(function(n){return '<button data-n=\"'+n+'\" style=\"background:#0b1220;border:1px solid #1e2b3d;color:#93a3b8;border-radius:8px;padding:5px 11px;font-size:12.5px;font-weight:700;cursor:pointer\">'+n+'</button>';}).join('')+'</div>'
      +'<div style=\"display:flex;align-items:center;gap:8px\"><button id=\"rp-vt-prev\" style=\"background:#0b1220;border:1px solid #1e2b3d;color:#93a3b8;border-radius:8px;padding:5px 11px;cursor:pointer\">‹</button><span id=\"rp-vt-pgn\">1 / 1</span><button id=\"rp-vt-next\" style=\"background:#0b1220;border:1px solid #1e2b3d;color:#93a3b8;border-radius:8px;padding:5px 11px;cursor:pointer\">›</button></div></div></div>';
    panel.parentElement.insertBefore(m, panel.nextSibling);
    document.getElementById('rp-vt-dias').addEventListener('click',function(e){ var d=e.target.getAttribute&&e.target.getAttribute('data-d'); if(d){ _vt.dias=+d; cargarVentas(); } });
    document.getElementById('rp-vt-pp').addEventListener('click',function(e){ var n=e.target.getAttribute&&e.target.getAttribute('data-n'); if(n){ _vt.per=+n; _vt.page=1; renderVentas(); } });
    document.getElementById('rp-vt-prev').onclick=function(){ if(_vt.page>1){ _vt.page--; renderVentas(); } };
    document.getElementById('rp-vt-next').onclick=function(){ _vt.page++; renderVentas(); };
    document.getElementById('rp-vt-csv').onclick=vtCSV;
    cargarVentas();
  }
  // Layout FIJO: KPI (Ventas/Facturación/Ticket/Ganancia) arriba, después Resumen (Publicidad+Costos)
  // y Últimas ventas. Escondo gráfico, Recomendación y Riesgos. Uso CSS 'order' (no toca el DOM → no pelea con React).
  function leafTxt(t){ var all=document.querySelectorAll('span,h2,h3,div,p'); for(var i=0;i<all.length;i++){ var e=all[i]; if(e.childElementCount===0 && (e.textContent||'').trim()===t) return e; } return null; }
  function layoutFijo(){
    var rt=leafTxt('Resumen del período'), ut=leafTxt('Últimas ventas'); if(!rt||!ut) return;
    var anc=[], a=rt; while(a){ anc.push(a); a=a.parentElement; }
    var cont=ut; while(cont && anc.indexOf(cont)<0) cont=cont.parentElement; if(!cont) return;
    var kids=cont.children;
    for(var i=0;i<kids.length;i++){ var el=kids[i], t=el.textContent||'', ord=90, hide=false;
      if(/Facturaci/.test(t) && /Ganancia/.test(t) && /Ticket/.test(t)) ord=1;              // fila KPI
      else if(t.indexOf('Resumen del per')>=0) ord=2;                                        // Publicidad + Costos
      else if(t.indexOf('Últimas ventas')>=0) ord=3;                                         // tabla
      else if(el.querySelector && el.querySelector('[class*=\"rounded\"]')) hide=true;       // gráfico / Recomendación / Riesgos
      if(el.style.order!==String(ord)) el.style.order=ord;
      var d=hide?'none':''; if(el.style.display!==d) el.style.display=d; }
    if(getComputedStyle(cont).display==='block') cont.style.display='flex', cont.style.flexDirection='column';
  }
  // Mientras arrastrás para reordenar ("Mover"), NO re-aplico nada (sino cancelo el drag).
  var _busy=false, _bt=null;
  document.addEventListener('pointerdown', function(){ _busy=true; }, true);
  document.addEventListener('pointerup', function(){ clearTimeout(_bt); _bt=setTimeout(function(){ _busy=false; try{ tick(); }catch(e){} }, 500); }, true);
  var _th=null;
  function tick(){ if(_busy) return; try{ layoutFijo(); }catch(e){} try{ estructura(); }catch(e){} try{ tablaVentas(); }catch(e){} if(_raw){ try{ paint(); }catch(e){} } }
  function schedule(){ if(_busy||_th) return; _th=setTimeout(function(){ _th=null; tick(); }, 120); }   // throttle: no en cada mutación
  try{ new MutationObserver(schedule).observe(document.body,{childList:true,subtree:true}); }catch(e){}
  [0,150,350,700,1300,2600].forEach(function(ms){ setTimeout(tick, ms); });   // arranques rápidos → sin parpadeo de Finanzas
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
                 "ventas_recompras", "ventas_periodo", "meli_ventas", "meli_unidades", "tot_ordenes"]
    ceros_float = ["facturado", "cobrado", "costo_prod", "envio", "comision", "impuestos",
                   "com_plataforma", "com_pago", "fullfilment", "envios", "envio_prom",
                   "costos_extra", "reemb_perdida", "gan_por_venta", "cpa", "publi_ars",
                   "publi_cuenta", "ganancia", "margen", "roas", "roas_be", "ticket",
                   "tasa_recompra", "facturacion_recompras",
                   "meli_facturado", "meli_cobrado", "meli_comision", "meli_costo", "meli_ganancia",
                   "meli_rent", "meli_fullfilment", "meli_aov", "meli_roas",
                   "tot_facturado", "tot_ganancia", "tot_margen", "tot_costo", "tot_fullfilment",
                   "tot_gan_por_venta", "tot_aov"]
    r = {"fecha": h, "desde": h, "hasta": h, "actualizado": h,
         "moneda": "ARS", "dolar": 1200.0}
    for k in ceros_int:
        r[k] = 0
    for k in ceros_float:
        r[k] = 0.0
    return r


def _blob_vacio() -> dict:
    return {"raw": resumen_vacio(), "prod": [], "ords": []}


# ---------------- Datos reales de Shopify → dashboard ----------------
def _shopify_orders(shop, token, desde, hasta):
    """Trae los pedidos de Shopify del período (paginado por Link header)."""
    out = []
    url = "https://%s/admin/api/2026-07/orders.json" % shop
    params = {"status": "any", "limit": 250,
              "created_at_min": desde + "T00:00:00-03:00",
              "created_at_max": hasta + "T23:59:59-03:00",
              "fields": "id,order_number,name,total_price,current_total_price,financial_status,cancelled_at,line_items,refunds,created_at,shipping_lines,shipping_address"}
    headers = {"X-Shopify-Access-Token": token}
    for _ in range(40):
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if r.status_code != 200:
            break
        out.extend(r.json().get("orders", []))
        link = r.headers.get("Link", "") or r.headers.get("link", "")
        nxt = None
        for part in link.split(","):
            if 'rel="next"' in part and "<" in part and ">" in part:
                nxt = part[part.find("<") + 1:part.find(">")]
        if not nxt:
            break
        url = nxt
        params = None
    return out


_MP_COST_CACHE = {}
TIENDA_PCT = 1.0        # comisión de tienda (Shopify/TN): 1% fijo por venta, no editable
IIBB_PCT = 3.5          # Ingresos Brutos: 3,5% fijo por venta, no editable
ENVIO_DOMICILIO = 9000  # costo promedio de envío a domicilio (Andreani)
ENVIO_SUCURSAL = 6000   # costo promedio de envío a sucursal (Andreani)


def _envio_costo(o) -> int:
    """Costo de envío del pedido según sea domicilio o sucursal (promedios fijos).
    Fallback cuando el pedido todavía no está en Envialo."""
    sl = o.get("shipping_lines") or []
    txt = " ".join(((s.get("title") or "") + " " + (s.get("code") or "")) for s in sl).lower()
    if any(k in txt for k in ("sucursal", "pickup", "pick up", "retiro", "punto")):
        return ENVIO_SUCURSAL
    return ENVIO_DOMICILIO


ENVIALO_BASE = "https://www.envialo.com.ar/api/v1"
ENVIALO_KEYS = DATA_DIR / "envialo_keys.json"   # API key de Envialo por usuario (persistente)
_ENVIALO_CACHE = {}   # email -> (ts, {nº pedido: costo})


def _envialo_keys() -> dict:
    try:
        return _json.loads(ENVIALO_KEYS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _envialo_save_key(email, key) -> None:
    d = _envialo_keys()
    d[str(email)] = key
    ENVIALO_KEYS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def _envialo_key_de(email):
    import os
    return (_envialo_keys().get(email) or os.getenv("ENVIALO_API_KEY", "")) if email else ""


def _envialo_fetch(key: str) -> dict:
    """{nº de pedido → costo REAL de envío} pegándole a Envialo con esa API key."""
    out = {}
    try:
        for pg in range(40):
            r = requests.get(ENVIALO_BASE + "/orders", headers={"X-API-Key": key},
                             params={"page": pg, "limit": 50}, timeout=30)
            if r.status_code != 200:
                break
            j = r.json()
            for o in j.get("orders", []):
                n = str(o.get("number") or "").strip()
                sc = o.get("shipping_cost")
                if n and sc not in (None, "", 0):
                    try:
                        out[n] = float(sc)
                    except (TypeError, ValueError):
                        pass
            if not j.get("hasMore"):
                break
    except Exception:
        pass
    return out


def _envialo_costos(email=None):
    """{nº de pedido → costo REAL de envío} desde la cuenta Envialo de ESE usuario.
    Vacío si no conectó su API key. Cache 5 min por usuario."""
    import time as _t
    key = _envialo_key_de(email)
    if not key:
        return {}
    c = _ENVIALO_CACHE.get(email)
    if c and (_t.time() - c[0] < 300):
        return c[1]
    out = _envialo_fetch(key)
    _ENVIALO_CACHE[email] = (_t.time(), out)
    return out


@app.get("/envialo/estado")
def envialo_estado():
    email = _user_actual()
    return jsonify({"ok": True, "conectado": bool(email and email in _envialo_keys())})


@app.post("/envialo/conectar")
@limiter.limit("20 per hour")
def envialo_conectar():
    """Guarda la API key de Envialo del usuario. Valida pegándole una vez a la API."""
    email = _user_actual()
    if not email:
        return jsonify({"ok": False, "error": "Tenés que iniciar sesión."}), 401
    data = request.get_json(silent=True) or request.form
    key = (data.get("api_key", "") or "").strip()
    if not key:
        return jsonify({"ok": False, "error": "Pegá tu API key de Envialo."}), 400
    try:
        r = requests.get(ENVIALO_BASE + "/orders", headers={"X-API-Key": key},
                         params={"page": 0, "limit": 1}, timeout=25)
        if r.status_code in (401, 403):
            return jsonify({"ok": False, "error": "La API key no es válida (Envialo la rechazó)."}), 400
        if r.status_code != 200:
            return jsonify({"ok": False, "error": "Envialo no respondió bien. Probá de nuevo."}), 400
    except Exception:
        return jsonify({"ok": False, "error": "No pudimos conectar con Envialo. Probá de nuevo."}), 502
    _envialo_save_key(email, key)
    _ENVIALO_CACHE.pop(email, None)
    return jsonify({"ok": True})


@app.get("/desconectar-envialo")
def desconectar_envialo():
    email = _user_actual()
    if email:
        d = _envialo_keys()
        d.pop(email, None)
        ENVIALO_KEYS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
        _ENVIALO_CACHE.pop(email, None)
    return redirect("/?integ=1")


def _mp_costos(email, desde, hasta):
    """Costos REALES de MercadoPago del período (de la cuenta MP conectada del usuario).
    costo real por pago = transaction_amount − net_received_amount (incluye comisión +
    financiación de cuotas + IVA, todo lo que MP realmente te sacó).
    Devuelve montos y % separando 1 pago (al instante) de cuotas (3 sin interés). None si no hay MP."""
    import os, time as _t
    tk = _mp_tokens().get(email)
    token = tk.get("access_token") if tk else None
    if not token:
        return None
    key = (email, desde, hasta)
    c = _MP_COST_CACHE.get(key)
    if c and (_t.time() - c[0] < 300):
        return c[1]
    ini = desde + "T00:00:00.000-03:00"
    fin = hasta + "T23:59:59.999-03:00"
    vol1 = cost1 = volc = costc = 0.0
    n1 = nc = 0
    offset = 0
    try:
        while True:
            r = requests.get("https://api.mercadopago.com/v1/payments/search",
                             headers={"Authorization": "Bearer " + token},
                             params={"sort": "date_approved", "criteria": "desc",
                                     "range": "date_approved", "begin_date": ini, "end_date": fin,
                                     "status": "approved", "offset": offset, "limit": 100}, timeout=30)
            if r.status_code >= 400:
                return None if offset == 0 else None
            data = r.json()
            res = data.get("results") or []
            for p in res:
                ta = float(p.get("transaction_amount") or 0)
                det = p.get("transaction_details") or {}
                net = float(det.get("net_received_amount") or 0)
                costo = (ta - net) if net else sum(float(f.get("amount") or 0)
                                                   for f in (p.get("fee_details") or []))
                inst = int(p.get("installments") or 1)
                if inst <= 1:
                    vol1 += ta; cost1 += costo; n1 += 1
                else:
                    volc += ta; costc += costo; nc += 1
            offset += 100
            if offset >= (data.get("paging") or {}).get("total", 0) or not res:
                break
    except Exception:
        return None
    vol = vol1 + volc
    costo = cost1 + costc
    out = {"vol": round(vol, 2), "costo": round(costo, 2),
           "pct_total": round(costo / vol * 100, 2) if vol else 0.0,
           "pct_1pago": round(cost1 / vol1 * 100, 2) if vol1 else 0.0,
           "pct_cuotas": round(costc / volc * 100, 2) if volc else 0.0,
           "costo_1pago": round(cost1, 2), "costo_cuotas": round(costc, 2),
           "n_1pago": n1, "n_cuotas": nc}
    _MP_COST_CACHE[key] = (_t.time(), out)
    return out


@app.get("/pf-mp-costos")
def pf_mp_costos():
    """% real que te saca MercadoPago (al instante vs 3 cuotas), para mostrar en Comisiones."""
    email = _user_actual()
    if not email:
        return jsonify({"ok": False})
    desde = request.args.get("desde") or _hoy()
    hasta = request.args.get("hasta") or desde
    mp = _mp_costos(email, desde, hasta)
    if mp is None:
        return jsonify({"ok": True, "conectado": False})
    return jsonify({"ok": True, "conectado": True, **mp})


@app.get("/pf-debug-ordenes")
def pf_debug_ordenes():
    """Detalle de costos REALES por pedido (últimos N) para verificar el cálculo pedido-por-pedido."""
    email = _user_actual()
    if not email:
        return jsonify({"ok": False})
    n = int(request.args.get("n") or 3)
    desde = request.args.get("desde") or (_dt.date.today() - _dt.timedelta(days=10)).isoformat()
    hasta = request.args.get("hasta") or _hoy()
    tk = _shop_tokens().get(email)
    if not tk or not tk.get("access_token"):
        return jsonify({"ok": True, "shopify": False})
    try:
        orders = _shopify_orders(tk.get("shop"), tk.get("access_token"), desde, hasta)
    except Exception:
        return jsonify({"ok": False, "error": "shopify"})
    orders = [o for o in orders if not o.get("cancelled_at")]
    orders.sort(key=lambda o: int(o.get("order_number") or 0), reverse=True)
    costos = (_costos().get(email) or {})
    emap = _envialo_costos(email)
    pagos = _mp_pagos_lista(email, desde, hasta)
    by_ref, by_amt = {}, {}
    for p in (pagos or []):
        if p["ref"]:
            by_ref.setdefault(str(p["ref"]), []).append(p)
        by_amt.setdefault(p["amount"], []).append(p)
    out = []
    for o in orders[:n]:
        tot = float(o.get("total_price") or o.get("current_total_price") or 0)
        u = sum(int(li.get("quantity") or 0) for li in (o.get("line_items") or []))
        cp = sum(float(costos.get(str(li.get("product_id") or "")) or 0) * int(li.get("quantity") or 0)
                 for li in (o.get("line_items") or []))
        num = str(o.get("order_number") or o.get("name") or "").replace("#", "").strip()
        # envío real o promedio
        env = emap.get(num)
        env_fuente = "envialo" if env is not None else "promedio"
        if env is None:
            env = _envio_costo(o)
        # match MP
        pago = None
        if pagos is not None:
            for ref in (str(o.get("id")), str(o.get("order_number")), num):
                lst = by_ref.get(ref)
                if lst:
                    pago = lst.pop(0); break
            if pago is None:
                lst = by_amt.get(round(tot))
                if lst:
                    pago = lst.pop(0)
        mp_fee = pago["fee"] if pago else 0.0
        mp_neto = pago["net"] if pago else None
        iibb = tot * IIBB_PCT / 100.0
        tienda = tot * TIENDA_PCT / 100.0
        gan = tot - cp - mp_fee - env - iibb - tienda
        out.append({"pedido": num, "total": round(tot, 2), "unidades": u,
                    "costo_prod": round(cp, 2), "mp_fee": round(mp_fee, 2),
                    "mp_neto_recibido": (round(mp_neto, 2) if mp_neto is not None else None),
                    "mp_matcheo": ("ok" if pago else "SIN MATCH"),
                    "envio": round(env, 2), "envio_fuente": env_fuente,
                    "iibb": round(iibb, 2), "tienda": round(tienda, 2),
                    "ganancia": round(gan, 2)})
    return jsonify({"ok": True, "shopify": True, "mp_conectado": pagos is not None, "ordenes": out})


_IMG_CACHE = {}


def _shop_img(shop, token, product_id):
    """URL de la foto de un producto de Shopify (cacheada). '' si no hay."""
    pid = str(product_id or "").strip()
    if not pid:
        return ""
    if pid in _IMG_CACHE:
        return _IMG_CACHE[pid]
    url = ""
    try:
        r = requests.get("https://%s/admin/api/2026-07/products/%s.json" % (shop, pid),
                         headers={"X-Shopify-Access-Token": token},
                         params={"fields": "id,image,images"}, timeout=15)
        if r.status_code == 200:
            p = (r.json() or {}).get("product") or {}
            url = ((p.get("image") or {}).get("src")
                   or ((p.get("images") or [{}])[0] or {}).get("src") or "")
    except Exception:
        pass
    _IMG_CACHE[pid] = url
    return url


@app.get("/pf-ventas")
def pf_ventas():
    """Órdenes reales de Shopify de los últimos `dias` días para la tabla 'Últimas ventas'.
    Liviano (sin el fetch pesado de MP): neto exacto se ve en el detalle de cada orden."""
    email = _user_actual()
    if not email:
        return jsonify({"ok": False, "ventas": []})
    try:
        dias = max(1, min(90, int(request.args.get("dias") or 7)))
    except Exception:
        dias = 7
    tk = _shop_tokens().get(email)
    if not tk or not tk.get("access_token"):
        return jsonify({"ok": True, "ventas": []})
    hasta = _hoy()
    desde = (_dt.date.today() - _dt.timedelta(days=dias - 1)).isoformat()
    try:
        orders = _shopify_orders(tk.get("shop"), tk.get("access_token"), desde, hasta)
    except Exception:
        return jsonify({"ok": True, "ventas": []})
    orders = [o for o in orders if not o.get("cancelled_at")]
    out = []
    for o in orders:
        tot = float(o.get("total_price") or o.get("current_total_price") or 0)
        num = str(o.get("order_number") or o.get("name") or "").replace("#", "").strip()
        out.append({"num": num, "origen": "Shopify",
                    "estado": _ESTADO_TXT.get((o.get("financial_status") or "").lower(), "—"),
                    "fecha": o.get("created_at") or "", "total": round(tot, 2),
                    "neto": round(tot * (1 - TIENDA_PCT / 100.0), 2)})
    out.sort(key=lambda x: int(x["num"]) if str(x["num"]).isdigit() else 0, reverse=True)
    return jsonify({"ok": True, "ventas": out[:300]})


@app.get("/pf-orden")
def pf_orden():
    """Detalle de UNA orden para el modal 'Últimas ventas': productos (con foto), cliente,
    medio de pago y desglose financiero real (MP + cuotas + tienda + costo producto + neto)."""
    email = _user_actual()
    if not email:
        return jsonify({"ok": False})
    num = (request.args.get("num") or "").strip().replace("#", "")
    tk = _shop_tokens().get(email)
    if not tk or not tk.get("access_token") or not num:
        return jsonify({"ok": False})
    shop, token = tk.get("shop"), tk.get("access_token")
    try:
        r = requests.get("https://%s/admin/api/2026-07/orders.json" % shop,
                         headers={"X-Shopify-Access-Token": token},
                         params={"name": "#" + num, "status": "any", "limit": 1,
                                 "fields": "id,order_number,name,created_at,financial_status,total_price,"
                                           "current_total_price,total_discounts,line_items,customer,"
                                           "contact_email,gateway,payment_gateway_names"}, timeout=25)
        orders = (r.json() or {}).get("orders") or []
        o = orders[0] if orders else None
    except Exception:
        o = None
    if not o:
        return jsonify({"ok": False, "msg": "no encontrada"})
    tot = float(o.get("total_price") or o.get("current_total_price") or 0)
    desc = float(o.get("total_discounts") or 0)
    costos = (_costos().get(email) or {})
    items, costo_prod = [], 0.0
    for li in (o.get("line_items") or []):
        q = int(li.get("quantity") or 0)
        pid = str(li.get("product_id") or "")
        cu = float(costos.get(pid) or 0)
        costo_prod += cu * q
        items.append({"nombre": li.get("title") or li.get("name") or "?", "cantidad": q,
                      "precio": float(li.get("price") or 0), "foto": _shop_img(shop, token, pid)})
    # MP: matcheo el pago de esta orden por fecha/monto para el desglose real.
    fecha = str(o.get("created_at") or "")[:10] or _hoy()
    d0 = fecha; d1 = (_dt.date.fromisoformat(fecha) + _dt.timedelta(days=4)).isoformat() if fecha else _hoy()
    pagos = _mp_pagos_lista(email, d0, d1) if fecha else None
    pago = None
    if pagos:
        for p in pagos:
            if p["ref"] in (str(o.get("id")), str(o.get("order_number")), num):
                pago = p; break
        if pago is None:
            for p in pagos:
                if p["amount"] == round(tot):
                    pago = p; break
    fee_mp = pago["fee_mp"] if pago else 0.0
    fee_cuotas = pago["fee_cuotas"] if pago else 0.0
    inst = pago["inst"] if pago else 1
    tienda = tot * TIENDA_PCT / 100.0
    neto = pago["net"] if pago else round(tot - fee_mp - fee_cuotas - tienda, 2)
    cust = o.get("customer") or {}
    medio = "Mercado Pago" if pago else (", ".join(o.get("payment_gateway_names") or []) or o.get("gateway") or "—")
    return jsonify({"ok": True, "orden": {
        "num": num, "origen": "Shopify", "estado": _ESTADO_TXT.get((o.get("financial_status") or "").lower(), "—"),
        "fecha": o.get("created_at") or "",
        "cliente": (cust.get("first_name", "") + " " + cust.get("last_name", "")).strip() or (o.get("contact_email") or ""),
        "email": o.get("contact_email") or cust.get("email") or "",
        "medio": medio, "items": items,
        "total": round(tot, 2), "descuento": round(desc, 2),
        "fee_mp": round(fee_mp, 2), "fee_cuotas": round(fee_cuotas, 2), "cuotas": inst,
        "fee_tienda": round(tienda, 2), "costo_prod": round(costo_prod, 2), "neto": round(neto, 2)}})


def _mp_pagos_lista(email, desde, hasta):
    """Lista de pagos aprobados de MP del usuario: {ref, amount, net, fee}. None si no hay MP.
    Sirve para MATCHEAR cada pago con su pedido de Shopify (comisión exacta por venta, sin inflar)."""
    tk = _mp_tokens().get(email)
    token = tk.get("access_token") if tk else None
    if not token:
        return None
    # Ventana de MP un poco más ancha que el período: un pago puede aprobarse hasta unos días
    # después de creado el pedido (transferencias, cuotas). Los que no matcheen se ignoran.
    try:
        h2 = (_dt.date.fromisoformat(hasta) + _dt.timedelta(days=4)).isoformat()
    except Exception:
        h2 = hasta
    ini = desde + "T00:00:00.000-03:00"
    fin = h2 + "T23:59:59.999-03:00"
    out = []
    offset = 0
    try:
        while True:
            r = requests.get("https://api.mercadopago.com/v1/payments/search",
                             headers={"Authorization": "Bearer " + token},
                             params={"sort": "date_approved", "criteria": "desc",
                                     "range": "date_approved", "begin_date": ini, "end_date": fin,
                                     "status": "approved", "offset": offset, "limit": 100}, timeout=30)
            if r.status_code >= 400:
                return None if offset == 0 else out
            data = r.json()
            res = data.get("results") or []
            for p in res:
                ta = float(p.get("transaction_amount") or 0)
                det = p.get("transaction_details") or {}
                net = float(det.get("net_received_amount") or 0)
                fee = (ta - net) if net else sum(float(f.get("amount") or 0)
                                                 for f in (p.get("fee_details") or []))
                # desglose para el modal: comisión MP (mercadopago+application) vs cuotas (financing)
                fd = p.get("fee_details") or []
                fin = sum(float(f.get("amount") or 0) for f in fd if f.get("type") == "financing_fee")
                base = sum(float(f.get("amount") or 0) for f in fd if f.get("type") != "financing_fee")
                if not fd:
                    base = fee; fin = 0.0
                out.append({"ref": (p.get("external_reference") or "").strip(),
                            "amount": round(ta), "net": round(net, 2), "fee": round(fee, 2),
                            "inst": int(p.get("installments") or 1),
                            "fee_mp": round(base, 2), "fee_cuotas": round(fin, 2),
                            "medio": (p.get("payment_method_id") or p.get("payment_type_id") or "")})
            offset += 100
            if offset >= (data.get("paging") or {}).get("total", 0) or not res:
                break
    except Exception:
        return None
    return out


def _shopify_resumen(email, desde, hasta):
    """Arma el 'raw' que espera el dashboard con los pedidos reales de Shopify + costos cargados."""
    tk = _shop_tokens().get(email)
    if not tk or not tk.get("access_token"):
        return None
    shop = tk.get("shop"); token = tk.get("access_token")
    try:
        orders = _shopify_orders(shop, token, desde, hasta)
    except Exception:
        return None
    costos = (_costos().get(email) or {})
    r = resumen_vacio()
    r["fecha"] = desde if desde == hasta else (desde + " a " + hasta)
    r["desde"] = desde; r["hasta"] = hasta
    r["actualizado"] = (_dt.datetime.utcnow() - _dt.timedelta(hours=3)).strftime("%H:%M:%S")
    emap = _envialo_costos(email)   # {nº pedido → costo REAL de envío} (vacío si no conectó Envialo)
    # MP: pagos reales del período para MATCHEAR cada pedido con su pago (comisión exacta).
    pagos = _mp_pagos_lista(email, desde, hasta)
    mp_conectado = pagos is not None
    by_ref, by_amt = {}, {}
    for p in (pagos or []):
        if p["ref"]:
            by_ref.setdefault(str(p["ref"]), []).append(p)
        by_amt.setdefault(p["amount"], []).append(p)
    mp_costo = 0.0
    mp_match = 0
    fact = cobr = costo_prod = reemb_monto = envio_monto = 0.0
    unidades = ordenes = reemb_cant = envio_real = 0
    prodmap = {}
    ords_list = []
    for o in orders:
        if o.get("cancelled_at"):
            continue
        ordenes += 1
        tot = float(o.get("total_price") or o.get("current_total_price") or 0)
        fact += tot
        # Envío: costo REAL de Envialo si el pedido ya está ahí; si no, promedio domicilio/sucursal.
        _num = str(o.get("order_number") or o.get("name") or "").replace("#", "").strip()
        _real = emap.get(_num)
        if _real is not None:
            envio_monto += _real; envio_real += 1
        else:
            envio_monto += _envio_costo(o)
        # MP: matcheo este pedido con su pago real (por referencia; fallback por monto exacto).
        pago = None
        if mp_conectado:
            for ref in (str(o.get("id")), str(o.get("order_number")), _num):
                lst = by_ref.get(ref)
                if lst:
                    pago = lst.pop(0); break
            if pago is None:
                lst = by_amt.get(round(tot))
                if lst:
                    pago = lst.pop(0)
            if pago is not None:
                mp_costo += pago["fee"]; mp_match += 1
        if (o.get("financial_status") or "") in ("paid", "partially_paid", "authorized"):
            cobr += tot
        for li in (o.get("line_items") or []):
            q = int(li.get("quantity") or 0)
            unidades += q
            pid = str(li.get("product_id") or "")
            c = costos.get(pid)
            if c:
                costo_prod += float(c) * q
            nm = li.get("title") or "?"
            prodmap[nm] = prodmap.get(nm, 0) + q
        for rf in (o.get("refunds") or []):
            reemb_cant += 1
            for tx in (rf.get("transactions") or []):
                reemb_monto += float(tx.get("amount") or 0)
        # Fila para la tabla "Últimas ventas" (neto = lo real que entró por MP si matcheó, sino el total).
        ords_list.append({"num": _num, "origen": "Shopify",
                          "estado": _ESTADO_TXT.get((o.get("financial_status") or "").lower(), "—"),
                          "fecha": o.get("created_at") or "",
                          "total": round(tot, 2),
                          "neto": round(pago["net"] if pago else tot, 2)})
    # Costos por venta. MercadoPago: comisión REAL matcheada pedido-por-pedido (mp_costo, ya
    # sumado en el loop). Así NO infla con pagos que no son de la tienda. Si no hay MP conectado,
    # cae al % manual. FIJOS: 1% tienda + 3,5% Ingresos Brutos. Envío: real (Envialo) o promedio.
    iibb_monto = fact * IIBB_PCT / 100.0
    tienda_monto = fact * TIENDA_PCT / 100.0
    if not mp_conectado:
        cu = _comis_user(email)
        mp_costo = fact * (cu["mp_comision"] + cu["mp_cuotas"]) * (1 + cu["iva"] / 100.0) / 100.0
    comision_monto = mp_costo + iibb_monto + tienda_monto
    r["mp_costo_real"] = round(mp_costo, 2)
    r["mp_match"] = mp_match            # pedidos que matchearon su pago de MP (comisión exacta)
    r["iibb_monto"] = round(iibb_monto, 2)
    r["tienda_monto"] = round(tienda_monto, 2)
    r["envio_monto"] = round(envio_monto, 2)
    r["envio_real"] = envio_real       # cuántos pedidos usaron el costo REAL de Envialo
    ganancia = fact - costo_prod - comision_monto - envio_monto
    # Break-even: contribución ANTES de ads (lo que queda para pagar publicidad).
    _pre_ads = fact - costo_prod - comision_monto - envio_monto
    r["be_roas"] = round(fact / _pre_ads, 2) if _pre_ads > 0 else 0.0
    r["breakeven_roas"] = r["be_roas"]
    r["be_cpa"] = round(_pre_ads / ordenes, 2) if ordenes else 0.0
    r["breakeven_cpa"] = r["be_cpa"]
    r["ordenes"] = ordenes
    r["ventas_periodo"] = ordenes
    r["unidades"] = unidades
    r["facturado"] = round(fact, 2)
    r["cobrado"] = round(cobr, 2)
    r["costo_prod"] = round(costo_prod, 2)
    r["comision"] = round(comision_monto, 2)
    r["ganancia"] = round(ganancia, 2)
    r["margen"] = round(ganancia / fact * 100, 2) if fact else 0.0
    r["ticket"] = round(fact / ordenes, 2) if ordenes else 0.0
    r["gan_por_venta"] = round(ganancia / ordenes, 2) if ordenes else 0.0
    r["reemb_cantidad"] = reemb_cant
    r["reemb_monto"] = round(reemb_monto, 2)
    # Totales (por ahora solo Shopify, sin MELI)
    r["tot_ordenes"] = ordenes
    r["tot_facturado"] = round(fact, 2)
    r["tot_ganancia"] = round(ganancia, 2)
    r["tot_costo"] = round(costo_prod, 2)
    r["tot_margen"] = round(ganancia / fact * 100, 2) if fact else 0.0
    r["tot_aov"] = round(fact / ordenes, 2) if ordenes else 0.0
    r["tot_gan_por_venta"] = round(ganancia / ordenes, 2) if ordenes else 0.0
    prod = [{"nombre": k, "unidades": v, "facturado": 0.0}
            for k, v in sorted(prodmap.items(), key=lambda x: -x[1])[:10]]
    ords_list.sort(key=lambda x: int(x["num"]) if str(x["num"]).isdigit() else 0, reverse=True)
    return {"raw": r, "prod": prod, "ords": ords_list}


_ORDS_CACHE = {}
_ESTADO_TXT = {"paid": "Pagado", "partially_paid": "Parcial", "pending": "Pendiente",
               "authorized": "Autorizado", "partially_refunded": "Reemb. parcial",
               "refunded": "Reembolsado", "voided": "Anulado"}


def _shopify_ordenes(email, dias=90):
    """Últimas órdenes REALES de Shopify (últimos `dias` días) para la tabla 'Últimas ventas'.
    Cada una: {num, origen, estado, fecha, total, neto}. neto = lo real que entró por MP (matcheado)
    o el total si no matcheó/no es MP. Cache 2 min por usuario."""
    import time as _t
    tk = _shop_tokens().get(email)
    if not tk or not tk.get("access_token"):
        return []
    c = _ORDS_CACHE.get(email)
    if c and (_t.time() - c[0] < 120):
        return c[1]
    hasta = _hoy()
    desde = (_dt.date.today() - _dt.timedelta(days=dias)).isoformat()
    try:
        orders = _shopify_orders(tk.get("shop"), tk.get("access_token"), desde, hasta)
    except Exception:
        return []
    orders = [o for o in orders if not o.get("cancelled_at")]
    pagos = _mp_pagos_lista(email, desde, hasta)   # para el neto real por pedido
    by_ref, by_amt = {}, {}
    for p in (pagos or []):
        if p["ref"]:
            by_ref.setdefault(str(p["ref"]), []).append(p)
        by_amt.setdefault(p["amount"], []).append(p)
    out = []
    for o in orders:
        tot = float(o.get("total_price") or o.get("current_total_price") or 0)
        num = str(o.get("order_number") or o.get("name") or "").replace("#", "").strip()
        pago = None
        if pagos is not None:
            for ref in (str(o.get("id")), str(o.get("order_number")), num):
                lst = by_ref.get(ref)
                if lst:
                    pago = lst.pop(0); break
            if pago is None:
                lst = by_amt.get(round(tot))
                if lst:
                    pago = lst.pop(0)
        neto = pago["net"] if pago else tot
        fs = (o.get("financial_status") or "").lower()
        out.append({"num": num, "origen": "Shopify",
                    "estado": _ESTADO_TXT.get(fs, (fs or "—").title()),
                    "fecha": o.get("created_at") or "",
                    "total": round(tot, 2), "neto": round(neto, 2)})
    out.sort(key=lambda x: int(x["num"]) if str(x["num"]).isdigit() else 0, reverse=True)
    out = out[:200]
    _ORDS_CACHE[email] = (_t.time(), out)
    return out


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


@app.get("/conectar-meta")
@limiter.limit("30 per hour")
def conectar_meta():
    """Manda al usuario a autorizar Meta (Facebook Login) para leer sus Ads."""
    if not _user_actual():
        return redirect("/")
    cfg = _meta_cfg()
    if not cfg["app_id"]:
        return ("Falta configurar el App ID de Meta (variables en Render).", 400)
    state = _secrets.token_urlsafe(16)
    session["meta_state"] = state
    qs = _url.urlencode({"client_id": cfg["app_id"], "redirect_uri": cfg["redirect_uri"],
                         "state": state, "response_type": "code",
                         "scope": "ads_read,ads_management,read_insights,business_management,pages_show_list,pages_read_engagement,pages_manage_ads,pages_manage_metadata,instagram_basic,instagram_manage_insights"})
    return redirect("https://www.facebook.com/%s/dialog/oauth?%s" % (META_API, qs), code=302)


@app.get("/meta/callback")
@limiter.limit("30 per hour")
def meta_callback():
    """Meta vuelve con 'code'. Lo cambiamos por token y lo hacemos de larga duración (60 días)."""
    cfg = _meta_cfg()
    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return ("RealProfit — punto de conexión con Meta. Volvé a la app y usá «Conectar».", 200)
    if not state or state != session.get("meta_state"):
        return ("La conexión no pasó el control de seguridad. Reintentá desde el botón.", 400)
    try:
        r = requests.get("https://graph.facebook.com/%s/oauth/access_token" % META_API,
                         params={"client_id": cfg["app_id"], "redirect_uri": cfg["redirect_uri"],
                                 "client_secret": cfg["app_secret"], "code": code}, timeout=30)
        tok = r.json() if r.content else {}
    except Exception:
        return ("No pudimos conectar con Meta en este momento. Probá de nuevo.", 502)
    if not tok.get("access_token"):
        return ("Meta no autorizó la conexión. Reintentá.", 400)
    # Token de larga duración (60 días) para no reconectar seguido.
    try:
        r2 = requests.get("https://graph.facebook.com/%s/oauth/access_token" % META_API,
                          params={"grant_type": "fb_exchange_token", "client_id": cfg["app_id"],
                                  "client_secret": cfg["app_secret"], "fb_exchange_token": tok["access_token"]},
                          timeout=30)
        j2 = r2.json() if r2.content else {}
        if j2.get("access_token"):
            tok = j2
    except Exception:
        pass
    email = _user_actual()
    if not email:
        return redirect("/")
    _meta_save_token(email, tok)
    session.pop("meta_state", None)
    return redirect("/?integ=1", code=302)


@app.get("/meta/estado")
def meta_estado():
    email = _user_actual()
    tk = _meta_tokens().get(email) if email else None
    conectado = bool(tk and tk.get("access_token"))
    return jsonify({"ok": True, "conectado": conectado, "cuenta": (tk or {}).get("cuenta")})


@app.get("/meta/cuentas")
def meta_cuentas():
    """Lista las cuentas publicitarias a las que el usuario dio acceso al conectar."""
    email = _user_actual()
    tk = _meta_tokens().get(email) if email else None
    if not tk or not tk.get("access_token"):
        return jsonify({"ok": True, "cuentas": [], "elegida": None})
    cuentas = []
    try:
        r = requests.get("https://graph.facebook.com/%s/me/adaccounts" % META_API,
                         params={"access_token": tk["access_token"],
                                 "fields": "account_id,name,currency", "limit": 500}, timeout=30)
        for a in (r.json().get("data") or []):
            cuentas.append({"id": a.get("account_id"), "name": a.get("name") or ("Cuenta " + str(a.get("account_id"))),
                            "moneda": a.get("currency")})
    except Exception:
        pass
    return jsonify({"ok": True, "cuentas": cuentas, "elegida": tk.get("cuenta")})


@app.post("/meta/cuenta")
def meta_elegir_cuenta():
    """Guarda cuál cuenta publicitaria mira este usuario (de ahí sale el gasto)."""
    email = _user_actual()
    if not email:
        return jsonify({"ok": False, "error": "login"}), 401
    data = request.get_json(silent=True) or {}
    cid = str(data.get("cuenta") or "").strip()
    d = _meta_tokens(); tk = d.get(email) or {}
    tk["cuenta"] = cid
    d[email] = tk
    META_TOKENS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    return jsonify({"ok": True})


def _meta_spend(email, desde, hasta):
    """Gasto en ads (USD/ARS) de la cuenta elegida, en el período. 0 si no hay cuenta/conexión.

    ATAJO DUEÑO: si el email logueado es el dueño (env META_OWNER_EMAIL), usa directo el
    System User token de METAFY (env META_OWNER_TOKEN) + su cuenta (env META_OWNER_ACT),
    sin OAuth ni App Review. Solo para tu propio usuario."""
    import os
    tk = _meta_tokens().get(email)
    token = tk.get("access_token") if tk else None
    cuenta = tk.get("cuenta") if tk else None
    es_owner = False
    owner = os.getenv("META_OWNER_EMAIL", "").strip().lower()
    if owner and email and email.strip().lower() == owner and os.getenv("META_OWNER_TOKEN"):
        token = os.getenv("META_OWNER_TOKEN")
        cuenta = os.getenv("META_OWNER_ACT") or cuenta
        es_owner = True
    if not token or not cuenta:
        return 0.0
    acc = str(cuenta).replace("act_", "")
    try:
        r = requests.get("https://graph.facebook.com/%s/act_%s/insights" % (META_API, acc),
                         params={"access_token": token, "fields": "spend,account_currency",
                                 "time_range": _json.dumps({"since": desde, "until": hasta}),
                                 "level": "account"}, timeout=30)
        data = r.json().get("data") or []
        if data:
            spend = float(data[0].get("spend") or 0)
            moneda = (data[0].get("account_currency") or "").upper()
            # Si la cuenta factura en USD y la tienda es en pesos, convierto con el dólar en vivo
            # (mismo criterio que METAFY: USDC/ARS de criptoya). Para tu usuario (owner) o cualquier
            # cuenta USD. Se puede fijar con la env DOLAR_ARS (número, 'blue' o 'cripto').
            if moneda == "USD" or es_owner:
                spend *= _dolar_ars_vivo()
            return spend
    except Exception:
        pass
    return 0.0


_dolar_cache = {"ts": 0, "val": 0.0}


def _dolar_ars_vivo() -> float:
    """USD→ARS en vivo (USDC/ARS de criptoya, ask de Ripio ≈ lo que se paga en ads), cache 10 min.
    Config con env DOLAR_ARS: número fijo (ej 1500), 'blue', o 'cripto'/'arq' (default)."""
    import os, time as _t
    c = _dolar_cache
    if c["val"] and (_t.time() - c["ts"] < 600):
        return c["val"]
    cfg = (os.getenv("DOLAR_ARS") or "cripto").strip().lower()
    try:
        return float(cfg)                    # valor fijo si pusieron un número
    except ValueError:
        pass
    val = 0.0
    try:
        if cfg == "blue":
            val = float(requests.get("https://dolarapi.com/v1/dolares/blue", timeout=10).json().get("venta") or 0)
        else:
            j = requests.get("https://criptoya.com/api/usdc/ars/1", timeout=10).json()
            val = float((j.get("ripioexchange") or {}).get("ask") or 0)
            if not val:
                asks = [float(v.get("ask") or 0) for v in j.values() if isinstance(v, dict) and v.get("ask")]
                val = sum(asks) / len(asks) if asks else 0.0
        if not val:
            val = float(requests.get("https://dolarapi.com/v1/dolares/cripto", timeout=10).json().get("venta") or 0)
    except Exception:
        val = 0.0
    if not val or val < 500:                 # API caída → último bueno o piso sano (nunca 1)
        return c["val"] or 1000.0
    c.update({"ts": _t.time(), "val": val})
    return val


@app.get("/desconectar-meta")
def desconectar_meta():
    email = _user_actual()
    if email:
        d = _meta_tokens()
        d.pop(email, None)
        META_TOKENS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    return redirect("/?integ=1")


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
    userbox = ('<a class="rp-pill" href="/logout" title="Cerrar sesión" style="bottom:16px">'
               '<span class="rp-ic" style="background:#137fec;color:#fff;font-weight:700;font-size:14px">'
               + inicial + '</span>'
               '<span class="rp-lbl"><span class="em">' + email + '</span>'
               '<span style="color:#94a3b8;font-size:11px">Cerrar sesión &#8594;</span></span></a>')
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
_PF_CACHE = {}   # (email, desde, hasta) -> (momento, blob) — evita pegarle a Shopify en cada refresco


@app.get("/pf-periodo")
def pf_periodo():
    email = _user_actual()
    desde = request.args.get("desde") or _hoy()
    hasta = request.args.get("hasta") or desde
    if email:
        key = (email, desde, hasta)
        now = _dt.datetime.utcnow()
        c = _PF_CACHE.get(key)
        if c and (now - c[0]).total_seconds() < 60:
            return jsonify({"ok": True, **c[1]})
        blob = None
        if email in _shop_tokens():
            blob = _shopify_resumen(email, desde, hasta)
        if blob is None:
            blob = _blob_vacio()
        # Gasto en ads de Meta (cuenta elegida) → INVERSIÓN ADS / ROAS / CPA / ganancia.
        spend = _meta_spend(email, desde, hasta)
        if spend:
            r = blob["raw"]
            fact = r.get("facturado", 0.0)
            ordenes = r.get("ordenes", 0)
            r["publi_ars"] = round(spend, 2)
            r["publi_cuenta"] = round(spend, 2)
            r["ganancia"] = round(r.get("ganancia", fact) - spend, 2)
            r["margen"] = round(r["ganancia"] / fact * 100, 2) if fact else 0.0
            r["roas"] = round(fact / spend, 2) if spend else 0.0
            r["cpa"] = round(spend / ordenes, 2) if ordenes else 0.0
            r["gan_por_venta"] = round(r["ganancia"] / ordenes, 2) if ordenes else 0.0
            r["tot_ganancia"] = r["ganancia"]
            r["tot_margen"] = r["margen"]
        _PF_CACHE[key] = (now, blob)
        return jsonify({"ok": True, **blob})
    return jsonify({"ok": True, **_blob_vacio()})


PROD_COSTOS = DATA_DIR / "prod_costos.json"   # costos por producto que carga cada usuario (persistente)


def _costos() -> dict:
    try:
        return _json.loads(PROD_COSTOS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _guardar_costo(email, pid, costo) -> None:
    d = _costos()
    u = d.get(email) or {}
    if costo and float(costo) > 0:
        u[str(pid)] = float(costo)
    else:
        u.pop(str(pid), None)
    d[email] = u
    PROD_COSTOS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


@app.get("/pf-productos")
def pf_productos():
    """Productos de la tienda conectada (por ahora Shopify). Sin tienda → lista vacía."""
    email = _user_actual()
    if not email:
        return jsonify({"ok": True, "tienda": None, "productos": [], "sin_costo": 0})
    tk = _shop_tokens().get(email)
    if not tk or not tk.get("access_token"):
        return jsonify({"ok": True, "tienda": None, "productos": [], "sin_costo": 0})
    shop = tk.get("shop"); token = tk.get("access_token")
    costos = (_costos().get(email) or {})
    productos = []
    try:
        r = requests.get("https://%s/admin/api/2026-07/products.json" % shop,
                         headers={"X-Shopify-Access-Token": token},
                         params={"limit": 250, "fields": "id,title,image,variants,status"}, timeout=30)
        if r.status_code == 200:
            for p in r.json().get("products", []):
                v = (p.get("variants") or [{}])[0]
                pid = p.get("id")
                productos.append({
                    "id": pid,
                    "nombre": p.get("title") or "",
                    "sku": v.get("sku") or "",
                    "precio": float(v.get("price") or 0),
                    "img": (p.get("image") or {}).get("src") or "",
                    "costo": costos.get(str(pid)) or 0,
                })
    except Exception:
        pass
    sin = sum(1 for x in productos if not x.get("costo"))
    return jsonify({"ok": True, "tienda": "Shopify", "shop": shop, "productos": productos, "sin_costo": sin})


@app.post("/pf-guardar-costo")
def pf_guardar_costo():
    """Guarda el costo de UN producto para este usuario."""
    email = _user_actual()
    if not email:
        return jsonify({"ok": False, "error": "login"}), 401
    data = request.get_json(silent=True) or {}
    pid = str(data.get("id") or "")
    if not pid:
        return jsonify({"ok": False, "error": "falta id"}), 400
    try:
        costo = float(data.get("costo") or 0)
    except Exception:
        costo = 0
    _guardar_costo(email, pid, costo)
    return jsonify({"ok": True})


# ---------------- Comisiones (MP + tienda + IVA + IIBB) ----------------
COMIS = DATA_DIR / "comisiones.json"   # config de comisiones por usuario (persistente)
_COMIS_CAMPOS = ["mp_comision", "mp_cuotas", "comision_tienda", "iva", "ingresos_brutos"]


def _comis() -> dict:
    try:
        return _json.loads(COMIS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _comis_user(email) -> dict:
    u = (_comis().get(email) or {})
    return {k: float(u.get(k) or 0) for k in _COMIS_CAMPOS}


def _comis_pct(email) -> float:
    """% total que se lleva cada venta: (MP + cuotas + tienda) con IVA + Ingresos Brutos (sin IVA)."""
    c = _comis_user(email)
    con_iva = (c["mp_comision"] + c["mp_cuotas"] + c["comision_tienda"]) * (1 + c["iva"] / 100.0)
    return round(con_iva + c["ingresos_brutos"], 4)


@app.get("/pf-comisiones")
def pf_comisiones():
    email = _user_actual()
    if not email:
        return jsonify({"ok": True, "comis": {k: 0 for k in _COMIS_CAMPOS}, "pct": 0})
    return jsonify({"ok": True, "comis": _comis_user(email), "pct": _comis_pct(email)})


@app.post("/pf-comisiones")
def pf_guardar_comisiones():
    email = _user_actual()
    if not email:
        return jsonify({"ok": False, "error": "login"}), 401
    data = request.get_json(silent=True) or {}
    d = _comis()
    u = {}
    for k in _COMIS_CAMPOS:
        try:
            u[k] = float(data.get(k) or 0)
        except Exception:
            u[k] = 0.0
    d[email] = u
    COMIS.write_text(_json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    return jsonify({"ok": True, "pct": _comis_pct(email)})


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


@app.post("/shopify/byoa-start")
@limiter.limit("30 per hour")
def shopify_byoa_start():
    """OAuth con la app PROPIA de cada tienda (estilo Envialo): recibe shop + Client ID + Client Secret."""
    if not _user_actual():
        return jsonify({"ok": False, "error": "Tenés que iniciar sesión."}), 401
    data = request.get_json(silent=True) or request.form
    shop = _shop_normalizar(data.get("shop", ""))
    cid = (data.get("client_id", "") or "").strip()
    secret = (data.get("client_secret", "") or "").strip()
    if not _shop_valido(shop):
        return jsonify({"ok": False, "error": "Dominio inválido. Usá el formato tutienda.myshopify.com"}), 400
    if not cid or not secret:
        return jsonify({"ok": False, "error": "Faltan el Client ID o el Client Secret."}), 400
    cfg = _shop_cfg()
    state = _secrets.token_urlsafe(16)
    session["shop_state"] = state
    session["shop_dom"] = shop
    session["shop_cid"] = cid
    session["shop_secret"] = secret
    qs = _url.urlencode({"client_id": cid, "scope": cfg["scopes"],
                         "redirect_uri": cfg["redirect_uri"], "state": state})
    return jsonify({"ok": True, "url": "https://" + shop + "/admin/oauth/authorize?" + qs})


@app.get("/conectar-shopify")
@limiter.limit("30 per hour")
def conectar_shopify():
    """Manda al usuario a autorizar SU tienda Shopify (OAuth con la app global de env)."""
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
    # Si vino por «tu propia app» (BYOA), usamos las claves que pegó el usuario; si no, las de env.
    cid = session.get("shop_cid") or cfg["client_id"]
    secret = session.get("shop_secret") or cfg["client_secret"]
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
    calc = _hmac.new(secret.encode(), mensaje.encode(), _hashlib.sha256).hexdigest()
    if not hmac_recibido or not _hmac.compare_digest(calc, hmac_recibido):
        return ("La firma de Shopify no es válida. Reintentá.", 400)
    try:
        r = requests.post("https://" + shop + "/admin/oauth/access_token", json={
            "client_id": cid, "client_secret": secret,
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
    for k in ("shop_state", "shop_dom", "shop_cid", "shop_secret"):
        session.pop(k, None)
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
