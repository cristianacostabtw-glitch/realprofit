/* ============================================================================
   RealProfit · tema "glass"  (rp_glass.js)
   ----------------------------------------------------------------------------
   Qué hace (y nada más):
     1. Interruptor: ?tema=clasico / ?tema=glass (se guarda en localStorage
        'rpTema'). Con 'clasico' NO hace nada: no pone la clase, no crea nodos.
     2. Pone html.rp-glass (todo el CSS cuelga de esa clase).
     3. Crea UNA sola vez el fondo de manchas (#rpg-bg, hijo de body).
     4. Mueve la marca azul de la barra lateral cambiando 4 variables CSS y una
        clase en el <nav> (cambios de ATRIBUTO: ningún MutationObserver de la
        app mira atributos, así que no los despierta). Se actualiza:
          - envolviendo window._rpNavActive (lo llaman todas las secciones),
          - con un listener de click (respaldo) y con resize.
   Qué NO hace: no toca textContent, valores, ids, handlers ni el orden de
   nada; no usa MutationObserver; no cuenta números; no anima por JS.
   Todo en un IIFE, todo en try/catch, nombres con prefijo rpGlass_.
   ========================================================================== */
(function () {
  'use strict';
  var W = window, D = document, H = D.documentElement;

  try {
    if (W.rpGlass_cargado) return;           // idempotente (preview + deploy a la vez)
    W.rpGlass_cargado = true;
  } catch (e) { return; }

  /* --------------------------------------------------------------- tema -- */
  function rpGlass_leerLS() {
    try { return W.localStorage.getItem('rpTema'); } catch (e) { return null; }
  }
  function rpGlass_guardarLS(v) {
    try { W.localStorage.setItem('rpTema', v); } catch (e) {}
  }
  function rpGlass_temaPedido() {
    var t = null;
    try {
      var m = /[?&]tema=(clasico|glass)(?:&|#|$)/i.exec(W.location.search || '');
      if (m) { t = m[1].toLowerCase(); rpGlass_guardarLS(t); }
    } catch (e) {}
    if (!t) t = rpGlass_leerLS();
    return t === 'clasico' ? 'clasico' : 'glass';
  }

  /* ---------------------------------------------------- ¿dónde estamos? -- */
  function rpGlass_enIframe() {
    try { return W.top !== W.self; } catch (e) { return true; }
  }
  function rpGlass_aside() {
    try { return D.querySelector('aside[class*="group/sidebar"]'); } catch (e) { return null; }
  }
  function rpGlass_nav() {
    try { var a = rpGlass_aside(); return a ? a.querySelector('nav') : null; } catch (e) { return null; }
  }
  function rpGlass_esDashboard() {
    try { return !!(D.getElementById('root') && (rpGlass_aside() || D.querySelector('[data-view="dashboard"]'))); }
    catch (e) { return false; }
  }

  /* ------------------------------------------------ fondo con manchas -- */
  function rpGlass_fondo() {
    try {
      if (D.getElementById('rpg-bg') || !D.body) return;
      var bg = D.createElement('div');
      bg.id = 'rpg-bg';
      bg.setAttribute('aria-hidden', 'true');
      bg.appendChild(D.createElement('i'));
      bg.appendChild(D.createElement('i'));
      bg.appendChild(D.createElement('i'));
      D.body.insertBefore(bg, D.body.firstChild);   // una sola inserción, nunca se recrea
    } catch (e) {}
  }

  /* ------------------------------------------- marca activa de la barra -- */
  var rpGlass_mq = null;
  try { rpGlass_mq = W.matchMedia ? W.matchMedia('(min-width: 821px)') : null; } catch (e) {}

  function rpGlass_visible(el) {
    try { return !!(el && el.offsetParent !== null && el.getClientRects().length); } catch (e) { return false; }
  }
  function rpGlass_abierto(id) {
    try { var o = D.getElementById(id); return !!(o && o.style.display && o.style.display !== 'none'); }
    catch (e) { return false; }
  }
  function rpGlass_linkActivo(nav) {
    try {
      // Integraciones no es un ítem del nav: con su sección abierta, la marca se esconde.
      var ib = D.getElementById('rp-integ-btn');
      if (ib && ib.classList.contains('rp-active') && rpGlass_abierto('rp-integ-ov')) return null;
      // _rpNavActive no incluye 'rp-meli-nav' (bug viejo de la app): lo resuelvo solo para la marca.
      if (rpGlass_abierto('rp-meli-ov')) {
        var ml = D.querySelector('#rp-meli-nav a');
        if (rpGlass_visible(ml)) return ml;
      }
      var as = nav.querySelectorAll('a.text-primary');
      for (var i = 0; i < as.length; i++) { if (rpGlass_visible(as[i])) return as[i]; }
      var ac = nav.querySelector('a[aria-current="page"]');
      if (rpGlass_visible(ac) && !rpGlass_algunaSeccion()) return ac;
    } catch (e) {}
    return null;
  }
  function rpGlass_algunaSeccion() {
    var ids = ['rp-prod-ov', 'rp-comis-ov', 'rp-desp-ov', 'rp-fact-ov', 'rp-mov-ov', 'rp-stock-ov',
               'rp-ads-ov', 'rp-wa-ov', 'rp-meli-ov', 'rp-integ-ov'];
    for (var i = 0; i < ids.length; i++) { if (rpGlass_abierto(ids[i])) return true; }
    return false;
  }
  function rpGlass_setVar(el, k, v) {
    try { if (el.style.getPropertyValue(k) !== v) el.style.setProperty(k, v); } catch (e) {}
  }
  function rpGlass_clase(el, c, on) {
    try { if (el.classList.contains(c) !== !!on) el.classList.toggle(c, !!on); } catch (e) {}
  }

  function rpGlass_marca() {
    try {
      var nav = rpGlass_nav();
      if (!nav) return;
      if (!H.classList.contains('rp-glass') || !(rpGlass_mq && rpGlass_mq.matches)) {
        rpGlass_clase(nav, 'rpg-ind-on', false);
        return;
      }
      var a = rpGlass_linkActivo(nav);
      if (!a) {
        if (nav.classList.contains('rpg-ind-on')) rpGlass_clase(nav, 'rpg-ind-hide', true);
        return;
      }
      var nr = nav.getBoundingClientRect(), ar = a.getBoundingClientRect();
      if (!ar.width || !ar.height) return;
      rpGlass_setVar(nav, '--rpg-ind-x', Math.round(ar.left - nr.left + nav.scrollLeft) + 'px');
      rpGlass_setVar(nav, '--rpg-ind-y', Math.round(ar.top - nr.top + nav.scrollTop) + 'px');
      rpGlass_setVar(nav, '--rpg-ind-w', Math.round(ar.width) + 'px');
      rpGlass_setVar(nav, '--rpg-ind-h', Math.round(ar.height) + 'px');
      rpGlass_clase(nav, 'rpg-ind-hide', false);
      if (!nav.classList.contains('rpg-ind-on')) {
        rpGlass_clase(nav, 'rpg-ind-on', true);
        // la transición recién después del primer lugar => no "vuela" desde arriba al cargar
        rpGlass_raf(function () { rpGlass_raf(function () { rpGlass_clase(nav, 'rpg-ind-ready', true); }); });
      }
    } catch (e) {}
  }

  function rpGlass_raf(fn) {
    try { (W.requestAnimationFrame || function (f) { return setTimeout(f, 16); })(fn); }
    catch (e) { try { setTimeout(fn, 16); } catch (e2) {} }
  }
  var rpGlass_pend = false;
  function rpGlass_programar() {
    try {
      if (rpGlass_pend) return;
      rpGlass_pend = true;
      rpGlass_raf(function () { rpGlass_pend = false; rpGlass_marca(); });
      setTimeout(rpGlass_marca, 260);           // por si la sección abre un toque después
    } catch (e) {}
  }

  /* Envuelve window._rpNavActive: llama a la original igual que siempre (mismos
     argumentos, mismo this, mismo retorno; si tirara error, sale igual que antes)
     y después reubica la marca. Se hace una sola vez. */
  function rpGlass_envolver() {
    try {
      var o = W._rpNavActive;
      if (typeof o !== 'function') return false;
      if (o.rpGlass_envuelta) return true;
      var f = function () {
        var r = o.apply(this, arguments);
        rpGlass_programar();
        return r;
      };
      f.rpGlass_envuelta = true;
      f.rpGlass_original = o;
      W._rpNavActive = f;
      return true;
    } catch (e) { return false; }
  }

  var rpGlass_escuchando = false;
  function rpGlass_escuchar() {
    if (rpGlass_escuchando) return;
    rpGlass_escuchando = true;
    try { D.addEventListener('click', rpGlass_programar, { capture: true, passive: true }); }
    catch (e) { try { D.addEventListener('click', rpGlass_programar, true); } catch (e2) {} }
    try { W.addEventListener('resize', rpGlass_programar, { passive: true }); } catch (e) {}
    try {
      if (rpGlass_mq) {
        if (rpGlass_mq.addEventListener) rpGlass_mq.addEventListener('change', rpGlass_programar);
        else if (rpGlass_mq.addListener) rpGlass_mq.addListener(rpGlass_programar);
      }
    } catch (e) {}
    // strip() clona los ítems de la barra después de DOMContentLoaded: unos reintentos
    // con tiempo (no observer) alcanzan para ubicar la marca de entrada.
    [0, 300, 900, 2000, 3500, 6000].forEach(function (ms) {
      try { setTimeout(function () { rpGlass_envolver(); rpGlass_marca(); }, ms); } catch (e) {}
    });
  }

  /* ------------------------------------------ entrada del dashboard -- */
  /* La animación de entrada de los paneles del dashboard cuelga de html.rpg-dash-in, que se
     pone UNA vez (cuando metafy-datos-reales pone html.mfy-ready) y se saca a los 1,6 s.
     Sin esto, cada vez que React re-monta un panel u ocultarVacios()/kpiArriba() lo
     esconden/mueven, la animación (opacity 0 + blur) se repetiría = parpadeo.
     Sondeo con setTimeout (no observer), ~9 s como máximo. */
  var rpGlass_entradaHecha = false;
  function rpGlass_entrada() {
    try {
      if (rpGlass_entradaHecha) return;
      rpGlass_entradaHecha = true;
      var n = 0;
      var mirar = function () {
        try {
          if (!H.classList.contains('rp-glass')) return;
          if (H.classList.contains('mfy-ready')) {
            H.classList.add('rpg-dash-in');
            setTimeout(function () { try { H.classList.remove('rpg-dash-in'); } catch (e) {} }, 1600);
            return;
          }
          if (++n < 60) setTimeout(mirar, 150);
        } catch (e) {}
      };
      mirar();
    } catch (e) {}
  }

  /* ------------------------------------------------------- encendido -- */
  function rpGlass_encender() {
    try {
      H.classList.add('rp-glass');
      if (!rpGlass_esDashboard()) return;     // solo el dashboard (/) lleva barra, manchas y marca
      var listo = function () {
        try { rpGlass_fondo(); rpGlass_envolver(); rpGlass_escuchar(); rpGlass_programar(); rpGlass_entrada(); } catch (e) {}
      };
      if (D.body) listo();
      else D.addEventListener('DOMContentLoaded', listo);
    } catch (e) {}
  }
  function rpGlass_apagar() {
    try {
      H.classList.remove('rp-glass');
      H.classList.remove('rpg-dash-in');
      var nav = rpGlass_nav();
      if (nav) { rpGlass_clase(nav, 'rpg-ind-on', false); rpGlass_clase(nav, 'rpg-ind-ready', false); }
    } catch (e) {}
  }

  /* API mínima para la consola: rpGlass_tema('clasico') / rpGlass_tema('glass') */
  try {
    W.rpGlass_tema = function (t) {
      try {
        t = (t === 'clasico') ? 'clasico' : 'glass';
        rpGlass_guardarLS(t);
        if (t === 'clasico') rpGlass_apagar(); else { rpGlass_encender(); rpGlass_programar(); }
        return t;
      } catch (e) { return null; }
    };
  } catch (e) {}

  try {
    if (rpGlass_enIframe()) return;           // /wa y /meli dentro del dashboard: nada
    if (rpGlass_temaPedido() === 'clasico') return;
    rpGlass_encender();
  } catch (e) {}
})();
