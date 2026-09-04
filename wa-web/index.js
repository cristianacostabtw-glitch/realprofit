// RealProfit — Servicio WhatsApp Web (Baileys)
// Una sesión por CUENTA (email). Aislado: cada cuenta guarda su auth en su carpeta y solo ve SUS chats.
// Endpoints (todos requieren header  x-wa-secret: <WA_WEB_SECRET>):
//   POST /connect   {acc}              -> arranca/retoma la sesión; devuelve {status, qr?}
//   GET  /status?acc=..                -> {status: 'qr'|'connected'|'connecting'|'logged_out', me?}
//   GET  /qr?acc=..                    -> {qr} (data URL PNG) mientras esté esperando escaneo
//   GET  /chats?acc=..&limit=..        -> [{id, name, photo, last, ts, unread}]
//   GET  /messages?acc=..&chat=..      -> {messages:[{id, fromMe, text, ts, kind}]}  (conversación 1:1)
//   POST /send      {acc,to,text}      -> envía un mensaje (lo usa el bot y el chat manual)
//   POST /logout    {acc}              -> cierra sesión y borra credenciales
//
// Si WA_WEB_HOOK está seteado, cada mensaje ENTRANTE nuevo (1:1) se POSTea ahí
// ({acc, from, tel, name, text, ts}) para que RealProfit decida si el bot responde.
//
// La sesión se persiste en DATA_DIR/<acc-sanitizado>/  (en Render montar un disco ahí).

import express from "express";
import pino from "pino";
import QRCode from "qrcode";
import fs from "fs";
import path from "path";
import {
  makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason,
  downloadMediaMessage,
} from "@whiskeysockets/baileys";

const PORT = process.env.PORT || 8090;
const SECRET = process.env.WA_WEB_SECRET || "";
const DATA_DIR = process.env.WA_DATA_DIR || "/var/data/wa-web";
const HOOK = process.env.WA_WEB_HOOK || "";   // URL de RealProfit que decide si responde el bot
const MAX_MSGS = 300;                          // máx mensajes guardados por chat (memoria acotada)
const log = pino({ level: process.env.LOG_LEVEL || "warn" });

fs.mkdirSync(DATA_DIR, { recursive: true });

// --- estado en memoria por cuenta ---
const sessions = new Map(); // acc -> { sock, status, qr, me, chats:Map, msgs:Map, starting }

function accDir(acc) {
  const safe = String(acc).replace(/[^a-zA-Z0-9._@-]/g, "_");
  return path.join(DATA_DIR, safe);
}

function pub(s) {
  if (!s) return { status: "disconnected" };
  return { status: s.status, me: s.me || null, hasQr: !!s.qr };
}

// --- persistencia de chats + mensajes en el disco (sobreviven reinicios) ---
function storePath(acc) { return path.join(accDir(acc), "store.json"); }
function loadStore(acc, s) {
  try {
    const d = JSON.parse(fs.readFileSync(storePath(acc), "utf8"));
    if (Array.isArray(d.chats)) s.chats = new Map(d.chats);
    if (Array.isArray(d.msgs)) s.msgs = new Map(d.msgs);
  } catch {}
}
const _saveTimers = new Map();
function saveStoreDebounced(acc, s) {
  if (_saveTimers.has(acc)) return;
  _saveTimers.set(acc, setTimeout(() => {
    _saveTimers.delete(acc);
    try {
      const d = { chats: [...s.chats.entries()], msgs: [...(s.msgs || new Map()).entries()] };
      fs.writeFileSync(storePath(acc), JSON.stringify(d));
    } catch {}
  }, 4000));
}

// --- MEDIOS (fotos, video, audio, sticker/gif, documento) ---
function mediaDir(acc) { return path.join(accDir(acc), "media"); }
function mediaKind(m) {
  const mm = m.message || {};
  if (mm.imageMessage) return { kind: "image", ext: (mm.imageMessage.mimetype || "").includes("png") ? "png" : "jpg", mime: mm.imageMessage.mimetype || "image/jpeg", caption: mm.imageMessage.caption || "" };
  if (mm.stickerMessage) return { kind: "sticker", ext: "webp", mime: "image/webp", caption: "" };
  if (mm.videoMessage) return { kind: (mm.videoMessage.gifPlayback ? "gif" : "video"), ext: "mp4", mime: mm.videoMessage.mimetype || "video/mp4", caption: mm.videoMessage.caption || "" };
  if (mm.audioMessage) return { kind: "audio", ext: (mm.audioMessage.mimetype || "").includes("mpeg") ? "mp3" : "ogg", mime: mm.audioMessage.mimetype || "audio/ogg", caption: "" };
  if (mm.documentMessage) return { kind: "document", ext: "bin", mime: mm.documentMessage.mimetype || "application/octet-stream", caption: mm.documentMessage.fileName || "Documento" };
  return null;
}
// descarga el medio y lo guarda en disco; devuelve {mediaId, mime} o null
async function saveMedia(sock, m, acc) {
  const mk = mediaKind(m);
  if (!mk) return null;
  const id = (m.key?.id || String(Date.now())).replace(/[^a-zA-Z0-9._-]/g, "");
  const fname = id + "." + mk.ext;
  const dir = mediaDir(acc);
  const file = path.join(dir, fname);
  try {
    if (!fs.existsSync(file)) {
      fs.mkdirSync(dir, { recursive: true });
      const buff = await downloadMediaMessage(m, "buffer", {}, { logger: log, reuploadRequest: sock.updateMediaMessage });
      fs.writeFileSync(file, buff);
    }
    return { mediaId: fname, mime: mk.mime };
  } catch {
    return null;
  }
}

// Texto legible de un mensaje de Baileys (lo que se muestra en el chat)
// Los GRUPOS solo se procesan en las sesiones habilitadas. Las demás (atención al cliente)
// siguen siendo 1:1 como siempre, para no meterles ruido de grupos.
// Se configura con la env WA_GRUPOS_ACCS = lista de cuentas separadas por coma
// (ej "visionpure.contacto@gmail.com"). Sin la env, ninguna sesión lee grupos.
const _GRUPOS_ACCS = String(process.env.WA_GRUPOS_ACCS || "")
  .split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
// De todos los grupos, solo pasa UNO: el de gastos. Se elige por nombre (WA_GRUPO_NOMBRE,
// por defecto "NOXALAB") o por jid exacto (WA_GRUPO_JID). El resto de los grupos se ignora,
// así la pantalla queda con los chats de personas + ese único grupo.
const _GRUPO_JID = String(process.env.WA_GRUPO_JID || "").trim();
const _GRUPO_NOM = String(process.env.WA_GRUPO_NOMBRE || "NOXALAB").trim().toLowerCase();

function cuentaLeeGrupos(acc) {
  const a = String(acc || "").toLowerCase();
  return _GRUPOS_ACCS.includes(a) || a.includes("gastos");
}
// s.gruposNom = jid → nombre del grupo (se llena al conectar y con groups.upsert/update)
// CUENTA DE GASTOS: pasa SOLO el grupo permitido. Ni otros grupos ni chats de personas —
// ese número tiene contactos propios (proveedores, etc.) y no tienen que llegar al bot.
// CUENTA NORMAL (atención al cliente): solo 1:1, sin grupos, como siempre.
function grupoOK(s, acc, jid) {
  const esGrupo = String(jid || "").endsWith("@g.us");
  if (!cuentaLeeGrupos(acc)) return !esGrupo;
  if (!esGrupo) return false;
  if (_GRUPO_JID) return jid === _GRUPO_JID;
  const nom = String((s && s.gruposNom && s.gruposNom.get(jid)) || "").toLowerCase();
  return !!nom && nom.includes(_GRUPO_NOM);
}

function msgText(m) {
  const mm = m.message || {};
  return mm.conversation
    || mm.extendedTextMessage?.text
    || (mm.imageMessage ? (mm.imageMessage.caption || "📷 Foto") : "")
    || (mm.videoMessage ? (mm.videoMessage.caption || "🎥 Video") : "")
    || (mm.documentMessage ? ("📄 " + (mm.documentMessage.fileName || "Documento")) : "")
    || (mm.audioMessage ? "🎤 Audio" : "")
    || (mm.stickerMessage ? "🎟️ Sticker" : "")
    || "";
}
function placeholderTxt(k) {
  return k === "audio" ? "🎤 Audio" : k === "video" ? "🎥 Video" : k === "gif" ? "🎞️ GIF" : k === "document" ? "📄 Documento" : "📷 Foto";
}

async function startSession(acc) {
  let s = sessions.get(acc);
  if (s && (s.status === "connected" || s.starting)) return s;

  const dir = accDir(acc);
  fs.mkdirSync(dir, { recursive: true });
  const { state, saveCreds } = await useMultiFileAuthState(dir);
  const { version } = await fetchLatestBaileysVersion();

  s = s || { chats: new Map(), msgs: new Map() };
  if (!s.msgs) s.msgs = new Map();
  if (s.chats.size === 0) loadStore(acc, s);   // recuperar del disco lo guardado (sobrevive reinicios)
  s.status = "connecting";
  s.qr = null;
  s.starting = true;
  s.startedAt = Date.now();
  sessions.set(acc, s);

  const sock = makeWASocket({
    version,
    auth: state,
    logger: log,
    printQRInTerminal: false,
    syncFullHistory: false,   // historial reciente (con full a veces se cuelga por volumen)
    markOnlineOnConnect: false,
    keepAliveIntervalMs: 20000,   // ping cada 20s → detecta la caída rápido (default 30s)
    browser: ["RealProfit", "Chrome", "1.0"],
  });
  s.sock = sock;
  s.lastRecv = Date.now();

  sock.ev.on("creds.update", saveCreds);

  // Señal de VIDA: cualquier evento entrante refresca lastRecv (para cazar la conexión "zombie").
  const bump = () => { s.lastRecv = Date.now(); };
  for (const ev of ["messages.update", "message-receipt.update", "presence.update", "chats.update", "chats.upsert", "contacts.update"]) {
    try { sock.ev.on(ev, bump); } catch {}
  }

  sock.ev.on("connection.update", async (u) => {
    const { connection, lastDisconnect, qr } = u;
    if (qr) {
      s.status = "qr";
      try {
        s.qr = await QRCode.toDataURL(qr, { margin: 1, width: 320 });
      } catch {
        s.qr = null;
      }
    }
    if (connection === "open") {
      s.status = "connected";
      s.qr = null;
      s.starting = false;
      s.lastRecv = Date.now();
      s.me = sock.user ? { id: sock.user.id, name: sock.user.name || sock.user.verifiedName || "" } : null;
      // nombres de los grupos: hacen falta para saber CUÁL es el de gastos (los jid son números)
      s.gruposNom = s.gruposNom || new Map();
      sock.groupFetchAllParticipating()
        .then((gs) => { for (const g of Object.values(gs || {})) if (g?.id) s.gruposNom.set(g.id, g.subject || ""); })
        .catch(() => {});
    }
    if (connection === "close") {
      s.starting = false;
      const code = lastDisconnect?.error?.output?.statusCode;
      if (code === DisconnectReason.loggedOut) {
        s.status = "logged_out";
        try { fs.rmSync(accDir(acc), { recursive: true, force: true }); } catch {}
        sessions.delete(acc);
      } else {
        s.status = "connecting";
        setTimeout(() => startSession(acc).catch(() => {}), 2500); // reconecta solo
      }
    }
  });

  // acumular chats (nombre + último mensaje). Las fotos se piden on-demand en /chats.
  const touch = (jid, name, text, ts, unread, fromMe) => {
    if (!jid || jid === "status@broadcast" || !grupoOK(s, acc, jid)) return;
    const c = s.chats.get(jid) || { id: jid };
    if (name) c.name = name;
    if (text != null) c.last = text;
    if (ts) c.ts = Math.max(c.ts || 0, ts);
    if (unread != null) c.unread = unread;
    if (fromMe != null) c.lastFromMe = !!fromMe;
    s.chats.set(jid, c);
    saveStoreDebounced(acc, s);
  };

  // guardar un mensaje en la conversación del chat (para la vista de chat completa)
  const pushMsg = (jid, id, fromMe, text, ts, kind, media) => {
    if (!jid || jid === "status@broadcast" || !grupoOK(s, acc, jid)) return;
    if (!text && !media) return;
    let arr = s.msgs.get(jid);
    if (!arr) { arr = []; s.msgs.set(jid, arr); }
    const ex = id ? arr.find((x) => x.id === id) : null;
    if (ex) {   // ya existía (ej placeholder) → si ahora bajó el medio, se lo agrego
      if (media && !ex.media) { ex.media = media.mediaId; ex.mime = media.mime || ""; saveStoreDebounced(acc, s); }
      return;
    }
    const item = { id: id || "", fromMe: !!fromMe, text: String(text || ""), ts: ts || 0, kind: kind || "text", ack: 0 };
    if (media) { item.media = media.mediaId; item.mime = media.mime || ""; }
    arr.push(item);
    if (arr.length > MAX_MSGS) arr.splice(0, arr.length - MAX_MSGS);
    saveStoreDebounced(acc, s);
  };
  // guarda un mensaje: si es medio, pushea placeholder y baja el archivo en background
  const pushAny = (m) => {
    const jid = m.key?.remoteJid;
    if (!jid || jid === "status@broadcast" || !grupoOK(s, acc, jid)) return;
    const t = msgText(m);
    const id = m.key?.id, fromMe = m.key?.fromMe, ts = Number(m.messageTimestamp) || 0;
    touch(jid, fromMe ? undefined : m.pushName, t, ts, undefined, fromMe);
    const mk = mediaKind(m);
    if (mk) {
      pushMsg(jid, id, fromMe, t || placeholderTxt(mk.kind), ts, mk.kind, null);
      saveMedia(sock, m, acc).then((md) => { if (md) pushMsg(jid, id, fromMe, t || placeholderTxt(mk.kind), ts, mk.kind, md); }).catch(() => {});
    } else {
      pushMsg(jid, id, fromMe, t, ts, "text", null);
    }
  };

  // Estado (ack) de MIS mensajes: 2=enviado, 3=entregado, 4=leido. Actualiza el item guardado.
  sock.ev.on("messages.update", (updates) => {
    try {
      for (const u of (updates || [])) {
        const jid = u.key && u.key.remoteJid, id = u.key && u.key.id;
        const st = u.update && u.update.status;
        if (!jid || !id || st == null) continue;
        const arr = s.msgs.get(jid);
        if (!arr) continue;
        for (let i = arr.length - 1; i >= 0; i--) {
          if (arr[i].id === id) { if ((arr[i].ack || 0) < st) arr[i].ack = st; break; }
        }
      }
      saveStoreDebounced(acc, s);
    } catch (e) {}
  });

  sock.ev.on("groups.upsert", (gs) => {
    s.gruposNom = s.gruposNom || new Map();
    for (const g of (gs || [])) if (g?.id) s.gruposNom.set(g.id, g.subject || "");
  });
  sock.ev.on("groups.update", (gs) => {
    s.gruposNom = s.gruposNom || new Map();
    for (const g of (gs || [])) if (g?.id && g.subject != null) s.gruposNom.set(g.id, g.subject || "");
  });
  sock.ev.on("chats.upsert", (chats) => {
    for (const c of chats) touch(c.id, c.name, undefined, Number(c.conversationTimestamp) || 0, c.unreadCount);
  });
  sock.ev.on("chats.update", (chats) => {
    for (const c of chats) touch(c.id, c.name, undefined, Number(c.conversationTimestamp) || 0, c.unreadCount);
  });
  sock.ev.on("contacts.upsert", (cs) => {
    for (const c of cs) touch(c.id, c.notify || c.name, undefined, 0, undefined);
  });

  // HISTORIAL RECIENTE que WhatsApp sincroniza al vincular → lo guardamos para ver la conversación
  sock.ev.on("messaging-history.set", ({ messages }) => {
    if (!messages) return;
    for (const m of messages) {
      const jid = m.key?.remoteJid;
      if (!jid || jid === "status@broadcast" || !grupoOK(s, acc, jid)) continue;
      pushAny(m);   // texto o medio (baja fotos/audios/videos)
    }
  });

  sock.ev.on("messages.upsert", ({ messages, type }) => {
    s.lastRecv = Date.now();   // hay actividad → sesión viva (watchdog anti-cuelgue-silencioso)
    for (const m of messages) {
      const jid = m.key?.remoteJid;
      if (!jid || jid === "status@broadcast" || !grupoOK(s, acc, jid)) continue;
      pushAny(m);   // texto o medio (baja fotos/audios/videos en background)
      // aviso a RealProfit: mensaje ENTRANTE nuevo (no míos), para que el bot decida si responde
      const texto = m.message?.conversation || m.message?.extendedTextMessage?.text || "";
      const esGrupo = jid.endsWith("@g.us");
      const mk2 = mediaKind(m);
      // En 1:1 avisamos solo si hay TEXTO (como siempre). En el grupo de gastos también avisamos
      // cuando viene solo un audio, una foto o un PDF: ahí el contenido ES el archivo.
      // En el grupo de gastos también procesamos los mensajes PROPIOS: el dueño carga gastos
      // desde el mismo teléfono vinculado. Se excluyen solo los que mandó el bot.
      const mio = m.key?.fromMe && !(s.mios && s.mios.has(m.key?.id));
      // CANDADO ANTI-LOOP: al reconectar, WhatsApp reenvía historial. Si reprocesáramos esos
      // mensajes, el bot se contestaría a sí mismo una y otra vez. Solo procesamos lo que llegó
      // DESPUÉS de que arrancó esta sesión (con 60s de margen).
      const _ts = Number(m.messageTimestamp) || 0;
      const _fresco = _ts * 1000 > ((s.startedAt || 0) - 60000);
      const paso = _fresco && (esGrupo ? (!m.key?.fromMe || mio) : !m.key?.fromMe);
      if (HOOK && type === "notify" && paso && (texto || (esGrupo && mk2))) {
        notifyHook({
          acc,
          from: jid,
          tel: jid.split("@")[0],
          name: m.pushName || "",
          text: texto,
          ts: Number(m.messageTimestamp) || 0,
          grupo: esGrupo,
          autor: (m.key?.participant || "").split("@")[0],   // quién escribió dentro del grupo
          medio: mk2 ? mk2.kind : "",
          msg_id: m.key?.id || "",
        }).catch(() => {});
      }
    }
  });

  return s;
}

// avisar a RealProfit de un mensaje entrante (fire-and-forget, sin romper si falla)
async function notifyHook(payload) {
  if (!HOOK) return;
  try {
    await fetch(HOOK, {
      method: "POST",
      headers: { "content-type": "application/json", "x-wa-secret": SECRET },
      body: JSON.stringify(payload),
    });
  } catch {}
}

// ---------------- HTTP ----------------
const app = express();
app.use(express.json());

app.use((req, res, next) => {
  if (req.path === "/health") return next();
  if (!SECRET || req.get("x-wa-secret") !== SECRET) return res.status(403).json({ ok: false, msg: "forbidden" });
  next();
});

app.get("/health", (_req, res) => res.json({ ok: true, sessions: sessions.size }));

app.post("/connect", async (req, res) => {
  const acc = (req.body?.acc || "").trim();
  if (!acc) return res.status(400).json({ ok: false, msg: "falta acc" });
  try {
    const s = await startSession(acc);
    // esperar hasta ~6s a que aparezca el QR o conecte
    for (let i = 0; i < 24 && s.status === "connecting" && !s.qr; i++) {
      await new Promise((r) => setTimeout(r, 250));
    }
    res.json({ ok: true, ...pub(s), qr: s.qr || null });
  } catch (e) {
    res.status(500).json({ ok: false, msg: String(e).slice(0, 200) });
  }
});

app.get("/status", (req, res) => {
  const acc = (req.query.acc || "").trim();
  res.json({ ok: true, ...pub(sessions.get(acc)) });
});

app.get("/qr", (req, res) => {
  const acc = (req.query.acc || "").trim();
  const s = sessions.get(acc);
  res.json({ ok: true, status: s?.status || "disconnected", qr: s?.qr || null });
});

app.get("/chats", (req, res) => {
  const acc = (req.query.acc || "").trim();
  const limit = Math.min(parseInt(req.query.limit || "50", 10) || 50, 200);
  const s = sessions.get(acc);
  if (!s || s.status !== "connected") return res.json({ ok: false, status: s?.status || "disconnected", chats: [] });
  // DEDUP por número: WhatsApp puede tener el mismo contacto con jid "@lid" Y "@s.whatsapp.net".
  // Nos quedamos con UNA sola fila por número (la más reciente) para no mostrar chats duplicados.
  // Los grupos que NO son el permitido se ESCONDEN acá también: el filtro de arriba solo evita
  // que entren nuevos, pero los que ya estaban guardados en disco seguían apareciendo.
  // Además pido en background el nombre de los grupos que no conozco (los jid son números).
  s.gruposNom = s.gruposNom || new Map();
  s._gnPend = s._gnPend || new Set();
  for (const c of s.chats.values()) {
    const id = c && c.id;
    if (id && String(id).endsWith("@g.us") && !s.gruposNom.has(id) && !s._gnPend.has(id)) {
      s._gnPend.add(id);
      s.sock.groupMetadata(id)
        .then((md) => s.gruposNom.set(id, (md && md.subject) || ""))
        .catch(() => s.gruposNom.set(id, ""))
        .finally(() => s._gnPend.delete(id));
    }
  }
  const _seenTel = new Set();
  const arr = [...s.chats.values()]
    .filter((c) => grupoOK(s, acc, c.id))
    .sort((a, b) => (b.ts || 0) - (a.ts || 0))
    .filter((c) => { const t = (c.id || "").split("@")[0]; if (!t || _seenTel.has(t)) return false; _seenTel.add(t); return true; })
    .slice(0, limit);
  // La foto de perfil se busca en BACKGROUND (NO se espera) → /chats responde al toque, no cuelga a RealProfit.
  s.photos = s.photos || new Map();
  s._photoPend = s._photoPend || new Set();
  const out = arr.map((c) => {
    const photo = s.photos.get(c.id);
    if (photo === undefined && !s._photoPend.has(c.id)) {
      s._photoPend.add(c.id);
      s.sock.profilePictureUrl(c.id, "preview")
        .then((u) => s.photos.set(c.id, u || null))
        .catch(() => s.photos.set(c.id, null))
        .finally(() => s._photoPend.delete(c.id));
    }
    return {
      id: c.id,
      tel: (c.id || "").split("@")[0],
      name: c.name || (s.gruposNom && s.gruposNom.get(c.id)) || (c.id || "").split("@")[0],
      photo: photo === undefined ? null : photo,
      last: c.last || "",
      ts: c.ts || 0,
      unread: c.unread || 0,
      lastFromMe: !!c.lastFromMe,
    };
  });
  res.json({ ok: true, status: "connected", me: s.me || null, chats: out });
});

// Conversación completa de un chat 1:1 (lo guardado: historial reciente + en vivo)
app.get("/messages", (req, res) => {
  const acc = (req.query.acc || "").trim();
  const chat = (req.query.chat || "").trim();
  const s = sessions.get(acc);
  if (!s || s.status !== "connected") return res.json({ ok: false, status: s?.status || "disconnected", messages: [] });
  // Junto los mensajes de TODOS los jids del mismo número (@lid + @s.whatsapp.net) → conversación única.
  const _tel = (chat || "").split("@")[0];
  let _all = [], _name = "";
  for (const [jid, marr] of (s.msgs || new Map()).entries()) {
    if ((jid || "").split("@")[0] !== _tel) continue;
    _all = _all.concat(marr || []);
    const cc = s.chats.get(jid);
    if (cc) { cc.unread = 0; s.chats.set(jid, cc); if (!_name) _name = cc.name; }   // baja el badge de los dos
  }
  const _seenId = new Set();
  const arr = _all
    .filter((m) => { const k = m.id || (String(m.ts) + m.text); if (_seenId.has(k)) return false; _seenId.add(k); return true; })
    .sort((a, b) => (a.ts || 0) - (b.ts || 0));
  res.json({ ok: true, name: _name || _tel, messages: arr });
});

// Sirve un archivo de medio (foto/audio/video/sticker/documento) guardado en disco
app.get("/media", (req, res) => {
  const acc = (req.query.acc || "").trim();
  const id = (req.query.id || "").replace(/[^a-zA-Z0-9._-]/g, "");
  if (!acc || !id) return res.status(400).end();
  const file = path.join(mediaDir(acc), id);
  if (!fs.existsSync(file)) return res.status(404).end();
  res.sendFile(file, (err) => { if (err && !res.headersSent) res.status(404).end(); });
});

app.post("/send", async (req, res) => {
  const acc = (req.body?.acc || "").trim();
  let to = (req.body?.to || "").trim();
  const text = (req.body?.text || "").toString();
  if (!acc || !to || !text) return res.status(400).json({ ok: false, msg: "faltan acc/to/text" });
  const s = sessions.get(acc);
  if (!s || s.status !== "connected") return res.status(409).json({ ok: false, msg: "sesion no conectada" });
  if (!to.includes("@")) to = to.replace(/\D/g, "") + "@s.whatsapp.net"; // acepta solo el número
  // CANDADO: en la cuenta de gastos el bot SOLO puede escribir en el grupo permitido.
  // Ese número tiene otros chats (proveedores, personas) y no debe contestarles NUNCA.
  // Tiene que ser el grupo permitido Y ser grupo: a una persona no le escribe nunca.
  if (cuentaLeeGrupos(acc) && (!to.endsWith("@g.us") || !grupoOK(s, acc, to))) {
    return res.status(403).json({ ok: false, msg: "esta cuenta solo puede escribir en el grupo de gastos" });
  }
  try {
    const sent = await s.sock.sendMessage(to, { text });
    // Guardo el id de lo que YO mando: en el grupo procesamos también los mensajes propios
    // (el dueño escribe desde el mismo teléfono), así que hay que poder distinguirlos
    // de los del bot. Sin esto el bot se contestaría a sí mismo en loop.
    s.mios = s.mios || new Set();
    if (sent && sent.key && sent.key.id) {
      s.mios.add(sent.key.id);
      if (s.mios.size > 300) s.mios = new Set([...s.mios].slice(-150));
    }
    touch_send(s, to, text);
    // guardar el mensaje enviado en la conversación
    if (!s.msgs) s.msgs = new Map();
    let arr = s.msgs.get(to);
    if (!arr) { arr = []; s.msgs.set(to, arr); }
    arr.push({ id: sent?.key?.id || "", fromMe: true, text: String(text), ts: Math.floor(Date.now() / 1000), kind: "text" });
    if (arr.length > MAX_MSGS) arr.splice(0, arr.length - MAX_MSGS);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, msg: String(e).slice(0, 200) });
  }
});

function touch_send(s, jid, text) {
  const c = s.chats.get(jid) || { id: jid };
  c.last = text;
  c.ts = Math.floor(Date.now() / 1000);
  s.chats.set(jid, c);
}

app.post("/logout", async (req, res) => {
  const acc = (req.body?.acc || "").trim();
  const s = sessions.get(acc);
  try { await s?.sock?.logout(); } catch {}
  try { fs.rmSync(accDir(acc), { recursive: true, force: true }); } catch {}
  sessions.delete(acc);
  res.json({ ok: true });
});

// Auto-reconectar las sesiones guardadas en disco al arrancar
// (así un redeploy/reinicio NO deja el WhatsApp "desconectado" esperando un /connect manual).
function bootSessions() {
  try {
    const dirs = fs.readdirSync(DATA_DIR, { withFileTypes: true });
    for (const d of dirs) {
      if (!d.isDirectory()) continue;
      if (fs.existsSync(path.join(DATA_DIR, d.name, "creds.json"))) {
        startSession(d.name).catch(() => {});
      }
    }
  } catch {}
}

function wsDead(sock) {
  try {
    const w = sock && sock.ws;
    if (!w) return true;
    if (typeof w.isOpen === "boolean") return !w.isOpen;
    const rs = w.socket && w.socket.readyState;
    if (typeof rs === "number") return rs !== 1;            // 1 = OPEN
    if (typeof w.readyState === "number") return w.readyState !== 1;
    return false;   // no pude determinar → asumir vivo
  } catch { return false; }
}

// WATCHDOG anti-cuelgue (sobre todo de madrugada): cada 90s revisa cada sesión y si NO está
// "connected" la reconecta sola. Reintenta SIEMPRE (no una sola vez como el setTimeout del close),
// así un blip de red no la deja colgada en "connecting" toda la noche.
setInterval(() => {
  try {
    for (const [acc, s] of sessions) {
      if (!s) continue;
      if (s.status === "logged_out" || s.status === "qr") continue;   // necesitan QR/manual
      if (s.starting && s.startedAt && (Date.now() - s.startedAt > 120000)) s.starting = false; // destrabar starting colgado
      // MUERTE SILENCIOSA: status dice "connected" pero el socket murió sin avisar "close" (se cortó a las 11am).
      // Reconectar si: (a) el WS está muerto, o (b) la sesión quedó MUDA >7min (conexión "zombie":
      // socket "abierto" pero WhatsApp dejó de mandar todo). Cubre la muerte silenciosa de las 8-9am.
      const muda = Date.now() - (s.lastRecv || s.startedAt || 0) > 7 * 60 * 1000;
      if (s.status === "connected" && !s.starting && (wsDead(s.sock) || muda)) {
        try { s.sock?.end?.(new Error("watchdog: socket muerto/zombie")); } catch {}
        s.status = "connecting";
        startSession(acc).catch(() => {});
        continue;
      }
      // Ping activo: mantiene la conexión caliente y fuerza round-trip con el server cada vuelta.
      if (s.status === "connected" && !s.starting) { try { s.sock?.sendPresenceUpdate?.("available"); } catch {} }
      if (s.status !== "connected" && !s.starting) startSession(acc).catch(() => {});
    }
    // cuenta con creds en disco que quedó fuera de memoria → levantarla
    for (const d of fs.readdirSync(DATA_DIR, { withFileTypes: true })) {
      if (d.isDirectory() && !sessions.has(d.name) && fs.existsSync(path.join(DATA_DIR, d.name, "creds.json"))) {
        startSession(d.name).catch(() => {});
      }
    }
  } catch {}
}, 60000);

app.listen(PORT, () => {
  console.log(`wa-web escuchando en :${PORT}  (data: ${DATA_DIR})`);
  setTimeout(bootSessions, 1500);
});
