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

// Texto legible de un mensaje de Baileys (lo que se muestra en el chat)
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
  sessions.set(acc, s);

  const sock = makeWASocket({
    version,
    auth: state,
    logger: log,
    printQRInTerminal: false,
    syncFullHistory: true,    // traer TODO el historial que WhatsApp tenga al vincular
    markOnlineOnConnect: false,
    browser: ["RealProfit", "Chrome", "1.0"],
  });
  s.sock = sock;

  sock.ev.on("creds.update", saveCreds);

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
      s.me = sock.user ? { id: sock.user.id, name: sock.user.name || sock.user.verifiedName || "" } : null;
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
  const touch = (jid, name, text, ts, unread) => {
    if (!jid || jid === "status@broadcast" || jid.endsWith("@g.us")) return; // solo 1:1 por ahora
    const c = s.chats.get(jid) || { id: jid };
    if (name) c.name = name;
    if (text != null) c.last = text;
    if (ts) c.ts = Math.max(c.ts || 0, ts);
    if (unread != null) c.unread = unread;
    s.chats.set(jid, c);
    saveStoreDebounced(acc, s);
  };

  // guardar un mensaje en la conversación del chat (para la vista de chat completa)
  const pushMsg = (jid, id, fromMe, text, ts, kind) => {
    if (!jid || jid === "status@broadcast" || jid.endsWith("@g.us")) return;
    if (!text) return;
    let arr = s.msgs.get(jid);
    if (!arr) { arr = []; s.msgs.set(jid, arr); }
    if (id && arr.some((x) => x.id === id)) return;   // evitar duplicados
    arr.push({ id: id || "", fromMe: !!fromMe, text: String(text), ts: ts || 0, kind: kind || "text" });
    if (arr.length > MAX_MSGS) arr.splice(0, arr.length - MAX_MSGS);
    saveStoreDebounced(acc, s);
  };

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
      const t = msgText(m);
      if (!t) continue;
      pushMsg(jid, m.key?.id, m.key?.fromMe, t, Number(m.messageTimestamp) || 0, "text");
      // el nombre del chat sale del CLIENTE (mensaje entrante), nunca del remitente saliente (el negocio)
      touch(jid, m.key?.fromMe ? undefined : m.pushName, t, Number(m.messageTimestamp) || 0, undefined);
    }
  });

  sock.ev.on("messages.upsert", ({ messages, type }) => {
    for (const m of messages) {
      const jid = m.key?.remoteJid;
      if (!jid || jid === "status@broadcast" || jid.endsWith("@g.us")) continue; // solo 1:1
      const t = msgText(m);
      touch(jid, m.key?.fromMe ? undefined : m.pushName, t, Number(m.messageTimestamp) || 0, undefined);
      pushMsg(jid, m.key?.id, m.key?.fromMe, t, Number(m.messageTimestamp) || 0, "text");
      // aviso a RealProfit: mensaje ENTRANTE nuevo (no míos), para que el bot decida si responde
      const texto = m.message?.conversation || m.message?.extendedTextMessage?.text || "";
      if (HOOK && type === "notify" && !m.key?.fromMe && texto) {
        notifyHook({
          acc,
          from: jid,
          tel: jid.split("@")[0],
          name: m.pushName || "",
          text: texto,
          ts: Number(m.messageTimestamp) || 0,
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
  const arr = [...s.chats.values()].sort((a, b) => (b.ts || 0) - (a.ts || 0)).slice(0, limit);
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
      name: c.name || (c.id || "").split("@")[0],
      photo: photo === undefined ? null : photo,
      last: c.last || "",
      ts: c.ts || 0,
      unread: c.unread || 0,
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
  // marcar como leído (baja el badge)
  const c = s.chats.get(chat);
  if (c) { c.unread = 0; s.chats.set(chat, c); }
  const arr = (s.msgs.get(chat) || []).slice().sort((a, b) => (a.ts || 0) - (b.ts || 0));
  res.json({ ok: true, name: c?.name || (chat.split("@")[0]), messages: arr });
});

app.post("/send", async (req, res) => {
  const acc = (req.body?.acc || "").trim();
  let to = (req.body?.to || "").trim();
  const text = (req.body?.text || "").toString();
  if (!acc || !to || !text) return res.status(400).json({ ok: false, msg: "faltan acc/to/text" });
  const s = sessions.get(acc);
  if (!s || s.status !== "connected") return res.status(409).json({ ok: false, msg: "sesion no conectada" });
  if (!to.includes("@")) to = to.replace(/\D/g, "") + "@s.whatsapp.net"; // acepta solo el número
  try {
    const sent = await s.sock.sendMessage(to, { text });
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

app.listen(PORT, () => {
  console.log(`wa-web escuchando en :${PORT}  (data: ${DATA_DIR})`);
  setTimeout(bootSessions, 1500);
});
