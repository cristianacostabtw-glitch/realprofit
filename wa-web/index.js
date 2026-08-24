// RealProfit — Servicio WhatsApp Web (Baileys)
// Una sesión por CUENTA (email). Aislado: cada cuenta guarda su auth en su carpeta y solo ve SUS chats.
// Endpoints (todos requieren header  x-wa-secret: <WA_WEB_SECRET>):
//   POST /connect   {acc}          -> arranca/retoma la sesión; devuelve {status, qr?}
//   GET  /status?acc=..            -> {status: 'qr'|'connected'|'connecting'|'logged_out', me?}
//   GET  /qr?acc=..                -> {qr} (data URL PNG) mientras esté esperando escaneo
//   GET  /chats?acc=..&limit=..    -> [{id, name, photo, last, ts, unread}]
//   POST /logout    {acc}          -> cierra sesión y borra credenciales
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
const log = pino({ level: process.env.LOG_LEVEL || "warn" });

fs.mkdirSync(DATA_DIR, { recursive: true });

// --- estado en memoria por cuenta ---
const sessions = new Map(); // acc -> { sock, status, qr, me, chats:Map, starting }

function accDir(acc) {
  const safe = String(acc).replace(/[^a-zA-Z0-9._@-]/g, "_");
  return path.join(DATA_DIR, safe);
}

function pub(s) {
  if (!s) return { status: "disconnected" };
  return { status: s.status, me: s.me || null, hasQr: !!s.qr };
}

async function startSession(acc) {
  let s = sessions.get(acc);
  if (s && (s.status === "connected" || s.starting)) return s;

  const dir = accDir(acc);
  fs.mkdirSync(dir, { recursive: true });
  const { state, saveCreds } = await useMultiFileAuthState(dir);
  const { version } = await fetchLatestBaileysVersion();

  s = s || { chats: new Map() };
  s.status = "connecting";
  s.qr = null;
  s.starting = true;
  sessions.set(acc, s);

  const sock = makeWASocket({
    version,
    auth: state,
    logger: log,
    printQRInTerminal: false,
    syncFullHistory: false,
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
  sock.ev.on("messages.upsert", ({ messages }) => {
    for (const m of messages) {
      const jid = m.key?.remoteJid;
      const t = m.message?.conversation
        || m.message?.extendedTextMessage?.text
        || (m.message?.imageMessage ? "📷 Foto" : "")
        || (m.message?.documentMessage ? "📄 Documento" : "")
        || (m.message?.audioMessage ? "🎤 Audio" : "");
      touch(jid, m.pushName, t, Number(m.messageTimestamp) || 0, undefined);
    }
  });

  return s;
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

app.get("/chats", async (req, res) => {
  const acc = (req.query.acc || "").trim();
  const limit = Math.min(parseInt(req.query.limit || "50", 10) || 50, 200);
  const s = sessions.get(acc);
  if (!s || s.status !== "connected") return res.json({ ok: false, status: s?.status || "disconnected", chats: [] });
  const arr = [...s.chats.values()].sort((a, b) => (b.ts || 0) - (a.ts || 0)).slice(0, limit);
  // foto de perfil on-demand (con caché simple)
  s.photos = s.photos || new Map();
  const out = [];
  for (const c of arr) {
    let photo = s.photos.get(c.id);
    if (photo === undefined) {
      try { photo = await s.sock.profilePictureUrl(c.id, "preview"); }
      catch { photo = null; }
      s.photos.set(c.id, photo);
    }
    out.push({
      id: c.id,
      tel: (c.id || "").split("@")[0],
      name: c.name || (c.id || "").split("@")[0],
      photo: photo || null,
      last: c.last || "",
      ts: c.ts || 0,
      unread: c.unread || 0,
    });
  }
  res.json({ ok: true, status: "connected", me: s.me || null, chats: out });
});

app.post("/logout", async (req, res) => {
  const acc = (req.body?.acc || "").trim();
  const s = sessions.get(acc);
  try { await s?.sock?.logout(); } catch {}
  try { fs.rmSync(accDir(acc), { recursive: true, force: true }); } catch {}
  sessions.delete(acc);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`wa-web escuchando en :${PORT}  (data: ${DATA_DIR})`));
