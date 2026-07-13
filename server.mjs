// server.mjs — jirun local Tidal bridge (v2.1, login flow)
// Your Tidal app isn't allowed the no-login method, so this uses the standard
// one-time login (OAuth Authorization Code + PKCE). The login + token exchange
// happen here on the server, so the browser never deals with OAuth or CORS.
//
// Setup once:
//   1) In developer.tidal.com → your app, add this Redirect URI EXACTLY:
//        http://localhost:8080/callback
//   2) Put your keys in credentials.txt (same folder):
//        TIDAL_CLIENT_ID=...
//        TIDAL_CLIENT_SECRET=...
// Run:
//   node server.mjs   → open http://localhost:8080/  → click "Log in with Tidal"
//
// Node 18+ (built-in fetch).

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;

function loadFile() {
  const cfg = {};
  for (const name of ["credentials.txt", ".env"]) {
    try {
      const p = path.join(__dirname, name);
      if (!fs.existsSync(p)) continue;
      for (const line of fs.readFileSync(p, "utf8").split(/\r?\n/)) {
        const s = line.trim();
        if (!s || s.startsWith("#")) continue;
        const i = s.indexOf("=");
        if (i < 0) continue;
        cfg[s.slice(0, i).trim()] = s.slice(i + 1).trim().replace(/^["']|["']$/g, "");
      }
    } catch (_) {}
  }
  return cfg;
}
const FILE = loadFile();
const CLIENT_ID = process.env.TIDAL_CLIENT_ID || FILE.TIDAL_CLIENT_ID || FILE.CLIENT_ID;
const CLIENT_SECRET = process.env.TIDAL_CLIENT_SECRET || FILE.TIDAL_CLIENT_SECRET || FILE.CLIENT_SECRET;
const COUNTRY = process.env.TIDAL_COUNTRY || FILE.TIDAL_COUNTRY || FILE.COUNTRY || "US";
const REDIRECT_URI = process.env.TIDAL_REDIRECT_URI || FILE.TIDAL_REDIRECT_URI || `http://localhost:${PORT}/callback`;
const SCOPES = process.env.TIDAL_SCOPES || FILE.TIDAL_SCOPES || "user.read collection.read collection.write playlists.read playlists.write";

/* ---- GetSongBPM cross-reference (BPM source) ---- */
const GSB_KEY = process.env.GETSONGBPM_API_KEY || FILE.GETSONGBPM_API_KEY || "";
const GSB_BASE = "https://api.getsong.co";
const BPM_CACHE_FILE = path.join(__dirname, "bpm-cache.json");
let bpmCache = {};
try { bpmCache = JSON.parse(fs.readFileSync(BPM_CACHE_FILE, "utf8")); } catch (_) {}
let cacheDirty = false;
function saveBpmCache() { if (!cacheDirty) return; try { fs.writeFileSync(BPM_CACHE_FILE, JSON.stringify(bpmCache)); cacheDirty = false; } catch (_) {} }
async function bpmFor(artist, title) {
  if (!GSB_KEY) throw new Error("GETSONGBPM_API_KEY not set");
  const k = `${(artist || "").toLowerCase()}|${(title || "").toLowerCase()}`;
  if (k in bpmCache) return bpmCache[k];
  let bpm = null;
  try {
    const lookup = encodeURIComponent(`song:${title} artist:${artist}`);
    const r = await fetch(`${GSB_BASE}/search/?api_key=${GSB_KEY}&type=both&limit=1&lookup=${lookup}`, { headers: { Accept: "application/json" } });
    if (r.ok) { const j = await r.json(); const hit = Array.isArray(j.search) ? j.search[0] : null; const t = hit && parseInt(hit.tempo, 10); if (t > 0) bpm = t; }
  } catch (_) {}
  bpmCache[k] = bpm; cacheDirty = true;
  return bpm;
}
async function mapLimit(arr, limit, fn) {
  const out = []; let i = 0;
  const worker = async () => { while (i < arr.length) { const idx = i++; out[idx] = await fn(arr[idx]); } };
  await Promise.all(Array.from({ length: Math.min(limit, arr.length || 1) }, worker));
  return out;
}

const API = "https://openapi.tidal.com/v2";
const TOKEN_URL = "https://auth.tidal.com/v1/oauth2/token";
const LOGIN_URL = "https://login.tidal.com/authorize";

/* ---- auth state (single user, in memory) ---- */
let store = { access: null, refresh: null, exp: 0 };
let pendingVerifier = null;
const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
function makePkce() {
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}
function authorizeUrl() {
  const { verifier, challenge } = makePkce();
  pendingVerifier = verifier;
  const q = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: SCOPES,
  });
  return `${LOGIN_URL}?${q}`;
}
function basicAuth() {
  return "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
}
async function exchangeCode(code) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: pendingVerifier || "",
  });
  const r = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { Authorization: basicAuth(), "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!r.ok) throw new Error(`token ${r.status}: ${await r.text()}`);
  const j = await r.json();
  store = { access: j.access_token, refresh: j.refresh_token || null, exp: Date.now() + ((j.expires_in || 3600) - 60) * 1000 };
}
async function refresh() {
  if (!store.refresh) throw new Error("no refresh token");
  const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: store.refresh });
  const r = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { Authorization: basicAuth(), "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!r.ok) throw new Error(`refresh ${r.status}`);
  const j = await r.json();
  store.access = j.access_token;
  if (j.refresh_token) store.refresh = j.refresh_token;
  store.exp = Date.now() + ((j.expires_in || 3600) - 60) * 1000;
}
async function accessToken() {
  if (store.access && Date.now() < store.exp) return store.access;
  if (store.refresh) { await refresh(); return store.access; }
  throw new Error("not logged in");
}

/* ---- API helper (auto-refresh once on 401) ---- */
async function tapi(pq) {
  let t = await accessToken();
  let r = await fetch(`${API}${pq}`, { headers: { Authorization: `Bearer ${t}`, Accept: "application/vnd.api+json" } });
  if (r.status === 401 && store.refresh) { await refresh(); t = store.access; r = await fetch(`${API}${pq}`, { headers: { Authorization: `Bearer ${t}`, Accept: "application/vnd.api+json" } }); }
  if (!r.ok) throw new Error(`${r.status} on ${pq}: ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

/* ---- JSON:API mapping ---- */
const isoToSec = (d) => { if (!d) return 210; const m = /PT(?:(\d+)M)?(?:(\d+)S)?/.exec(d); return (+(m?.[1] || 0)) * 60 + (+(m?.[2] || 0)) || 210; };
function mapTrack(res, included = []) {
  const a = res.attributes || {};
  const artistId = res.relationships?.artists?.data?.[0]?.id;
  const artist = included.find((x) => x.type === "artists" && x.id === artistId)?.attributes?.name || "";
  const gids = (res.relationships?.genres?.data || []).map((g) => g.id);
  const genres = included.filter((x) => x.type === "genres" && gids.includes(x.id)).map((x) => x.attributes?.name).filter(Boolean);
  return { id: res.id, title: a.title || "?", artist, bpm: a.bpm ?? null, isrc: a.isrc || null, durationSec: isoToSec(a.duration), genres };
}
async function search(q) {
  const s = await tapi(`/searchResults/${encodeURIComponent(q)}?countryCode=${COUNTRY}&include=tracks`);
  let ids = (s.data?.relationships?.tracks?.data || []).map((d) => d.id);
  if (!ids.length) ids = (s.included || []).filter((x) => x.type === "tracks").map((t) => t.id);
  ids = ids.slice(0, 10);
  if (!ids.length) return [];
  const t = await tapi(`/tracks?filter[id]=${ids.join(",")}&countryCode=${COUNTRY}&include=artists`);
  const byId = {}; for (const tr of (t.data || [])) byId[tr.id] = mapTrack(tr, t.included);
  return ids.map((id) => byId[id]).filter(Boolean);
}
async function pool(seedIds) {
  if (!GSB_KEY) throw new Error("GETSONGBPM_API_KEY not set — add it to credentials.txt");
  // Gather each seed's candidates separately so we can interleave fairly.
  const seedLists = [];
  for (const id of seedIds) {
    const list = [String(id)]; // the seed itself
    for (const rel of ["similarTracks", "suggestedTracks", "radio"]) {
      try { const j = await tapi(`/tracks/${id}/relationships/${rel}?countryCode=${COUNTRY}`); for (const d of j.data || []) list.push(d.id); } catch (_) {}
    }
    seedLists.push(list);
  }
  // Round-robin merge so every seed is represented, then dedupe.
  const seen = new Set(), ordered = [];
  const maxLen = Math.max(0, ...seedLists.map((l) => l.length));
  for (let i = 0; i < maxLen; i++) {
    for (const list of seedLists) { const id = list[i]; if (id && !seen.has(id)) { seen.add(id); ordered.push(id); } }
  }
  // Fetch Tidal meta for a generous slice (BPM lookups are cached, so this is cheap on repeat).
  const CAP = 220;
  const pick = ordered.slice(0, CAP), meta = [];
  for (let i = 0; i < pick.length; i += 20) {
    const chunk = pick.slice(i, i + 20);
    try { const j = await tapi(`/tracks?filter[id]=${chunk.join(",")}&countryCode=${COUNTRY}&include=artists,genres`); for (const t of j.data || []) meta.push(mapTrack(t, j.included)); } catch (_) {}
  }
  // Cross-reference BPM from GetSongBPM.
  const enriched = await mapLimit(meta, 8, async (t) => { const b = await bpmFor(t.artist, t.title).catch(() => null); return b ? { ...t, bpm: b } : null; });
  saveBpmCache();
  return enriched.filter(Boolean);
}

/* ---- playlist write (create + add tracks) ---- */
async function tpost(pq, body) {
  let t = await accessToken();
  const opts = { method: "POST", headers: { Authorization: `Bearer ${t}`, "Content-Type": "application/vnd.api+json", Accept: "application/vnd.api+json" }, body: JSON.stringify(body) };
  let r = await fetch(`${API}${pq}`, opts);
  if (r.status === 401 && store.refresh) { await refresh(); opts.headers.Authorization = `Bearer ${store.access}`; r = await fetch(`${API}${pq}`, opts); }
  if (!r.ok) throw new Error(`${r.status} on ${pq}: ${(await r.text()).slice(0, 300)}`);
  const txt = await r.text();
  return txt ? JSON.parse(txt) : {};
}
async function createPlaylist(name, trackIds) {
  const created = await tpost(`/playlists?countryCode=${COUNTRY}`, { data: { type: "playlists", attributes: { name, accessType: "UNLISTED" } } });
  const id = created?.data?.id;
  if (!id) throw new Error("playlist created but no id returned");
  for (let i = 0; i < trackIds.length; i += 20) {
    const chunk = trackIds.slice(i, i + 20).map((tid) => ({ id: String(tid), type: "tracks" }));
    await tpost(`/playlists/${id}/relationships/items?countryCode=${COUNTRY}`, { data: chunk });
  }
  return id;
}

/* ---- http ---- */
const sendJSON = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }); res.end(JSON.stringify(obj)); };
const sendHTML = (res, code, html) => { res.writeHead(code, { "Content-Type": "text/html" }); res.end(html); };
const page = (title, body) => `<!doctype html><meta charset="utf-8"><title>jirun</title><body style="font-family:system-ui;background:#0A0D12;color:#EAEEF5;padding:28px;line-height:1.5"><h3 style="color:#FF6A45">${title}</h3>${body}</body>`;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  try {
    if (url.pathname === "/login") {
      if (!CLIENT_ID) return sendHTML(res, 500, page("No credentials", "<p>Set your keys in credentials.txt and restart.</p>"));
      res.writeHead(302, { Location: authorizeUrl() });
      return res.end();
    }
    if (url.pathname === "/callback") {
      const err = url.searchParams.get("error");
      if (err) return sendHTML(res, 200, page("Tidal login error", `<p><b>${err}</b>: ${url.searchParams.get("error_description") || ""}</p><p>Copy this message and send it back.</p>`));
      const code = url.searchParams.get("code");
      if (!code) return sendHTML(res, 400, page("No code returned", "<p>Try the login again.</p>"));
      try { await exchangeCode(code); res.writeHead(302, { Location: "/" }); return res.end(); }
      catch (e) { return sendHTML(res, 200, page("Login exchange failed", `<pre style="white-space:pre-wrap;background:#131820;padding:12px;border-radius:8px">${e.message}</pre><p>Copy this and send it back.</p>`)); }
    }
    if (url.pathname === "/api/health") {
      return sendJSON(res, 200, { ok: true, loggedIn: !!(store.access || store.refresh), hasCreds: !!(CLIENT_ID && CLIENT_SECRET), bpmKey: !!GSB_KEY, country: COUNTRY });
    }
    if (url.pathname === "/api/bpmtest") {
      if (!GSB_KEY) return sendJSON(res, 200, { error: "GETSONGBPM_API_KEY not set in credentials.txt" });
      const artist = url.searchParams.get("artist") || "";
      const title = url.searchParams.get("title") || "";
      if (!title) return sendJSON(res, 400, { error: "add ?title=...&artist=..." });
      const lookup = encodeURIComponent(`song:${title} artist:${artist}`);
      const r = await fetch(`${GSB_BASE}/search/?api_key=${GSB_KEY}&type=both&limit=3&lookup=${lookup}`, { headers: { Accept: "application/json" } });
      const j = await r.json().catch(() => ({}));
      return sendJSON(res, 200, { status: r.status, results: (j.search || []).map((s) => ({ title: s.title, artist: s.artist?.name, tempo: s.tempo })) });
    }
    if (url.pathname === "/api/search") {
      const q = url.searchParams.get("q") || "";
      if (!q.trim()) return sendJSON(res, 400, { error: "empty query" });
      return sendJSON(res, 200, await search(q));
    }
    if (url.pathname === "/api/raw") {
      const q = url.searchParams.get("q") || "";
      if (!q.trim()) return sendJSON(res, 400, { error: "add ?q=a+song" });
      const s = await tapi(`/searchResults/${encodeURIComponent(q)}?countryCode=${COUNTRY}&include=tracks`);
      let ids = (s.data?.relationships?.tracks?.data || []).map((d) => d.id);
      if (!ids.length) ids = (s.included || []).filter((x) => x.type === "tracks").map((t) => t.id);
      ids = ids.slice(0, 2);
      const t = ids.length ? await tapi(`/tracks?filter[id]=${ids.join(",")}&countryCode=${COUNTRY}&include=artists`) : null;
      const sampleTrack = t?.data?.[0];
      return sendJSON(res, 200, {
        firstTrackIds: ids,
        sampleTrackRelationships: sampleTrack?.relationships || null,
        includedTypes: [...new Set((t?.included || []).map((x) => x.type))],
        includedArtistsSample: (t?.included || []).filter((x) => x.type === "artists").slice(0, 2).map((x) => ({ id: x.id, name: x.attributes?.name })),
        mappedResult: sampleTrack ? mapTrack(sampleTrack, t.included) : null,
      });
    }
    if (url.pathname === "/api/pooltest") {
      const q = url.searchParams.get("q") || "";
      if (!q.trim()) return sendJSON(res, 400, { error: "add ?q=a+song+you+seeded" });
      const hits = await search(q);
      const seed = hits[0];
      if (!seed) return sendJSON(res, 200, { note: "no search hit", hits: hits.length });
      const out = { seed: { id: seed.id, title: seed.title, artist: seed.artist, bpm: seed.bpm }, discovery: {} };
      let firstIds = [];
      for (const rel of ["similarTracks", "suggestedTracks", "radio"]) {
        try { const j = await tapi(`/tracks/${seed.id}/relationships/${rel}?countryCode=${COUNTRY}`); const d = j.data || []; out.discovery[rel] = d.length; if (!firstIds.length) firstIds = d.slice(0, 20).map((x) => x.id); }
        catch (e) { out.discovery[rel] = "ERROR: " + e.message.slice(0, 120); }
      }
      if (firstIds.length) {
        try {
          const tr = await tapi(`/tracks?filter[id]=${firstIds.join(",")}&countryCode=${COUNTRY}&include=artists,genres`);
          const tracks = (tr.data || []).map((t) => mapTrack(t, tr.included));
          out.fetchedTracks = tracks.length;
          out.tracksWithBpm = tracks.filter((t) => t.bpm != null).length;
          out.sampleBpms = tracks.slice(0, 10).map((t) => ({ title: t.title, bpm: t.bpm }));
        } catch (e) { out.bpmCheckError = e.message.slice(0, 150); }
      }
      return sendJSON(res, 200, out);
    }
    if (url.pathname === "/api/pool") {
      const ids = (url.searchParams.get("ids") || "").split(",").filter(Boolean);
      if (!ids.length) return sendJSON(res, 400, { error: "no seed ids" });
      return sendJSON(res, 200, await pool(ids));
    }
    if (url.pathname === "/api/export" && req.method === "POST") {
      let raw = ""; for await (const c of req) raw += c;
      let body = {}; try { body = JSON.parse(raw || "{}"); } catch (_) {}
      const name = (body.name || "pace→beat run").toString().slice(0, 100);
      const ids = Array.isArray(body.ids) ? body.ids.filter(Boolean) : [];
      if (!ids.length) return sendJSON(res, 400, { error: "no tracks to export" });
      const id = await createPlaylist(name, ids);
      return sendJSON(res, 200, { id, url: `https://tidal.com/playlist/${id}`, count: ids.length, name });
    }
    // static
    const file = url.pathname === "/" ? "paceBeat.html" : url.pathname.slice(1);
    const fp = path.join(__dirname, file);
    if (fp.startsWith(__dirname) && fs.existsSync(fp) && fs.statSync(fp).isFile()) {
      const ext = path.extname(fp);
      const type = ext === ".html" ? "text/html" : ext === ".mjs" || ext === ".js" ? "text/javascript" : "text/plain";
      res.writeHead(200, { "Content-Type": type });
      return res.end(fs.readFileSync(fp));
    }
    sendJSON(res, 404, { error: "not found" });
  } catch (e) {
    sendJSON(res, 500, { error: e.message });
  }
});
server.listen(PORT, () => {
  const creds = CLIENT_ID && CLIENT_SECRET ? "credentials loaded" : "⚠ no credentials — set them in credentials.txt";
  console.log(`jirun bridge on http://localhost:${PORT}/  (${creds})`);
  console.log(`Redirect URI (add this to your Tidal app): ${REDIRECT_URI}`);
});
