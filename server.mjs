// server.mjs — jirun bridge (dual-service: Tidal + Spotify)
// Discovery: Last.fm (similar artists). Tempo: GetSongBPM. Catalog + playlist:
// Tidal OR Spotify, chosen by which service the user logs into.
//
// credentials.txt (or env vars) — Tidal needs its pair, Spotify needs its pair:
//   TIDAL_CLIENT_ID / TIDAL_CLIENT_SECRET
//   SPOTIFY_CLIENT_ID / SPOTIFY_CLIENT_SECRET
//   GETSONGBPM_API_KEY
//   LASTFM_API_KEY
// Redirect URI to register in BOTH dashboards: http://localhost:8080/callback
// Run: node server.mjs

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
const env = (k) => process.env[k] || FILE[k];
const COUNTRY = env("TIDAL_COUNTRY") || "US";
const REDIRECT_URI = env("REDIRECT_URI") || env("TIDAL_REDIRECT_URI") || `http://localhost:${PORT}/callback`;
const GSB_KEY = env("GETSONGBPM_API_KEY") || "";
const GSB_BASE = "https://api.getsong.co";
const LASTFM_KEY = env("LASTFM_API_KEY") || "";
const LASTFM_BASE = "https://ws.audioscrobbler.com/2.0/";
const TIDAL_API = "https://openapi.tidal.com/v2";
const SPOTIFY_API = "https://api.spotify.com/v1";

/* ============ auth: two services, generic OAuth ============ */
const SERVICES = {
  tidal: {
    clientId: env("TIDAL_CLIENT_ID"), clientSecret: env("TIDAL_CLIENT_SECRET"),
    authorize: "https://login.tidal.com/authorize", token: "https://auth.tidal.com/v1/oauth2/token",
    scopes: env("TIDAL_SCOPES") || "user.read collection.read collection.write playlists.read playlists.write",
    pkce: true, store: { access: null, refresh: null, exp: 0 }, verifier: null,
  },
  spotify: {
    clientId: env("SPOTIFY_CLIENT_ID"), clientSecret: env("SPOTIFY_CLIENT_SECRET"),
    authorize: "https://accounts.spotify.com/authorize", token: "https://accounts.spotify.com/api/token",
    scopes: "playlist-modify-private playlist-modify-public",
    pkce: false, store: { access: null, refresh: null, exp: 0 }, verifier: null,
  },
};
const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
function makePkce() { const verifier = b64url(crypto.randomBytes(48)); const challenge = b64url(crypto.createHash("sha256").update(verifier).digest()); return { verifier, challenge }; }
function authorizeUrl(name) {
  const s = SERVICES[name];
  const p = new URLSearchParams({ client_id: s.clientId, response_type: "code", redirect_uri: REDIRECT_URI, scope: s.scopes, state: name });
  if (s.pkce) { const { verifier, challenge } = makePkce(); s.verifier = verifier; p.set("code_challenge", challenge); p.set("code_challenge_method", "S256"); }
  return `${s.authorize}?${p}`;
}
const basicAuth = (s) => "Basic " + Buffer.from(`${s.clientId}:${s.clientSecret}`).toString("base64");
async function exchangeCode(name, code) {
  const s = SERVICES[name];
  const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI });
  if (s.pkce) body.set("code_verifier", s.verifier || "");
  const r = await fetch(s.token, { method: "POST", headers: { Authorization: basicAuth(s), "Content-Type": "application/x-www-form-urlencoded" }, body });
  if (!r.ok) throw new Error(`token ${r.status}: ${await r.text()}`);
  const j = await r.json();
  s.store = { access: j.access_token, refresh: j.refresh_token || null, exp: Date.now() + ((j.expires_in || 3600) - 60) * 1000 };
}
async function refresh(name) {
  const s = SERVICES[name];
  if (!s.store.refresh) throw new Error("no refresh token");
  const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: s.store.refresh });
  const r = await fetch(s.token, { method: "POST", headers: { Authorization: basicAuth(s), "Content-Type": "application/x-www-form-urlencoded" }, body });
  if (!r.ok) throw new Error(`refresh ${r.status}`);
  const j = await r.json();
  s.store.access = j.access_token; if (j.refresh_token) s.store.refresh = j.refresh_token;
  s.store.exp = Date.now() + ((j.expires_in || 3600) - 60) * 1000;
}
async function accessToken(name) {
  const s = SERVICES[name];
  if (s.store.access && Date.now() < s.store.exp) return s.store.access;
  if (s.store.refresh) { await refresh(name); return s.store.access; }
  throw new Error(`not logged in to ${name}`);
}

/* ============ shared helpers ============ */
async function mapLimit(arr, limit, fn) {
  const out = []; let i = 0;
  const worker = async () => { while (i < arr.length) { const idx = i++; out[idx] = await fn(arr[idx]); } };
  await Promise.all(Array.from({ length: Math.min(limit, arr.length || 1) }, worker));
  return out;
}
const isoToSec = (d) => { if (!d) return 210; const m = /PT(?:(\d+)M)?(?:(\d+)S)?/.exec(d); return (+(m?.[1] || 0)) * 60 + (+(m?.[2] || 0)) || 210; };

/* ---- GetSongBPM (tempo) ---- */
const BPM_CACHE_FILE = path.join(__dirname, "bpm-cache.json");
let bpmCache = {}; try { bpmCache = JSON.parse(fs.readFileSync(BPM_CACHE_FILE, "utf8")); } catch (_) {}
let cacheDirty = false;
function saveBpmCache() { if (!cacheDirty) return; try { fs.writeFileSync(BPM_CACHE_FILE, JSON.stringify(bpmCache)); cacheDirty = false; } catch (_) {} }
async function bpmFor(artist, title) {
  if (!GSB_KEY) throw new Error("GETSONGBPM_API_KEY not set");
  const k = `${(artist || "").toLowerCase()}|${(title || "").toLowerCase()}`;
  if (k in bpmCache) return bpmCache[k];
  let bpm = null;
  try {
    const lookup = encodeURIComponent(`song:${title} artist:${artist}`);
    const r = await fetch(`${GSB_BASE}/search/?api_key=${GSB_KEY}&type=both&limit=5&lookup=${lookup}`, { headers: { Accept: "application/json" } });
    if (r.ok) { const j = await r.json(); for (const hit of (Array.isArray(j.search) ? j.search : [])) { const t = parseInt(hit && hit.tempo, 10); if (t > 0) { bpm = t; break; } } }
  } catch (_) {}
  bpmCache[k] = bpm; cacheDirty = true;
  return bpm;
}

/* ---- Last.fm (similar artists) ---- */
async function lastfmSimilar(name, limit = 40) {
  if (!LASTFM_KEY || !name) return [];
  try {
    const u = `${LASTFM_BASE}?method=artist.getsimilar&artist=${encodeURIComponent(name)}&api_key=${LASTFM_KEY}&format=json&limit=${limit}&autocorrect=1`;
    const r = await fetch(u, { headers: { Accept: "application/json" } });
    if (!r.ok) return [];
    const j = await r.json();
    return (j.similarartists?.artist || []).map((a) => a.name).filter(Boolean);
  } catch (_) { return []; }
}

/* ============ TIDAL ============ */
async function tapi(pq) {
  let t = await accessToken("tidal");
  let r = await fetch(`${TIDAL_API}${pq}`, { headers: { Authorization: `Bearer ${t}`, Accept: "application/vnd.api+json" } });
  if (r.status === 401 && SERVICES.tidal.store.refresh) { await refresh("tidal"); t = SERVICES.tidal.store.access; r = await fetch(`${TIDAL_API}${pq}`, { headers: { Authorization: `Bearer ${t}`, Accept: "application/vnd.api+json" } }); }
  if (!r.ok) throw new Error(`${r.status} on ${pq}: ${(await r.text()).slice(0, 200)}`);
  return r.json();
}
async function tapiPost(pq, body) {
  let t = await accessToken("tidal");
  const opts = { method: "POST", headers: { Authorization: `Bearer ${t}`, "Content-Type": "application/vnd.api+json", Accept: "application/vnd.api+json" }, body: JSON.stringify(body) };
  let r = await fetch(`${TIDAL_API}${pq}`, opts);
  if (r.status === 401 && SERVICES.tidal.store.refresh) { await refresh("tidal"); opts.headers.Authorization = `Bearer ${SERVICES.tidal.store.access}`; r = await fetch(`${TIDAL_API}${pq}`, opts); }
  if (!r.ok) throw new Error(`${r.status} on ${pq}: ${(await r.text()).slice(0, 300)}`);
  const txt = await r.text(); return txt ? JSON.parse(txt) : {};
}
function tidalMapTrack(res, included = []) {
  const a = res.attributes || {};
  const artistId = res.relationships?.artists?.data?.[0]?.id;
  const artist = included.find((x) => x.type === "artists" && x.id === artistId)?.attributes?.name || "";
  const gids = (res.relationships?.genres?.data || []).map((g) => g.id);
  const genres = included.filter((x) => x.type === "genres" && gids.includes(x.id)).map((x) => x.attributes?.name).filter(Boolean);
  return { id: res.id, ref: res.id, title: a.title || "?", artist, bpm: null, durationSec: isoToSec(a.duration), genres };
}
async function tidalSearchArtists(q) {
  const s = await tapi(`/searchResults/${encodeURIComponent(q)}?countryCode=${COUNTRY}&include=artists`);
  let ids = (s.data?.relationships?.artists?.data || []).map((d) => d.id);
  if (!ids.length) ids = (s.included || []).filter((x) => x.type === "artists").map((a) => a.id);
  ids = ids.slice(0, 10);
  const byId = {};
  for (const a of (s.included || []).filter((x) => x.type === "artists")) byId[a.id] = { id: a.id, name: a.attributes?.name || "?" };
  return ids.map((id) => byId[id]).filter(Boolean);
}
const tidalArtistIdCache = {};
async function tidalResolveArtist(name) {
  const k = (name || "").toLowerCase();
  if (k in tidalArtistIdCache) return tidalArtistIdCache[k];
  let id = null; try { const a = await tidalSearchArtists(name); id = a[0]?.id || null; } catch (_) {}
  tidalArtistIdCache[k] = id; return id;
}
async function tidalPool(seeds) {
  if (!GSB_KEY) throw new Error("GETSONGBPM_API_KEY not set — add it to credentials.txt");
  const seedList = seeds.map((s) => (typeof s === "string" ? { id: s, name: "" } : s));
  const seedIds = seedList.map((s) => String(s.id));
  const tidalIds = [];
  for (const s of seedList) { try { const j = await tapi(`/artists/${s.id}/relationships/similarArtists?countryCode=${COUNTRY}`); for (const d of j.data || []) tidalIds.push(d.id); } catch (_) {} }
  let lastfmIds = [];
  if (LASTFM_KEY) {
    const names = new Set();
    for (const s of seedList) { if (s.name) (await lastfmSimilar(s.name, 35)).slice(0, 30).forEach((n) => names.add(n)); }
    lastfmIds = (await mapLimit([...names], 6, (n) => tidalResolveArtist(n))).filter(Boolean);
  }
  const inter = [], mx = Math.max(lastfmIds.length, tidalIds.length);
  for (let i = 0; i < mx; i++) { if (lastfmIds[i]) inter.push(lastfmIds[i]); if (tidalIds[i]) inter.push(tidalIds[i]); }
  const useArtists = [...new Set([...seedIds, ...inter])].slice(0, 50);
  const trackLists = await mapLimit(useArtists, 6, async (aid) => { try { const j = await tapi(`/artists/${aid}/relationships/tracks?countryCode=${COUNTRY}&collapseBy=FINGERPRINT`); return (j.data || []).map((d) => d.id); } catch (_) { return []; } });
  const seedSet = new Set(seedIds), seedTracks = [], similarLists = [];
  useArtists.forEach((aid, i) => { if (seedSet.has(aid)) seedTracks.push(...(trackLists[i] || []).slice(0, 25)); else similarLists.push(trackLists[i] || []); });
  const rr = [], maxT = Math.max(0, ...similarLists.map((l) => l.length));
  for (let i = 0; i < maxT; i++) for (const tl of similarLists) if (tl[i]) rr.push(tl[i]);
  const seenT = new Set(), trackIds = [];
  for (const id of [...seedTracks, ...rr]) if (!seenT.has(id)) { seenT.add(id); trackIds.push(id); }
  const pick = trackIds.slice(0, 400), meta = [];
  for (let i = 0; i < pick.length; i += 20) { const chunk = pick.slice(i, i + 20); try { const j = await tapi(`/tracks?filter[id]=${chunk.join(",")}&countryCode=${COUNTRY}&include=artists,genres`); for (const t of j.data || []) meta.push(tidalMapTrack(t, j.included)); } catch (_) {} }
  const enriched = await mapLimit(meta, 8, async (t) => { const b = await bpmFor(t.artist, t.title).catch(() => null); return b ? { ...t, bpm: b } : null; });
  saveBpmCache();
  return enriched.filter(Boolean);
}
async function tidalCreatePlaylist(name, refs) {
  const created = await tapiPost(`/playlists?countryCode=${COUNTRY}`, { data: { type: "playlists", attributes: { name, accessType: "UNLISTED" } } });
  const id = created?.data?.id;
  if (!id) throw new Error("playlist created but no id returned");
  for (let i = 0; i < refs.length; i += 20) { const chunk = refs.slice(i, i + 20).map((tid) => ({ id: String(tid), type: "tracks" })); await tapiPost(`/playlists/${id}/relationships/items?countryCode=${COUNTRY}`, { data: chunk }); }
  return { id, url: `https://tidal.com/playlist/${id}` };
}

/* ============ SPOTIFY ============ */
async function sapi(pq, { method = "GET", body } = {}) {
  let t = await accessToken("spotify");
  const opts = { method, headers: { Authorization: `Bearer ${t}`, "Content-Type": "application/json" } };
  if (body) opts.body = JSON.stringify(body);
  let r = await fetch(`${SPOTIFY_API}${pq}`, opts);
  if (r.status === 401 && SERVICES.spotify.store.refresh) { await refresh("spotify"); opts.headers.Authorization = `Bearer ${SERVICES.spotify.store.access}`; r = await fetch(`${SPOTIFY_API}${pq}`, opts); }
  if (!r.ok) throw new Error(`${r.status} on ${pq}: ${(await r.text()).slice(0, 200)}`);
  const txt = await r.text(); return txt ? JSON.parse(txt) : {};
}
async function spotifySearchArtists(q) {
  const j = await sapi(`/search?q=${encodeURIComponent(q)}&type=artist&limit=10`);
  return (j.artists?.items || []).map((a) => ({ id: a.id, name: a.name }));
}
async function spotifyArtistTracks(name) {
  const j = await sapi(`/search?q=${encodeURIComponent(`artist:"${name}"`)}&type=track&limit=10`);
  return (j.tracks?.items || []).map((t) => ({ id: t.id, ref: t.uri, title: t.name, artist: t.artists?.[0]?.name || name, durationSec: Math.round((t.duration_ms || 210000) / 1000), genres: [] }));
}
async function spotifyPool(seeds) {
  if (!GSB_KEY) throw new Error("GETSONGBPM_API_KEY not set — add it to credentials.txt");
  const seedList = seeds.map((s) => (typeof s === "string" ? { name: s } : s));
  const seedNames = seedList.map((s) => s.name).filter(Boolean);
  const sim = new Set();
  if (LASTFM_KEY) for (const nm of seedNames) (await lastfmSimilar(nm, 35)).slice(0, 30).forEach((n) => sim.add(n));
  const artistNames = [...new Set([...seedNames, ...sim])].slice(0, 50);
  const trackLists = await mapLimit(artistNames, 5, async (nm) => { try { return await spotifyArtistTracks(nm); } catch (_) { return []; } });
  const seedNameSet = new Set(seedNames.map((n) => n.toLowerCase()));
  const seedTracks = [], similarLists = [];
  artistNames.forEach((nm, i) => { if (seedNameSet.has(nm.toLowerCase())) seedTracks.push(...(trackLists[i] || []).slice(0, 25)); else similarLists.push(trackLists[i] || []); });
  const rr = [], maxT = Math.max(0, ...similarLists.map((l) => l.length));
  for (let i = 0; i < maxT; i++) for (const tl of similarLists) if (tl[i]) rr.push(tl[i]);
  const seen = new Set(), cand = [];
  for (const t of [...seedTracks, ...rr]) if (t && !seen.has(t.ref)) { seen.add(t.ref); cand.push(t); }
  const pick = cand.slice(0, 400);
  const enriched = await mapLimit(pick, 8, async (t) => { const b = await bpmFor(t.artist, t.title).catch(() => null); return b ? { ...t, bpm: b } : null; });
  saveBpmCache();
  return enriched.filter(Boolean);
}
async function spotifyCreatePlaylist(name, uris) {
  await sapi(`/me`); // verify token/user
  const created = await sapi(`/me/playlists`, { method: "POST", body: { name, public: false, description: "Made with jirun" } });
  const id = created?.id;
  if (!id) throw new Error("Spotify playlist created but no id returned");
  for (let i = 0; i < uris.length; i += 100) { const chunk = uris.slice(i, i + 100); await sapi(`/playlists/${id}/items`, { method: "POST", body: { uris: chunk } }); }
  return { id, url: `https://open.spotify.com/playlist/${id}` };
}

/* ============ dispatch ============ */
const searchArtists = (svc, q) => (svc === "spotify" ? spotifySearchArtists(q) : tidalSearchArtists(q));
const buildPool = (svc, seeds) => (svc === "spotify" ? spotifyPool(seeds) : tidalPool(seeds));
const createPlaylist = (svc, name, refs) => (svc === "spotify" ? spotifyCreatePlaylist(name, refs) : tidalCreatePlaylist(name, refs));

/* ============ http ============ */
const sendJSON = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }); res.end(JSON.stringify(obj)); };
const sendHTML = (res, code, html) => { res.writeHead(code, { "Content-Type": "text/html" }); res.end(html); };
const page = (title, body) => `<!doctype html><meta charset="utf-8"><title>jirun</title><body style="font-family:system-ui;background:#F7F8F9;color:#172B4D;padding:28px;line-height:1.5"><h3 style="color:#0C66E4">${title}</h3>${body}</body>`;
const readBody = async (req) => { let raw = ""; for await (const c of req) raw += c; try { return JSON.parse(raw || "{}"); } catch (_) { return {}; } };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  try {
    if (url.pathname === "/login") {
      const svc = url.searchParams.get("service") || "tidal";
      if (!SERVICES[svc]?.clientId) return sendHTML(res, 500, page(`No ${svc} credentials`, `<p>Add ${svc.toUpperCase()}_CLIENT_ID / _SECRET to credentials.txt and restart.</p>`));
      res.writeHead(302, { Location: authorizeUrl(svc) }); return res.end();
    }
    if (url.pathname === "/callback") {
      const err = url.searchParams.get("error");
      const svc = url.searchParams.get("state") || "tidal";
      if (err) return sendHTML(res, 200, page(`${svc} login error`, `<p><b>${err}</b>: ${url.searchParams.get("error_description") || ""}</p><p>Copy this and send it back.</p>`));
      const code = url.searchParams.get("code");
      if (!code) return sendHTML(res, 400, page("No code", "<p>Try again.</p>"));
      try { await exchangeCode(svc, code); res.writeHead(302, { Location: `/?service=${svc}` }); return res.end(); }
      catch (e) { return sendHTML(res, 200, page(`${svc} login failed`, `<pre style="white-space:pre-wrap;background:#fff;padding:12px;border-radius:8px">${e.message}</pre>`)); }
    }
    if (url.pathname === "/api/health") {
      return sendJSON(res, 200, {
        ok: true,
        tidal: { loggedIn: !!(SERVICES.tidal.store.access || SERVICES.tidal.store.refresh), hasCreds: !!SERVICES.tidal.clientId },
        spotify: { loggedIn: !!(SERVICES.spotify.store.access || SERVICES.spotify.store.refresh), hasCreds: !!SERVICES.spotify.clientId },
        bpmKey: !!GSB_KEY, lastfmKey: !!LASTFM_KEY, country: COUNTRY,
      });
    }
    if (url.pathname === "/api/search") {
      const svc = url.searchParams.get("service") || "tidal";
      const q = url.searchParams.get("q") || "";
      if (!q.trim()) return sendJSON(res, 400, { error: "empty query" });
      return sendJSON(res, 200, await searchArtists(svc, q));
    }
    if (url.pathname === "/api/pool" && req.method === "POST") {
      const body = await readBody(req);
      const svc = body.service || "tidal";
      const seeds = Array.isArray(body.seeds) ? body.seeds : [];
      if (!seeds.length) return sendJSON(res, 400, { error: "no seeds" });
      return sendJSON(res, 200, await buildPool(svc, seeds));
    }
    if (url.pathname === "/api/export" && req.method === "POST") {
      const body = await readBody(req);
      const svc = body.service || "tidal";
      const name = (body.name || "jirun run").toString().slice(0, 100);
      const refs = Array.isArray(body.refs) ? body.refs.filter(Boolean) : [];
      if (!refs.length) return sendJSON(res, 400, { error: "no tracks to export" });
      const r = await createPlaylist(svc, name, refs);
      return sendJSON(res, 200, { ...r, count: refs.length, name });
    }
    if (url.pathname === "/api/bpmtest") {
      if (!GSB_KEY) return sendJSON(res, 200, { error: "GETSONGBPM_API_KEY not set" });
      const artist = url.searchParams.get("artist") || "", title = url.searchParams.get("title") || "";
      if (!title) return sendJSON(res, 400, { error: "add ?title=...&artist=..." });
      const lookup = encodeURIComponent(`song:${title} artist:${artist}`);
      const r = await fetch(`${GSB_BASE}/search/?api_key=${GSB_KEY}&type=both&limit=3&lookup=${lookup}`, { headers: { Accept: "application/json" } });
      const j = await r.json().catch(() => ({}));
      return sendJSON(res, 200, { status: r.status, results: (j.search || []).map((s) => ({ title: s.title, artist: s.artist?.name, tempo: s.tempo })) });
    }
    if (url.pathname === "/api/lasttest") {
      if (!LASTFM_KEY) return sendJSON(res, 200, { error: "LASTFM_API_KEY not set" });
      const artist = url.searchParams.get("artist") || "";
      if (!artist) return sendJSON(res, 400, { error: "add ?artist=..." });
      const names = await lastfmSimilar(artist, 20);
      return sendJSON(res, 200, { similarCount: names.length, similar: names.slice(0, 15) });
    }
    // static
    const file = url.pathname === "/" ? "paceBeat.html" : url.pathname.slice(1);
    const fp = path.join(__dirname, file);
    if (fp.startsWith(__dirname) && fs.existsSync(fp) && fs.statSync(fp).isFile()) {
      const ext = path.extname(fp);
      const type = ext === ".html" ? "text/html" : ext === ".mjs" || ext === ".js" ? "text/javascript" : "text/plain";
      res.writeHead(200, { "Content-Type": type }); return res.end(fs.readFileSync(fp));
    }
    sendJSON(res, 404, { error: "not found" });
  } catch (e) { sendJSON(res, 500, { error: e.message }); }
});
server.listen(PORT, () => {
  const have = (n) => (SERVICES[n].clientId ? "✓" : "—");
  console.log(`jirun bridge on http://localhost:${PORT}/  (tidal ${have("tidal")}, spotify ${have("spotify")}, bpm ${GSB_KEY ? "✓" : "—"}, lastfm ${LASTFM_KEY ? "✓" : "—"})`);
  console.log(`Redirect URI to register in both dashboards: ${REDIRECT_URI}`);
});
