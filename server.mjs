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
    scopes: env("TIDAL_SCOPES") || "user.read collection.read collection.write playlists.read playlists.write search.read",
    pkce: true, store: { access: null, refresh: null, exp: 0 }, verifier: null,
  },
  spotify: {
    clientId: env("SPOTIFY_CLIENT_ID"), clientSecret: env("SPOTIFY_CLIENT_SECRET"),
    authorize: "https://accounts.spotify.com/authorize", token: "https://accounts.spotify.com/api/token",
    scopes: "playlist-modify-private playlist-modify-public playlist-read-private playlist-read-collaborative",
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

/** Same BPM match rules as the client — used so pool expansion keys off usable music. */
function bpmMatch(bpm, cad, tol, modes) {
  const c = [];
  if (modes.includes("direct")) c.push(cad);
  if (modes.includes("half")) c.push(cad / 2);
  for (const target of c) if (Math.abs(bpm - target) <= tol) return true;
  return false;
}
/**
 * Per-cadence fill status. Tracks are assigned exclusively (no repeats across segments),
 * matching how the client packs — so "enough 170spm music" doesn't count toward a 150spm segment.
 */
function poolNeed(targetSec, targets, candidates) {
  const tol = +targets?.tol || 3;
  const modes = Array.isArray(targets?.modes) && targets.modes.length ? targets.modes : ["direct", "half"];
  let needs = Array.isArray(targets?.cadenceNeeds)
    ? targets.cadenceNeeds.map((n) => ({ cadence: +n.cadence, need: Math.max(0, +n.sec || 0), filled: 0 })).filter((n) => n.cadence > 0 && n.need > 0)
    : [];
  if (!needs.length && Array.isArray(targets?.cadences) && targets.cadences.length && targetSec > 0) {
    const share = targetSec / targets.cadences.length;
    needs = targets.cadences.map((c) => ({ cadence: +c, need: share, filled: 0 })).filter((n) => n.cadence > 0);
  }
  if (!needs.length) {
    const raw = candidates.reduce((s, t) => s + (t.durationSec || 210), 0);
    const matched = candidates.reduce((s, t) => s + (t.bpm != null ? (t.durationSec || 210) : 0), 0);
    const fillNeed = Math.max(0, targetSec);
    return {
      rawNeed: fillNeed * 8, matchNeed: fillNeed * 1.5, fillNeed, matched, raw,
      canFill: fillNeed <= 0 || matched >= fillNeed, enough: fillNeed <= 0 || matched >= fillNeed * 1.5,
      byCadence: [],
    };
  }

  // Merge duplicate cadence rows
  const byCad = new Map();
  for (const n of needs) {
    const k = Math.round(n.cadence);
    const prev = byCad.get(k);
    if (prev) prev.need += n.need;
    else byCad.set(k, { cadence: k, need: n.need, filled: 0 });
  }
  needs = [...byCad.values()];

  const tracks = [];
  for (const t of candidates) {
    if (t.bpm == null) continue;
    const cads = needs.filter((n) => bpmMatch(t.bpm, n.cadence, tol, modes)).map((n) => n.cadence);
    if (cads.length) tracks.push({ dur: t.durationSec || 210, cads });
  }
  tracks.sort((a, b) => b.dur - a.dur);
  for (const t of tracks) {
    let best = null, bestDeficit = 0;
    for (const n of needs) {
      if (!t.cads.includes(n.cadence)) continue;
      const deficit = n.need - n.filled;
      if (deficit > bestDeficit) { bestDeficit = deficit; best = n; }
    }
    if (best) best.filled += t.dur;
  }

  const fillNeed = needs.reduce((s, n) => s + n.need, 0);
  const matched = needs.reduce((s, n) => s + Math.min(n.filled, n.need), 0);
  const raw = candidates.reduce((s, t) => s + (t.durationSec || 210), 0);
  const canFill = needs.every((n) => n.filled >= n.need * 0.98);
  const enough = needs.every((n) => n.filled >= n.need * 1.35);
  return {
    rawNeed: fillNeed * 8,
    matchNeed: fillNeed * 1.35,
    fillNeed,
    matched,
    raw,
    canFill,
    enough,
    byCadence: needs.map((n) => ({
      cadence: n.cadence,
      need: Math.round(n.need),
      filled: Math.round(n.filled),
      short: Math.max(0, Math.round(n.need - n.filled)),
    })),
  };
}
/** Overall playlist-build % for the gather phase (never 100 — packing finishes on the client). */
function playlistGatherPct(phase, { level = 0, maxLevels = 20, need = null, bpmDone = 0, bpmTotal = 0 } = {}) {
  if (phase === "done") return 88;
  const ring = Math.max(0, Math.min(1, level / Math.max(1, maxLevels)));
  const fill = need?.fillNeed > 0 ? Math.max(0, Math.min(1, need.matched / need.fillNeed)) : 0;
  const bpm = bpmTotal > 0 ? Math.max(0, Math.min(1, bpmDone / bpmTotal)) : 0;
  const phaseBase = {
    start: 4,
    tracks: 10,
    similar: 14,
    expand: 18,
    resolve: 20,
    bpm: 22,
  }[phase] ?? 12;
  // Ring depth drives most of the bar so early “enough matches” can’t mark the job complete.
  const pct = phaseBase + ring * 50 + fill * 12 + bpm * 4;
  return Math.max(3, Math.min(86, Math.round(pct)));
}

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
  let ok = false;
  try {
    const lookup = encodeURIComponent(`song:${title} artist:${artist}`);
    const r = await fetch(`${GSB_BASE}/search/?api_key=${GSB_KEY}&type=both&limit=5&lookup=${lookup}`, { headers: { Accept: "application/json" } });
    if (r.ok) {
      ok = true;
      const j = await r.json();
      for (const hit of (Array.isArray(j.search) ? j.search : [])) {
        const t = parseInt(hit && hit.tempo, 10);
        if (t > 0) { bpm = t; break; }
      }
    }
  } catch (_) {}
  // Only cache real API answers — don't permanently cache network/rate-limit failures as "no BPM".
  if (ok) { bpmCache[k] = bpm; cacheDirty = true; }
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
/** App-only token for catalog/search. User tokens without search.read redact search to empty. */
const tidalCatalogAuth = { access: null, exp: 0 };
async function tidalCatalogToken() {
  if (tidalCatalogAuth.access && Date.now() < tidalCatalogAuth.exp) return tidalCatalogAuth.access;
  const s = SERVICES.tidal;
  if (!s.clientId || !s.clientSecret) throw new Error("Tidal credentials missing");
  const body = new URLSearchParams({ grant_type: "client_credentials" });
  const r = await fetch(s.token, { method: "POST", headers: { Authorization: basicAuth(s), "Content-Type": "application/x-www-form-urlencoded" }, body });
  if (!r.ok) throw new Error(`tidal client_credentials ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const j = await r.json();
  tidalCatalogAuth.access = j.access_token;
  tidalCatalogAuth.exp = Date.now() + ((j.expires_in || 3600) - 60) * 1000;
  return tidalCatalogAuth.access;
}
const TIDAL_ACCEPTS = ["application/vnd.api+json", "application/vnd.tidal.v1+json", "application/json"];
async function tidalFetch(pq, { token, accept = TIDAL_ACCEPTS[0] } = {}) {
  const r = await fetch(`${TIDAL_API}${pq}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: accept, "User-Agent": "jirun/1.0" },
  });
  const text = await r.text();
  let json = null; try { json = text ? JSON.parse(text) : {}; } catch (_) { json = { raw: text.slice(0, 300) }; }
  return { ok: r.ok, status: r.status, json, text: text.slice(0, 300) };
}
async function tapi(pq) {
  let t = await accessToken("tidal");
  let res = await tidalFetch(pq, { token: t });
  if (res.status === 401 && SERVICES.tidal.store.refresh) {
    await refresh("tidal");
    t = SERVICES.tidal.store.access;
    res = await tidalFetch(pq, { token: t });
  }
  if (!res.ok) throw new Error(`${res.status} on ${pq}: ${res.text}`);
  return res.json;
}
/** Catalog calls (search, artist metadata) — client credentials, no user login required. */
async function tapiCatalog(pq) {
  let t = await tidalCatalogToken();
  let res = await tidalFetch(pq, { token: t });
  if (res.status === 401) {
    tidalCatalogAuth.access = null; tidalCatalogAuth.exp = 0;
    t = await tidalCatalogToken();
    res = await tidalFetch(pq, { token: t });
  }
  // Some Tidal stacks prefer the v1 accept header
  if (!res.ok && (res.status === 406 || res.status === 415)) {
    res = await tidalFetch(pq, { token: t, accept: "application/vnd.tidal.v1+json" });
  }
  if (!res.ok) throw new Error(`${res.status} on ${pq}: ${res.text}`);
  return res.json;
}
async function tapiPost(pq, body) {
  let t = await accessToken("tidal");
  const opts = { method: "POST", headers: { Authorization: `Bearer ${t}`, "Content-Type": "application/vnd.api+json", Accept: "application/vnd.api+json", "User-Agent": "jirun/1.0" }, body: JSON.stringify(body) };
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
function tidalExtractArtists(payload) {
  const byId = {};
  const remember = (x) => {
    if (!x || x.type !== "artists" || !x.id) return;
    const nm = (x.attributes && x.attributes.name) || byId[x.id]?.name || "";
    byId[x.id] = { id: x.id, name: nm };
  };
  for (const x of payload.included || []) remember(x);
  const raw = payload.data;
  const dataArr = Array.isArray(raw) ? raw : raw ? [raw] : [];
  for (const x of dataArr) remember(x);

  const order = [];
  const push = (ref) => {
    const id = typeof ref === "string" ? ref : ref?.id;
    const type = typeof ref === "string" ? "artists" : ref?.type;
    if (!id || (type && type !== "artists")) return;
    if (!byId[id]) byId[id] = { id, name: "" };
    if (!order.includes(id)) order.push(id);
  };
  for (const x of dataArr) {
    if (x.type === "artists") push(x);
    for (const r of x.relationships?.artists?.data || []) push(r);
    for (const r of x.relationships?.topHits?.data || []) push(r);
    for (const r of x.relationships?.directHits?.data || []) push(r);
  }
  // Relationship docs: primary data is an array of {type,id} linkages
  if (Array.isArray(raw)) for (const r of raw) push(r);
  if (!order.length) for (const id of Object.keys(byId)) push(id);
  return order.slice(0, 10).map((id) => byId[id]).filter(Boolean);
}
async function tidalHydrateArtistNames(artists) {
  const need = artists.filter((a) => a && a.id && !a.name);
  if (!need.length) return artists.map((a) => ({ id: a.id, name: a.name || "?" }));
  try {
    const ids = [...new Set(need.map((a) => a.id))].slice(0, 20);
    const j = await tapiCatalog(`/artists?filter[id]=${ids.join(",")}&countryCode=${COUNTRY}`);
    const names = {};
    for (const a of j.data || []) if (a?.type === "artists") names[a.id] = a.attributes?.name || "";
    return artists.map((a) => ({ id: a.id, name: a.name || names[a.id] || "?" }));
  } catch (_) {
    return artists.map((a) => ({ id: a.id, name: a.name || "?" }));
  }
}
function tidalRelPath(link) {
  if (!link) return null;
  let p = String(link);
  if (p.startsWith("http")) p = p.replace(/^https?:\/\/openapi\.tidal\.com\/v2/i, "");
  if (p.startsWith("/v2/")) p = p.slice(3);
  if (!p.startsWith("/")) p = `/${p}`;
  return p;
}
/** Normalize an artist name into a Tidal profile handle (e.g. "Taylor Swift" → "taylorswift"). */
function tidalNameToHandle(name) {
  return String(name || "").toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "");
}
/** Accept pasted Tidal artist URLs or bare numeric ids. */
function tidalParseArtistRef(q) {
  const s = String(q || "").trim();
  if (!s) return null;
  const url = s.match(/(?:tidal\.com|listen\.tidal\.com)\/(?:browse\/)?artist\/(\d+)/i);
  if (url) return url[1];
  if (/^\d{3,}$/.test(s)) return s;
  return null;
}
async function tidalArtistById(id) {
  if (!id) return null;
  const path = `/artists/${encodeURIComponent(id)}?countryCode=${COUNTRY}`;
  for (const getter of [tapiCatalog, tapi]) {
    try {
      const j = await getter(path);
      const a = j?.data;
      if (a?.type === "artists" && a.id) return { id: String(a.id), name: a.attributes?.name || String(a.id) };
    } catch (_) { /* try next auth */ }
  }
  // Bulk filter works on some tokens when singular GET does not
  try {
    const j = await tapiCatalog(`/artists?filter[id]=${encodeURIComponent(id)}&countryCode=${COUNTRY}`);
    const a = (j.data || []).find((x) => x?.type === "artists" && String(x.id) === String(id));
    if (a) return { id: String(a.id), name: a.attributes?.name || String(a.id) };
  } catch (_) {}
  return null;
}
async function tidalArtistsByHandle(handle) {
  const h = tidalNameToHandle(handle);
  if (!h || h.length < 2) return [];
  const path = `/artists?filter[handle]=${encodeURIComponent(h)}&countryCode=${COUNTRY}`;
  for (const getter of [tapiCatalog, tapi]) {
    try {
      const j = await getter(path);
      return (j.data || [])
        .filter((a) => a?.type === "artists" && a.id)
        .map((a) => ({ id: String(a.id), name: a.attributes?.name || h }));
    } catch (_) { /* try next auth */ }
  }
  return [];
}
/** Fuzzy artist names via Last.fm (preferred) or MusicBrainz (no key). */
async function externalArtistNames(query, limit = 8) {
  const q = (query || "").trim();
  if (q.length < 1) return [];
  if (LASTFM_KEY) {
    try {
      const u = `${LASTFM_BASE}?method=artist.search&artist=${encodeURIComponent(q)}&api_key=${LASTFM_KEY}&format=json&limit=${limit}`;
      const r = await fetch(u, { headers: { Accept: "application/json" } });
      if (r.ok) {
        const j = await r.json();
        const raw = j.results?.artistmatches?.artist;
        const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
        const names = list.map((a) => a?.name).filter(Boolean);
        if (names.length) return [...new Set(names)].slice(0, limit);
      }
    } catch (_) {}
  }
  try {
    const u = `https://musicbrainz.org/ws/2/artist?query=${encodeURIComponent(q)}&fmt=json&limit=${limit}`;
    const r = await fetch(u, { headers: { Accept: "application/json", "User-Agent": "jirun/1.0 (https://github.com/jfforbes/jirun)" } });
    if (r.ok) {
      const j = await r.json();
      const names = (j.artists || []).map((a) => a.name).filter(Boolean);
      if (names.length) return [...new Set(names)].slice(0, limit);
    }
  } catch (_) {}
  return [];
}
/**
 * Tidal OpenAPI /v2/searchResults/{id} currently 400s with INVALID_RESOURCE_ID for many
 * third-party apps (see tidal-music/discussions/366). Classic v1 wants legacy r_usr.
 * Work around by resolving artists via handle/id and external name search.
 */
async function tidalSearchArtists(q, { debug = false } = {}) {
  const query = (q || "").trim();
  if (query.length < 1) return debug ? { artists: [], debug: [], build: "search-ext-72cc" } : [];
  const enc = encodeURIComponent(query);
  const debugLog = [];
  const done = (artists) => (debug ? { artists, debug: debugLog, build: "search-ext-72cc" } : artists);
  const finish = async (payload, via) => {
    const extracted = tidalExtractArtists(payload || {});
    const out = (await tidalHydrateArtistNames(extracted)).filter((a) => a.name && a.name !== "?");
    if (debug) debugLog.push({ via, extracted: extracted.length, named: out.length, sample: out.slice(0, 3) });
    return out;
  };
  const withInclude = (path, inc) => {
    if (!path) return null;
    if (path.includes("include=")) return path;
    return `${path}${path.includes("?") ? "&" : "?"}include=${inc}`;
  };

  // 0) Pasted Tidal artist URL / numeric id
  const directId = tidalParseArtistRef(query);
  if (directId) {
    try {
      const a = await tidalArtistById(directId);
      if (debug) debugLog.push({ via: "direct-id", id: directId, named: a ? 1 : 0, sample: a ? [a] : [] });
      if (a) return done([a]);
    } catch (e) {
      if (debug) debugLog.push({ via: "direct-id", error: String(e.message || e) });
    }
  }

  // 1) Direct handle for the typed query (fast path for names like "underoath")
  try {
    const byHandle = await tidalArtistsByHandle(query);
    if (debug) debugLog.push({ via: "handle/query", handle: tidalNameToHandle(query), named: byHandle.length, sample: byHandle.slice(0, 3) });
    if (byHandle.length) return done(byHandle);
  } catch (e) {
    if (debug) debugLog.push({ via: "handle/query", error: String(e.message || e) });
  }

  // 2) External fuzzy name search → resolve each candidate on Tidal by handle
  //    (bypasses broken searchResults; see github.com/orgs/tidal-music/discussions/366)
  if (query.length >= 2) {
    try {
      const names = await externalArtistNames(query, 10);
      if (debug) debugLog.push({ via: "external/names", count: names.length, sample: names.slice(0, 5) });
      const handleList = [];
      const seenHandle = new Set();
      for (const name of names) {
        const handle = tidalNameToHandle(name);
        if (!handle || handle.length < 2 || seenHandle.has(handle)) continue;
        seenHandle.add(handle);
        handleList.push(handle);
      }
      const batches = await mapLimit(handleList.slice(0, 12), 4, (h) => tidalArtistsByHandle(h));
      const resolved = [];
      for (const hits of batches) {
        for (const a of hits || []) {
          if (!resolved.some((x) => x.id === a.id)) resolved.push(a);
        }
      }
      if (debug) debugLog.push({ via: "external/resolve", tried: handleList.length, named: resolved.length, sample: resolved.slice(0, 3) });
      if (resolved.length) return done(resolved.slice(0, 10));
    } catch (e) {
      if (debug) debugLog.push({ via: "external", error: String(e.message || e) });
    }
  }

  // 3) Native OpenAPI search last — currently broken for many third-party apps, but
  //    keep it so we pick it up automatically if Tidal fixes access.
  const getters = [];
  try { await accessToken("tidal"); getters.push({ kind: "user", get: tapi }); } catch (e) {
    if (debug) debugLog.push({ via: "openapi/auth-user", error: String(e.message || e) });
  }
  getters.push({ kind: "catalog", get: tapiCatalog });
  for (const { kind, get } of getters) {
    try {
      const s = await get(`/searchResults/${enc}?countryCode=${COUNTRY}&include=artists,topHits`);
      const out = await finish(s, `openapi/${kind}`);
      if (out.length) return done(out);
      const relUrl = withInclude(
        tidalRelPath(s?.data?.relationships?.artists?.links?.self) ||
          `/searchResults/${enc}/relationships/artists?countryCode=${COUNTRY}`,
        "artists"
      );
      try {
        const rel = await get(relUrl);
        const out2 = await finish(rel, `openapi/${kind}/relationships`);
        if (out2.length) return done(out2);
      } catch (e) {
        if (debug) debugLog.push({ via: `openapi/${kind}/relationships`, error: String(e.message || e) });
      }
    } catch (e) {
      if (debug) debugLog.push({ via: `openapi/${kind}`, error: String(e.message || e) });
    }
  }

  return done([]);
}
const tidalArtistIdCache = {};
/** Pool expansion only needs a Tidal id for a known name — skip fuzzy/OpenAPI search. */
async function tidalResolveArtist(name) {
  const k = (name || "").toLowerCase();
  if (k in tidalArtistIdCache) return tidalArtistIdCache[k];
  let id = null;
  try {
    const hits = await tidalArtistsByHandle(name);
    id = hits[0]?.id || null;
  } catch (_) {}
  tidalArtistIdCache[k] = id;
  return id;
}
async function tidalArtistTrackIds(aid, limit) {
  const ids = [];
  let pathq = `/artists/${aid}/relationships/tracks?countryCode=${COUNTRY}&collapseBy=FINGERPRINT`;
  const rel = (n) => (n ? (n.startsWith("http") ? n.replace(TIDAL_API, "") : n) : null);
  for (let page = 0; page < 6 && pathq && ids.length < limit; page++) {
    try {
      const j = await tapi(pathq);
      for (const d of j.data || []) if (d?.id) ids.push(d.id);
      pathq = rel(j.links?.next);
    } catch (_) { break; }
  }
  return ids.slice(0, limit);
}
const POOL_BUDGET_MS = 15 * 60 * 1000; // absolute ceiling; keep expanding until each cadence can be filled
async function tidalPool(seeds, targetSec = 0, targets = null, onProgress = null) {
  if (!GSB_KEY) throw new Error("GETSONGBPM_API_KEY not set — add it to credentials.txt");
  const started = Date.now();
  const hardStop = () => Date.now() - started > POOL_BUDGET_MS;
  const seedList = seeds.map((s) => (typeof s === "string" ? { id: s, name: "" } : s));
  const seedIds = seedList.map((s) => String(s.id));
  const seedNames = seedList.map((s) => s.name).filter(Boolean);
  const ARTIST_CAP = 600, TRACK_CAP = 3000, MAX_LEVELS = 20;
  const knownNames = new Map(); seedNames.forEach((n) => knownNames.set(n.toLowerCase(), n));
  const doneArtists = new Set(), allTrackIds = new Set(), candidates = [];
  const idToName = new Map();
  let currentLevel = 0;
  const bpmStats = { tried: 0, hit: 0 };
  for (const s of seedList) if (s.id && s.name) idToName.set(String(s.id), s.name);
  // With many seeds, pull fewer tracks each so every seed gets BPM coverage before the time ceiling.
  const seedTrackCap = Math.max(20, Math.min(80, Math.floor(1200 / Math.max(1, seedIds.length))));
  const report = (phase, extra = {}) => {
    if (!onProgress) return;
    const need = poolNeed(targetSec, targets, candidates);
    const level = extra.level != null ? extra.level : currentLevel;
    const short = (need.byCadence || []).filter((c) => c.short > 30).slice(0, 4)
      .map((c) => `${c.cadence}spm needs ${Math.round(c.short / 60)}m more`);
    try {
      onProgress({
        stage: "gather",
        phase,
        pct: playlistGatherPct(phase, {
          level,
          maxLevels: MAX_LEVELS,
          need,
          bpmDone: extra.bpmDone || 0,
          bpmTotal: extra.bpmTotal || 0,
        }),
        level,
        maxLevels: MAX_LEVELS,
        artists: doneArtists.size,
        tracks: candidates.length,
        matchedSec: Math.round(need.matched || 0),
        needSec: Math.round(need.fillNeed || need.matchNeed || 0),
        elapsedSec: Math.round((Date.now() - started) / 1000),
        shortCadences: short,
        bpmHit: bpmStats.hit,
        bpmTried: bpmStats.tried,
        ...extra,
      });
    } catch (_) {}
  };
  /** Round-robin BPM lookups by artist so 38 seeds aren't starved by the first few. */
  async function enrichBpm(meta, detail, { finishAll = false } = {}) {
    const byArtist = new Map();
    for (const t of meta) {
      const k = (t.artist || "?").toLowerCase();
      if (!byArtist.has(k)) byArtist.set(k, []);
      byArtist.get(k).push(t);
    }
    const queues = [...byArtist.values()];
    const order = [];
    let guard = 0;
    while (queues.some((q) => q.length) && guard++ < meta.length + 5) {
      for (const q of queues) if (q.length) order.push(q.shift());
    }
    let i = 0;
    while (i < order.length) {
      if (!finishAll && poolNeed(targetSec, targets, candidates).enough) break;
      if (!finishAll && hardStop()) break;
      // Seed phase: keep going past the soft ceiling only briefly; still stop on absolute overrun.
      if (finishAll && Date.now() - started > POOL_BUDGET_MS * 1.5) break;
      const batch = order.slice(i, i + 24);
      i += batch.length;
      report("bpm", { detail, bpmDone: i, bpmTotal: order.length });
      const enriched = await mapLimit(batch, 10, async (t) => {
        bpmStats.tried++;
        const b = await bpmFor(t.artist, t.title).catch(() => null);
        if (b) bpmStats.hit++;
        return b ? { ...t, bpm: b } : null;
      });
      for (const t of enriched) if (t) {
        candidates.push(t);
        if (t.artist) {
          const k = t.artist.toLowerCase();
          if (!knownNames.has(k)) knownNames.set(k, t.artist);
        }
      }
      if (cacheDirty) saveBpmCache();
    }
  }
  async function fetchArtists(ids, seedWeight, detail) {
    const fresh = ids.filter((a) => a && !doneArtists.has(a));
    fresh.forEach((a) => doneArtists.add(a));
    if (!fresh.length) return [];
    report("tracks", { detail, pendingArtists: fresh.length });
    const perArtist = seedWeight ? seedTrackCap : 35;
    const trackLists = await mapLimit(fresh, 6, async (aid) => {
      try { return await tidalArtistTrackIds(aid, perArtist); } catch (_) { return []; }
    });
    const newIds = [];
    for (const tl of trackLists) for (const id of tl) if (!allTrackIds.has(id)) { allTrackIds.add(id); newIds.push(id); }
    const meta = [];
    for (let i = 0; i < newIds.length; i += 20) {
      if (!seedWeight && hardStop()) break;
      const chunk = newIds.slice(i, i + 20);
      try {
        const t = await tapi(`/tracks?filter[id]=${chunk.join(",")}&countryCode=${COUNTRY}&include=artists,genres`);
        for (const tr of t.data || []) {
          const mapped = tidalMapTrack(tr, t.included);
          meta.push(mapped);
          const aid = tr.relationships?.artists?.data?.[0]?.id;
          if (aid && mapped.artist) idToName.set(String(aid), mapped.artist);
        }
      } catch (_) {}
      report("tracks", { detail, trackMeta: meta.length, trackIds: newIds.length });
    }
    await enrichBpm(meta, detail, { finishAll: !!seedWeight });
    return fresh;
  }
  async function tidalSimilarIds(ids, detail) {
    const out = [];
    const fresh = ids.filter(Boolean);
    if (!fresh.length) return out;
    report("similar", { detail, pendingArtists: fresh.length });
    await mapLimit(fresh, 6, async (aid) => {
      try {
        const j = await tapi(`/artists/${aid}/relationships/similarArtists?countryCode=${COUNTRY}`);
        for (const d of j.data || []) if (d?.id) out.push(String(d.id));
      } catch (_) {}
    });
    return out;
  }

  report("start", { detail: "Gathering songs from seed artists" });
  await fetchArtists(seedIds, true, "seed artists");

  // BFS: related artists of related artists until every cadence band can be filled.
  let frontierIds = [...seedIds];
  let frontierNames = [...seedNames];
  for (let level = 1; level <= MAX_LEVELS; level++) {
    currentLevel = level;
    const need = poolNeed(targetSec, targets, candidates);
    if (need.enough) break;
    if (hardStop()) break;
    if (doneArtists.size >= ARTIST_CAP || allTrackIds.size >= TRACK_CAP) break;
    if (!frontierIds.length && !frontierNames.length) break;

    const shortNote = (need.byCadence || []).filter((c) => c.short > 30)
      .map((c) => `${c.cadence}spm`).slice(0, 3).join(", ");
    report("expand", {
      detail: shortNote ? `Gathering songs · ring ${level} (still short on ${shortNote})` : `Gathering songs · related artists ring ${level}`,
      level,
    });
    const nextIds = [];
    const nextNames = [];

    if (frontierIds.length && doneArtists.size < ARTIST_CAP) {
      const sim = await tidalSimilarIds(frontierIds.slice(0, 50), `Tidal similar · ring ${level}`);
      for (const id of sim) if (!doneArtists.has(id)) nextIds.push(id);
    }

    if (LASTFM_KEY && frontierNames.length && doneArtists.size < ARTIST_CAP) {
      const lists = await mapLimit(frontierNames.slice(0, 40), 6, (n) => lastfmSimilar(n, level === 1 ? 35 : 20));
      const newNames = [];
      for (const names of lists) for (const nm of names) {
        const k = nm.toLowerCase();
        if (!knownNames.has(k)) { knownNames.set(k, nm); newNames.push(nm); }
      }
      const room = Math.max(0, ARTIST_CAP - doneArtists.size - nextIds.length);
      const slice = newNames.slice(0, Math.min(room, level === 1 ? 60 : 45));
      report("resolve", { detail: `resolving ${slice.length} Last.fm artists · ring ${level}`, level });
      const resolved = await mapLimit(slice, 6, async (n) => {
        const id = await tidalResolveArtist(n);
        if (id) idToName.set(String(id), n);
        return id;
      });
      for (const id of resolved) if (id && !doneArtists.has(id)) nextIds.push(id);
      for (const n of slice) nextNames.push(n);
    }

    const uniq = [];
    const seen = new Set();
    for (const id of nextIds) {
      if (!id || seen.has(id) || doneArtists.has(id)) continue;
      seen.add(id);
      uniq.push(id);
    }
    if (!uniq.length) {
      frontierIds = [];
      frontierNames = nextNames;
      if (!frontierNames.length) break;
      continue;
    }

    const room = Math.max(0, ARTIST_CAP - doneArtists.size);
    const batch = uniq.slice(0, room);
    await fetchArtists(batch, false, `related artists · ring ${level}`);

    frontierIds = batch;
    frontierNames = batch.map((id) => idToName.get(id)).filter(Boolean);
    if (!frontierNames.length) frontierNames = nextNames;

    if (poolNeed(targetSec, targets, candidates).enough) break;
  }

  saveBpmCache();
  const finalNeed = poolNeed(targetSec, targets, candidates);
  report("done", {
    detail: finalNeed.enough
      ? "Song pool ready — building playlist"
      : finalNeed.canFill
        ? "Song pool can fill — building playlist"
        : hardStop()
          ? "Time ceiling reached — building playlist with what we have"
          : "Expanded as far as caps allow — building playlist",
  });
  return candidates;
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
const spotifyArtistIdCache = {};
async function spotifyResolveArtist(name) {
  const k = (name || "").toLowerCase();
  if (k in spotifyArtistIdCache) return spotifyArtistIdCache[k];
  let id = null; try { const a = await spotifySearchArtists(name); id = a[0]?.id || null; } catch (_) {}
  spotifyArtistIdCache[k] = id; return id;
}
function spotifyMapTrack(t, fallbackArtist) {
  return { id: t.id, ref: t.uri, title: t.name, artist: t.artists?.[0]?.name || fallbackArtist || "?", durationSec: Math.round((t.duration_ms || 210000) / 1000), genres: [] };
}
async function spotifyArtistTracks(name, id = null, limit = 40) {
  const byRef = new Map();
  const add = (t) => { if (t?.uri && !byRef.has(t.uri)) byRef.set(t.uri, spotifyMapTrack(t, name)); };
  if (id) {
    try { const j = await sapi(`/artists/${id}/top-tracks?market=US`); for (const t of j.tracks || []) add(t); } catch (_) {}
  }
  const q = encodeURIComponent(`artist:"${name}"`);
  for (let offset = 0; offset < 100 && byRef.size < limit; offset += 50) {
    try {
      const j = await sapi(`/search?q=${q}&type=track&limit=50&offset=${offset}`);
      const items = j.tracks?.items || [];
      if (!items.length) break;
      for (const t of items) add(t);
      if (items.length < 50) break;
    } catch (_) { break; }
  }
  return [...byRef.values()].slice(0, limit);
}
async function spotifyPool(seeds, targetSec = 0, targets = null, onProgress = null) {
  if (!GSB_KEY) throw new Error("GETSONGBPM_API_KEY not set — add it to credentials.txt");
  const started = Date.now();
  const hardStop = () => Date.now() - started > POOL_BUDGET_MS;
  const seedList = seeds.map((s) => (typeof s === "string" ? { name: s } : s));
  const seedNames = seedList.map((s) => s.name).filter(Boolean);
  const ARTIST_CAP = 600, TRACK_CAP = 3000, MAX_LEVELS = 20;
  const knownNames = new Map(); seedNames.forEach((n) => knownNames.set(n.toLowerCase(), n));
  const seedNameSet = new Set(seedNames.map((n) => n.toLowerCase()));
  const seedIdByName = new Map(); for (const s of seedList) if (s.name && s.id) seedIdByName.set(String(s.name).toLowerCase(), String(s.id));
  const doneNames = new Set(), seenRef = new Set(), candidates = [];
  let currentLevel = 0;
  const bpmStats = { tried: 0, hit: 0 };
  const seedTrackCap = Math.max(20, Math.min(70, Math.floor(1000 / Math.max(1, seedNames.length))));
  const report = (phase, extra = {}) => {
    if (!onProgress) return;
    const need = poolNeed(targetSec, targets, candidates);
    const level = extra.level != null ? extra.level : currentLevel;
    const short = (need.byCadence || []).filter((c) => c.short > 30).slice(0, 4)
      .map((c) => `${c.cadence}spm needs ${Math.round(c.short / 60)}m more`);
    try {
      onProgress({
        stage: "gather",
        phase,
        pct: playlistGatherPct(phase, {
          level,
          maxLevels: MAX_LEVELS,
          need,
          bpmDone: extra.bpmDone || 0,
          bpmTotal: extra.bpmTotal || 0,
        }),
        level,
        maxLevels: MAX_LEVELS,
        artists: doneNames.size,
        tracks: candidates.length,
        matchedSec: Math.round(need.matched || 0),
        needSec: Math.round(need.fillNeed || need.matchNeed || 0),
        elapsedSec: Math.round((Date.now() - started) / 1000),
        shortCadences: short,
        bpmHit: bpmStats.hit,
        bpmTried: bpmStats.tried,
        ...extra,
      });
    } catch (_) {}
  };
  async function enrichBpm(toBpm, detail, { finishAll = false } = {}) {
    const byArtist = new Map();
    for (const t of toBpm) {
      const k = (t.artist || "?").toLowerCase();
      if (!byArtist.has(k)) byArtist.set(k, []);
      byArtist.get(k).push(t);
    }
    const queues = [...byArtist.values()];
    const order = [];
    let guard = 0;
    while (queues.some((q) => q.length) && guard++ < toBpm.length + 5) {
      for (const q of queues) if (q.length) order.push(q.shift());
    }
    let i = 0;
    while (i < order.length) {
      if (!finishAll && poolNeed(targetSec, targets, candidates).enough) break;
      if (!finishAll && hardStop()) break;
      if (finishAll && Date.now() - started > POOL_BUDGET_MS * 1.5) break;
      const batch = order.slice(i, i + 24);
      i += batch.length;
      report("bpm", { detail, bpmDone: i, bpmTotal: order.length });
      const enriched = await mapLimit(batch, 10, async (t) => {
        bpmStats.tried++;
        const b = await bpmFor(t.artist, t.title).catch(() => null);
        if (b) bpmStats.hit++;
        return b ? { ...t, bpm: b } : null;
      });
      for (const t of enriched) if (t) candidates.push(t);
      if (cacheDirty) saveBpmCache();
    }
  }
  async function fetchNames(names, detail, { seedWeight = false } = {}) {
    const fresh = names.filter((n) => n && !doneNames.has(n.toLowerCase()));
    fresh.forEach((n) => doneNames.add(n.toLowerCase()));
    if (!fresh.length) return [];
    report("tracks", { detail, pendingArtists: fresh.length });
    const lists = await mapLimit(fresh, 5, async (nm) => {
      const isSeed = seedNameSet.has(nm.toLowerCase());
      let id = seedIdByName.get(nm.toLowerCase()) || null;
      if (!id) id = await spotifyResolveArtist(nm).catch(() => null);
      return spotifyArtistTracks(nm, id, isSeed ? seedTrackCap : 35).catch(() => []);
    });
    const toBpm = [];
    for (const tl of lists) for (const t of tl) if (t && !seenRef.has(t.ref)) { seenRef.add(t.ref); toBpm.push(t); }
    await enrichBpm(toBpm, detail, { finishAll: seedWeight });
    return fresh;
  }

  report("start", { detail: "Gathering songs from seed artists" });
  await fetchNames(seedNames, "seed artists", { seedWeight: true });

  let frontier = [...seedNames];
  for (let level = 1; level <= MAX_LEVELS; level++) {
    currentLevel = level;
    const need = poolNeed(targetSec, targets, candidates);
    if (need.enough) break;
    if (hardStop()) break;
    if (doneNames.size >= ARTIST_CAP || candidates.length >= TRACK_CAP) break;
    if (!LASTFM_KEY || !frontier.length) break;

    const shortNote = (need.byCadence || []).filter((c) => c.short > 30)
      .map((c) => `${c.cadence}spm`).slice(0, 3).join(", ");
    report("expand", {
      detail: shortNote ? `Gathering songs · ring ${level} (still short on ${shortNote})` : `Gathering songs · related artists ring ${level}`,
      level,
    });
    const lists = await mapLimit(frontier.slice(0, 40), 6, (n) => lastfmSimilar(n, level === 1 ? 35 : 20));
    const newNames = [];
    for (const names of lists) for (const nm of names) {
      const k = nm.toLowerCase();
      if (!knownNames.has(k)) { knownNames.set(k, nm); newNames.push(nm); }
    }
    const room = Math.max(0, ARTIST_CAP - doneNames.size);
    const slice = newNames.slice(0, Math.min(room, level === 1 ? 60 : 45));
    if (!slice.length) break;
    await fetchNames(slice, `related artists · ring ${level}`);
    frontier = slice;
  }

  saveBpmCache();
  const finalNeed = poolNeed(targetSec, targets, candidates);
  report("done", {
    detail: finalNeed.enough
      ? "Song pool ready — building playlist"
      : finalNeed.canFill
        ? "Song pool can fill — building playlist"
        : hardStop()
          ? "Time ceiling reached — building playlist with what we have"
          : "Expanded as far as caps allow — building playlist",
  });
  return candidates;
}
async function spotifyCreatePlaylist(name, uris) {
  await sapi(`/me`); // verify token/user
  const created = await sapi(`/me/playlists`, { method: "POST", body: { name, public: false, description: "Made with jirun" } });
  const id = created?.id;
  if (!id) throw new Error("Spotify playlist created but no id returned");
  for (let i = 0; i < uris.length; i += 100) { const chunk = uris.slice(i, i + 100); await sapi(`/playlists/${id}/items`, { method: "POST", body: { uris: chunk } }); }
  return { id, url: `https://open.spotify.com/playlist/${id}` };
}

/* ============ import seeds from a playlist ============ */
function jwtSub(token) { try { const p = JSON.parse(Buffer.from((token || "").split(".")[1] || "", "base64").toString("utf8")); return p.uid || p.userId || p.sub || null; } catch (_) { return null; } }
async function tidalMyPlaylists() {
  const uid = jwtSub(SERVICES.tidal.store.access);
  if (!uid) throw new Error("couldn't read Tidal user id from token");
  const map = new Map();
  const rel = (n) => (n ? (n.startsWith("http") ? n.replace(TIDAL_API, "") : n) : null);
  // source 1: playlists owned by the user (paginated)
  let pathq = `/playlists?filter[owners.id]=${uid}&countryCode=${COUNTRY}`;
  for (let p = 0; p < 12 && pathq; p++) {
    try { const j = await tapi(pathq); for (const pl of j.data || []) if (pl.type === "playlists" && !map.has(pl.id)) map.set(pl.id, { id: pl.id, name: pl.attributes?.name || "Untitled" }); pathq = rel(j.links?.next); } catch (_) { break; }
  }
  // source 2: the user's library collection (includes private + saved playlists), paginated
  let pathq2 = `/userCollectionPlaylists/${uid}/relationships/items?countryCode=${COUNTRY}&include=items`;
  for (let p = 0; p < 12 && pathq2; p++) {
    try {
      const j = await tapi(pathq2);
      const names = {}; for (const x of j.included || []) if (x.type === "playlists") names[x.id] = x.attributes?.name;
      for (const d of j.data || []) if (d.type === "playlists" && !map.has(d.id)) map.set(d.id, { id: d.id, name: names[d.id] || "Untitled" });
      pathq2 = rel(j.links?.next);
    } catch (_) { break; }
  }
  return [...map.values()];
}
async function tidalPlaylistArtists(id) {
  const rel = (n) => (n ? (n.startsWith("http") ? n.replace(TIDAL_API, "") : n) : null);
  const ids = new Set();
  let pathq = `/playlists/${id}/relationships/items?include=items&countryCode=${COUNTRY}`;
  for (let p = 0; p < 25 && pathq; p++) {
    const j = await tapi(pathq);
    for (const d of j.data || []) if (d.type === "tracks") ids.add(d.id);
    for (const x of j.included || []) if (x.type === "tracks") ids.add(x.id);
    pathq = rel(j.links?.next);
  }
  const trackIds = [...ids].slice(0, 600), artists = new Map();
  for (let i = 0; i < trackIds.length; i += 20) {
    const chunk = trackIds.slice(i, i + 20);
    try { const t = await tapi(`/tracks?filter[id]=${chunk.join(",")}&countryCode=${COUNTRY}&include=artists`); for (const tr of t.data || []) { const aid = tr.relationships?.artists?.data?.[0]?.id; const nm = (t.included || []).find((x) => x.type === "artists" && x.id === aid)?.attributes?.name; if (aid && nm && !artists.has(aid)) artists.set(aid, { id: aid, name: nm }); } } catch (_) {}
  }
  return [...artists.values()];
}
async function spotifyMyPlaylists() {
  const j = await sapi(`/me/playlists?limit=50`);
  return (j.items || []).map((p) => ({ id: p.id, name: p.name }));
}
async function spotifyPlaylistArtists(id) {
  const artists = new Map();
  let pathq = `/playlists/${id}/tracks?limit=100`;
  for (let page = 0; page < 8 && pathq; page++) {
    const j = await sapi(pathq);
    for (const it of j.items || []) { const t = it.track; if (!t) continue; for (const a of t.artists || []) if (a.id && !artists.has(a.id)) artists.set(a.id, { id: a.id, name: a.name }); }
    pathq = j.next ? j.next.replace(SPOTIFY_API, "") : null;
  }
  return [...artists.values()];
}

/* ============ dispatch ============ */
const searchArtists = (svc, q) => (svc === "spotify" ? spotifySearchArtists(q) : tidalSearchArtists(q));
const buildPool = (svc, seeds, targetSec, targets, onProgress) => (svc === "spotify" ? spotifyPool(seeds, targetSec, targets, onProgress) : tidalPool(seeds, targetSec, targets, onProgress));
const createPlaylist = (svc, name, refs) => (svc === "spotify" ? spotifyCreatePlaylist(name, refs) : tidalCreatePlaylist(name, refs));
const myPlaylists = (svc) => (svc === "spotify" ? spotifyMyPlaylists() : tidalMyPlaylists());
const playlistArtists = (svc, id) => (svc === "spotify" ? spotifyPlaylistArtists(id) : tidalPlaylistArtists(id));

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
    if (url.pathname === "/api/logout") {
      const svc = url.searchParams.get("service") || "tidal";
      if (SERVICES[svc]) { SERVICES[svc].store = { access: null, refresh: null, exp: 0 }; SERVICES[svc].verifier = null; }
      return sendJSON(res, 200, { ok: true, service: svc });
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
      if (svc === "tidal" && url.searchParams.get("debug") === "1") {
        return sendJSON(res, 200, await tidalSearchArtists(q, { debug: true }));
      }
      return sendJSON(res, 200, await searchArtists(svc, q));
    }
    if (url.pathname === "/api/pool" && req.method === "POST") {
      const body = await readBody(req);
      const svc = body.service || "tidal";
      const seeds = Array.isArray(body.seeds) ? body.seeds : [];
      if (!seeds.length) return sendJSON(res, 400, { error: "no seeds" });
      const targets = body.targets && typeof body.targets === "object" ? body.targets : null;
      // Stream NDJSON progress so the UI can show live status during long builds.
      res.writeHead(200, {
        "Content-Type": "application/x-ndjson; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
      });
      const send = (obj) => { try { res.write(JSON.stringify(obj) + "\n"); } catch (_) {} };
      try {
        const candidates = await buildPool(svc, seeds, +body.targetSec || 0, targets, (p) => send({ type: "progress", ...p }));
        send({ type: "done", candidates });
      } catch (e) {
        send({ type: "error", error: e.message || String(e) });
      }
      return res.end();
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
    if (url.pathname === "/api/playlists") {
      const svc = url.searchParams.get("service") || "tidal";
      return sendJSON(res, 200, await myPlaylists(svc));
    }
    if (url.pathname === "/api/playlist-artists") {
      const svc = url.searchParams.get("service") || "tidal";
      const id = url.searchParams.get("id");
      if (!id) return sendJSON(res, 400, { error: "no playlist id" });
      return sendJSON(res, 200, await playlistArtists(svc, id));
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
// Pool builds can run longer than Node's default 5-minute request timeout.
server.requestTimeout = 0;
server.headersTimeout = 0;
server.timeout = 0;
