// server.mjs — jirun bridge (dual-service: Tidal + Spotify)
// Discovery: Last.fm (similar artists). Tempo: GetSongBPM (+ Deezer, optional
// FreqBlog, AcousticBrainz; Tidal catalog BPM as final fallback). Catalog + playlist:
// Tidal OR Spotify, chosen by which service the user logs into.
//
// credentials.txt (or env vars) — Tidal needs its pair, Spotify needs its pair:
//   TIDAL_CLIENT_ID / TIDAL_CLIENT_SECRET
//   SPOTIFY_CLIENT_ID / SPOTIFY_CLIENT_SECRET
//   GETSONGBPM_API_KEY
//   LASTFM_API_KEY
//   FREQBLOG_API_KEY (optional second BPM source)
//   BPM_CACHE_MAX (optional; default 100000 track groups in bpm-cache.json)
// AcousticBrainz needs no key (MusicBrainz recording MBID → rhythm.bpm).
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
  // Small packing headroom — stop expanding once the run can be filled.
  const enough = needs.every((n) => n.filled >= n.need * 1.05);
  return {
    rawNeed: fillNeed * 8,
    matchNeed: fillNeed * 1.05,
    fillNeed,
    matched,
    // Uncapped fill (can exceed need) — used for honest progress past 100%.
    matchedRaw: needs.reduce((s, n) => s + n.filled, 0),
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
function playlistGatherPct(phase, { level = 0, maxLevels = 80, need = null, bpmDone = 0, bpmTotal = 0 } = {}) {
  if (phase === "done") return 88;
  if (need?.canFill) return 86;
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
  // Coverage drives the bar; ring depth is secondary so deep searches still look active.
  const pct = phaseBase + fill * 45 + ring * 18 + bpm * 4;
  return Math.max(3, Math.min(86, Math.round(pct)));
}

/* ---- BPM lookup (GetSongBPM + Deezer + optional FreqBlog + AcousticBrainz) ---- */
const MB_UA = "jirun/1.0 (https://github.com/jfforbes/jirun)";
const MB_BASE = "https://musicbrainz.org/ws/2";
const AB_BASE = "https://acousticbrainz.org/api/v1";
/** MusicBrainz asks for ≤1 req/s — serialize + space requests. */
let mbNextAt = 0;
let mbChain = Promise.resolve();
function mbFetch(url) {
  const run = async () => {
    const wait = Math.max(0, mbNextAt - Date.now());
    if (wait) await new Promise((r) => setTimeout(r, wait));
    mbNextAt = Date.now() + 1100;
    return fetch(url, { headers: { Accept: "application/json", "User-Agent": MB_UA } });
  };
  const p = mbChain.then(run, run);
  mbChain = p.then(() => {}, () => {});
  return p;
}
const mbidResolveCache = new Map(); // cacheKey → [{id,score}] | null
const BPM_CACHE_FILE = path.join(__dirname, "bpm-cache.json");
/** Cap unique track groups (each lookup may write several alias keys). File stays small; no DB needed. */
const BPM_CACHE_MAX_TRACKS = Math.max(100, Math.min(200000, parseInt(env("BPM_CACHE_MAX") || "100000", 10) || 100000));
let bpmCache = {}; try { bpmCache = JSON.parse(fs.readFileSync(BPM_CACHE_FILE, "utf8")); } catch (_) {}
let cacheDirty = false;
function saveBpmCache() {
  if (!cacheDirty) return;
  pruneBpmCache(BPM_CACHE_MAX_TRACKS);
  try { fs.writeFileSync(BPM_CACHE_FILE, JSON.stringify(bpmCache)); cacheDirty = false; } catch (_) {}
}
const FREQBLOG_KEY = env("FREQBLOG_API_KEY") || "";
/** Normalize for fuzzy title/artist matching across services. */
function cleanMusicToken(s) {
  return String(s || "").toLowerCase().normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\([^)]*\)/g, " ")
    .replace(/\[[^\]]*\]/g, " ")
    .replace(/feat\.?.*/g, " ")
    .replace(/ft\.?.*/g, " ")
    .replace(/[^a-z0-9]+/g, "")
    .trim();
}
function normTrackKey(artist, title) {
  return `${cleanMusicToken(artist)}|${cleanMusicToken(title)}`;
}
function makeCacheEntry(bpm, meta = {}) {
  const hasBpm = Number(bpm) > 0;
  // Persist misses too (with updatedAt) so LRU can age them out.
  if (!hasBpm && meta.source !== "miss" && !meta.allowMiss) return null;
  return {
    bpm: hasBpm ? Math.round(Number(bpm)) : null,
    source: meta.source || "unknown",
    confidence: Number(meta.confidence) || 0,
    updatedAt: Date.now(),
    ...meta,
    bpm: hasBpm ? Math.round(Number(bpm)) : null,
  };
}
function cacheEntryBpm(entry) {
  if (entry == null) return null;
  if (typeof entry === "number") return entry > 0 ? entry : null;
  if (typeof entry === "object" && Number(entry.bpm) > 0) return Math.round(Number(entry.bpm));
  return null;
}
/** Accept catalog/API BPM values in a runnable cadence range. */
function parseCatalogBpm(v) {
  const n = Number(v);
  if (!(n >= 40 && n <= 240)) return null;
  return Math.round(n);
}
function cacheStoreKeys(artist, title, { isrc = null, trackId = null, service = null } = {}) {
  const keys = [];
  const raw = `${(artist || "").toLowerCase()}|${(title || "").toLowerCase()}`;
  if (raw !== "|") keys.push(raw);
  const nk = normTrackKey(artist, title);
  if (nk !== "|") keys.push(`norm:${nk}`);
  if (isrc) keys.push(`isrc:${String(isrc).toUpperCase()}`);
  if (service && trackId) keys.push(`track:${service}:${trackId}`);
  return keys;
}
function cacheEntryUpdatedAt(entry) {
  if (entry && typeof entry === "object" && Number(entry.updatedAt) > 0) return Number(entry.updatedAt);
  return 0;
}
function cacheEntryPinned(entry) {
  return !!(entry && typeof entry === "object" && entry.user);
}
/** Drop oldest track groups until ≤ maxTracks. Alias keys for one lookup share groupId. */
function pruneBpmCache(maxTracks = BPM_CACHE_MAX_TRACKS) {
  const groups = new Map(); // groupId → { keys, updatedAt, pinned }
  for (const [k, v] of Object.entries(bpmCache)) {
    let groupId;
    let updatedAt = 0;
    let pinned = false;
    if (v && typeof v === "object") {
      updatedAt = cacheEntryUpdatedAt(v);
      pinned = cacheEntryPinned(v);
      if (v.groupId) groupId = `g:${v.groupId}`;
      else if (v.trackId != null && v.service) groupId = `track:${v.service}:${v.trackId}`;
      else if (v.isrc) groupId = `isrc:${String(v.isrc).toUpperCase()}`;
      else if (k.startsWith("norm:")) groupId = k;
      else groupId = `solo:${k}`;
    } else {
      groupId = `solo:${k}`;
    }
    const g = groups.get(groupId) || { keys: [], updatedAt: 0, pinned: false };
    g.keys.push(k);
    g.updatedAt = Math.max(g.updatedAt, updatedAt);
    g.pinned = g.pinned || pinned;
    groups.set(groupId, g);
  }
  if (groups.size <= maxTracks) return false;
  const ranked = [...groups.values()].sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? 1 : -1; // pinned last (kept)
    return a.updatedAt - b.updatedAt; // oldest first
  });
  let drop = groups.size - maxTracks;
  let removed = false;
  for (const g of ranked) {
    if (drop <= 0) break;
    if (g.pinned) continue;
    for (const k of g.keys) {
      if (k in bpmCache) {
        delete bpmCache[k];
        removed = true;
      }
    }
    drop--;
  }
  if (removed) cacheDirty = true;
  return removed;
}
function touchCacheEntry(entry) {
  if (!entry || typeof entry !== "object") return entry;
  if (Number(entry.updatedAt) > Date.now() - 60_000) return entry; // skip noisy rewrites
  entry.updatedAt = Date.now();
  cacheDirty = true;
  return entry;
}
function cacheBpm(artist, title, bpm, meta = {}) {
  const groupId = meta.groupId || crypto.randomUUID();
  const entry = makeCacheEntry(bpm, { ...meta, groupId });
  const val = entry || null;
  for (const k of cacheStoreKeys(artist, title, meta)) {
    bpmCache[k] = val;
    cacheDirty = true;
  }
}
function readCachedBpm(artist, title, { isrc = null, trackId = null, service = null } = {}) {
  const keys = cacheStoreKeys(artist, title, { isrc, trackId, service });
  for (const k of keys) {
    if (!(k in bpmCache)) continue;
    let entry = bpmCache[k];
    // Upgrade legacy bare numbers / nulls so LRU + prune have metadata.
    if (typeof entry === "number") {
      entry = { bpm: entry > 0 ? entry : null, source: "legacy", confidence: 0.5, updatedAt: Date.now(), groupId: crypto.randomUUID() };
      bpmCache[k] = entry;
      cacheDirty = true;
    } else if (entry === null) {
      entry = { bpm: null, source: "miss", confidence: 0, updatedAt: Date.now(), groupId: crypto.randomUUID() };
      bpmCache[k] = entry;
      cacheDirty = true;
    } else {
      touchCacheEntry(entry);
    }
    const bpm = cacheEntryBpm(entry);
    return { bpm, key: k, entry };
  }
  return { bpm: null, key: null, entry: null };
}
async function bpmFromGetSong(artist, title) {
  if (!GSB_KEY) return { bpm: null, ok: false };
  const lookups = [
    `song:${title} artist:${artist}`,
    `${title} ${artist}`,
    title,
  ];
  let sawOk = false;
  let best = null;
  for (const lookup of lookups) {
    try {
      const r = await fetch(`${GSB_BASE}/search/?api_key=${GSB_KEY}&type=both&limit=8&lookup=${encodeURIComponent(lookup)}`, {
        headers: { Accept: "application/json" },
      });
      if (!r.ok) continue;
      sawOk = true;
      const j = await r.json();
      const hits = Array.isArray(j.search) ? j.search : [];
      const wantArt = (artist || "").toLowerCase();
      const wantTitle = (title || "").toLowerCase();
      const scored = hits.map((hit) => {
        const t = parseInt(hit && hit.tempo, 10);
        if (!(t > 0)) return null;
        const hTitle = String(hit.title || hit.song_title || "").toLowerCase();
        const hArt = String(hit.artist?.name || hit.artist || "").toLowerCase();
        let score = 0;
        if (hTitle && wantTitle && (hTitle === wantTitle || hTitle.includes(wantTitle) || wantTitle.includes(hTitle))) score += 2;
        if (hArt && wantArt && (hArt === wantArt || hArt.includes(wantArt) || wantArt.includes(hArt))) score += 2;
        return { t, score };
      }).filter(Boolean).sort((a, b) => b.score - a.score);
      if (!scored.length) continue;
      // Strong match → done. Weak match → keep trying other query shapes.
      if (scored[0].score >= 2) return { bpm: scored[0].t, ok: true };
      if (!best || scored[0].score > best.score) best = scored[0];
    } catch (_) {}
  }
  if (best) return { bpm: best.t, ok: true };
  return { bpm: null, ok: sawOk };
}
async function bpmFromFreqBlog(artist, title) {
  if (!FREQBLOG_KEY) return { bpm: null, ok: false };
  try {
    const u = new URL("https://api.freqblog.com/lookup");
    u.searchParams.set("track", title || "");
    u.searchParams.set("artist", artist || "");
    const r = await fetch(u, { headers: { Accept: "application/json", "X-API-Key": FREQBLOG_KEY } });
    if (r.status === 202) return { bpm: null, ok: false }; // queued — don't cache as miss
    if (!r.ok) return { bpm: null, ok: false };
    const j = await r.json();
    const t = parseInt(j.bpm_snapped || j.bpm, 10);
    if (t > 0) return { bpm: t, ok: true };
    return { bpm: null, ok: true };
  } catch (_) {
    return { bpm: null, ok: false };
  }
}
async function bpmFromDeezer(artist, title, isrc = null) {
  try {
    if (isrc) {
      const byIsrc = await fetch(`https://api.deezer.com/track/isrc:${encodeURIComponent(String(isrc).toUpperCase())}`);
      if (byIsrc.ok) {
        const j = await byIsrc.json();
        const b = parseInt(j?.bpm, 10);
        if (b > 0) return { bpm: b, ok: true, source: "deezer:isrc", confidence: 0.96 };
      }
    }
    const q = encodeURIComponent(`track:"${title || ""}" artist:"${artist || ""}"`);
    const r = await fetch(`https://api.deezer.com/search?q=${q}&limit=8`);
    if (!r.ok) return { bpm: null, ok: false };
    const j = await r.json();
    const hits = Array.isArray(j?.data) ? j.data : [];
    const wantArt = cleanMusicToken(artist);
    const wantTitle = cleanMusicToken(title);
    const scored = hits.map((h) => {
      const b = parseInt(h?.bpm, 10);
      if (!(b > 0)) return null;
      const hArt = cleanMusicToken(h?.artist?.name || "");
      const hTitle = cleanMusicToken(h?.title || "");
      let score = 0;
      if (hArt && wantArt && (hArt === wantArt || hArt.includes(wantArt) || wantArt.includes(hArt))) score += 2;
      if (hTitle && wantTitle && (hTitle === wantTitle || hTitle.includes(wantTitle) || wantTitle.includes(hTitle))) score += 2;
      return { bpm: b, score };
    }).filter(Boolean).sort((a, b) => b.score - a.score);
    if (scored.length) {
      const conf = scored[0].score >= 4 ? 0.93 : scored[0].score >= 2 ? 0.82 : 0.68;
      return { bpm: scored[0].bpm, ok: true, source: "deezer:search", confidence: conf };
    }
    return { bpm: null, ok: true };
  } catch (_) {
    return { bpm: null, ok: false };
  }
}
/** Escape Lucene-ish specials for MusicBrainz search phrases. */
function mbQuote(s) {
  return String(s || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
async function musicBrainzFindRecordings(artist, title, isrc = null, limit = 5) {
  const cacheKey = isrc
    ? `isrc:${String(isrc).toUpperCase()}`
    : `at:${normTrackKey(artist, title)}`;
  if (mbidResolveCache.has(cacheKey)) return mbidResolveCache.get(cacheKey) || [];

  const queries = [];
  if (isrc) queries.push(`isrc:${String(isrc).toUpperCase()}`);
  const a = mbQuote(artist), t = mbQuote(title);
  if (t && a) queries.push(`recording:"${t}" AND artist:"${a}"`);
  if (t && a) queries.push(`recording:${t} AND artist:${a}`);

  const wantArt = cleanMusicToken(artist);
  const wantTitle = cleanMusicToken(title);
  let best = [];
  let sawOk = false;
  for (const q of queries) {
    try {
      const r = await mbFetch(`${MB_BASE}/recording?query=${encodeURIComponent(q)}&fmt=json&limit=${limit}`);
      if (!r.ok) continue;
      sawOk = true;
      const j = await r.json();
      const hits = Array.isArray(j?.recordings) ? j.recordings : [];
      const scored = hits.map((h) => {
        const id = h?.id;
        if (!id) return null;
        const hTitle = cleanMusicToken(h?.title || "");
        const credit = Array.isArray(h?.["artist-credit"]) ? h["artist-credit"] : [];
        const hArt = cleanMusicToken(credit.map((c) => c?.name || c?.artist?.name || "").join(" "));
        let score = Number(h?.score) || 0;
        if (isrc && queries[0].startsWith("isrc:")) score += 50;
        if (hTitle && wantTitle && (hTitle === wantTitle || hTitle.includes(wantTitle) || wantTitle.includes(hTitle))) score += 20;
        if (hArt && wantArt && (hArt === wantArt || hArt.includes(wantArt) || wantArt.includes(hArt))) score += 20;
        return { id, score, title: h?.title || title };
      }).filter(Boolean).sort((x, y) => y.score - x.score);
      if (scored.length) {
        best = scored;
        // ISRC hit or strong match is enough.
        if (isrc || scored[0].score >= 40) break;
      }
    } catch (_) {}
  }
  const out = best.slice(0, limit);
  mbidResolveCache.set(cacheKey, out.length ? out : (sawOk ? [] : null));
  return out;
}
async function acousticBrainzBpmForMbid(mbid) {
  if (!mbid) return null;
  try {
    const r = await fetch(`${AB_BASE}/${encodeURIComponent(mbid)}/low-level`, {
      headers: { Accept: "application/json", "User-Agent": MB_UA },
    });
    if (r.status === 404) return null;
    if (!r.ok) return null;
    const j = await r.json();
    const bpm = Number(j?.rhythm?.bpm);
    if (!(bpm >= 40 && bpm <= 240)) return null;
    return Math.round(bpm);
  } catch (_) {
    return null;
  }
}
/** AcousticBrainz tempo via MusicBrainz recording MBID (ISRC preferred). */
async function bpmFromAcousticBrainz(artist, title, isrc = null) {
  try {
    const recs = await musicBrainzFindRecordings(artist, title, isrc, 5);
    if (!recs.length) {
      // Empty array from cache after a successful MB search = definitive miss.
      // null cache (network fail) surfaces as empty here too after first fail — treat as soft miss.
      return { bpm: null, ok: mbidResolveCache.get(isrc ? `isrc:${String(isrc).toUpperCase()}` : `at:${normTrackKey(artist, title)}`) != null };
    }
    for (const rec of recs) {
      const bpm = await acousticBrainzBpmForMbid(rec.id);
      if (!(bpm > 0)) continue;
      const viaIsrc = !!(isrc && rec.score >= 50);
      const conf = viaIsrc ? 0.9 : rec.score >= 40 ? 0.86 : rec.score >= 20 ? 0.78 : 0.65;
      return {
        bpm,
        ok: true,
        source: viaIsrc ? "acousticbrainz:isrc" : "acousticbrainz",
        confidence: conf,
        mbid: rec.id,
      };
    }
    return { bpm: null, ok: true };
  } catch (_) {
    return { bpm: null, ok: false };
  }
}
function pickConsensus(candidates) {
  const good = (candidates || []).filter((c) => Number(c?.bpm) > 0);
  if (!good.length) return null;
  if (good.length === 1) return good[0];
  // Prefer agreement cluster within ±3 BPM; otherwise highest-confidence source.
  let best = null;
  for (const c of good) {
    const cluster = good.filter((x) => Math.abs(x.bpm - c.bpm) <= 3);
    const score = cluster.reduce((s, x) => s + (Number(x.confidence) || 0.5), 0);
    if (!best || score > best.score) {
      const weighted = Math.round(cluster.reduce((s, x) => s + x.bpm * (Number(x.confidence) || 0.5), 0) / score);
      best = { bpm: weighted, source: "consensus", confidence: Math.min(0.99, score / Math.max(1, cluster.length)), score };
    }
  }
  return best || good.sort((a, b) => (b.confidence || 0) - (a.confidence || 0))[0];
}
/** Per-artist GetSongBPM song→tempo map (far denser than per-track search for seed catalogs). */
const gsbArtistMaps = new Map(); // lowerName → Map<titleKey, tempo> | null (miss)
async function gsbArtistTempoMap(artistName) {
  const name = String(artistName || "").trim();
  if (!GSB_KEY || !name) return null;
  const k = name.toLowerCase();
  if (gsbArtistMaps.has(k)) return gsbArtistMaps.get(k);
  let map = null;
  try {
    const r = await fetch(`${GSB_BASE}/artist/?api_key=${GSB_KEY}&lookup=${encodeURIComponent(name)}`, {
      headers: { Accept: "application/json" },
    });
    if (r.ok) {
      const j = await r.json();
      const arts = Array.isArray(j.artist) ? j.artist : j.artist ? [j.artist] : Array.isArray(j.search) ? j.search : [];
      const want = cleanMusicToken(name);
      const pick = arts.find((a) => cleanMusicToken(a?.name || a?.artist?.name || "") === want)
        || arts.find((a) => cleanMusicToken(a?.name || "").includes(want) || want.includes(cleanMusicToken(a?.name || "")))
        || arts[0];
      const songs = pick?.songs || pick?.song || [];
      if (Array.isArray(songs) && songs.length) {
        map = new Map();
        for (const s of songs) {
          const title = s.song_title || s.title || s.name || "";
          const tempo = parseInt(s.tempo ?? s.bpm, 10);
          const tk = cleanMusicToken(title);
          if (tk && tempo > 0 && !map.has(tk)) map.set(tk, tempo);
        }
        if (!map.size) map = null;
      }
    }
  } catch (_) {}
  gsbArtistMaps.set(k, map);
  return map;
}
async function bpmForTrack(track) {
  const artist = track?.artist || "";
  const title = track?.title || "";
  const isrc = track?.isrc || null;
  const trackId = track?.id || track?.ref || null;
  const service = track?.service || null;
  // Catalog BPM (e.g. Tidal attributes.bpm) is a final fallback — try cache + APIs first.
  const catalogBpm = parseCatalogBpm(track?.bpm);

  const cached = readCachedBpm(artist, title, { isrc, trackId, service });
  if (cached.key) return cached.bpm;

  // Artist catalog first — one request covers many tracks for that artist.
  const artMap = await gsbArtistTempoMap(artist);
  const tk = cleanMusicToken(title);
  if (artMap && tk && artMap.has(tk)) {
    const bpm = artMap.get(tk);
    cacheBpm(artist, title, bpm, { source: "getsong:artist", confidence: 0.92, isrc, trackId, service });
    return bpm;
  }

  const gsb = await bpmFromGetSong(artist, title);
  const fb = gsb.bpm == null ? await bpmFromFreqBlog(artist, title) : { bpm: null, ok: false };
  const dz = await bpmFromDeezer(artist, title, isrc);
  let winner = pickConsensus([
    gsb.bpm != null ? { bpm: gsb.bpm, source: "getsong:search", confidence: 0.8 } : null,
    fb.bpm != null ? { bpm: fb.bpm, source: "freqblog", confidence: 0.84 } : null,
    dz.bpm != null ? { bpm: dz.bpm, source: dz.source || "deezer", confidence: dz.confidence || 0.78 } : null,
  ].filter(Boolean));
  // AcousticBrainz fills gaps when commercial BPM APIs miss (and can join consensus).
  let ab = { bpm: null, ok: false };
  if (!winner?.bpm) {
    ab = await bpmFromAcousticBrainz(artist, title, isrc);
    if (ab.bpm != null) {
      winner = { bpm: ab.bpm, source: ab.source || "acousticbrainz", confidence: ab.confidence || 0.8, mbid: ab.mbid };
    }
  }
  if (winner?.bpm) {
    cacheBpm(artist, title, winner.bpm, { ...winner, isrc, trackId, service });
    return winner.bpm;
  }
  // Tidal/catalog native tempo last — free when already on the track, after external misses.
  if (catalogBpm != null) {
    const src = track?.bpmSource || (service === "tidal" ? "tidal" : "native");
    cacheBpm(artist, title, catalogBpm, { source: src, confidence: 0.88, isrc, trackId, service });
    return catalogBpm;
  }
  // Only cache definitive misses; leave network failures retriable.
  if (gsb.ok || fb.ok || dz.ok || ab.ok) {
    cacheBpm(artist, title, null, { source: "miss", confidence: 0, isrc, trackId, service });
  }
  return null;
}
async function bpmFor(artist, title) {
  return bpmForTrack({ artist, title });
}
/** Target BPM centers (direct ± tol and optional half-time) we still care about. */
function cadenceBpmCenters(targets) {
  const tol = +targets?.tol || 3;
  const modes = Array.isArray(targets?.modes) && targets.modes.length ? targets.modes : ["direct", "half"];
  const centers = new Set();
  const needs = Array.isArray(targets?.cadenceNeeds) ? targets.cadenceNeeds : [];
  for (const n of needs) {
    const cad = Math.round(+n.cadence);
    if (!(cad > 0)) continue;
    if (modes.includes("direct")) for (let d = -tol; d <= tol; d++) centers.add(cad + d);
    if (modes.includes("half")) {
      const h = Math.round(cad / 2);
      for (let d = -tol; d <= tol; d++) if (h + d >= 40) centers.add(h + d);
    }
  }
  if (!centers.size && Array.isArray(targets?.cadences)) {
    for (const c of targets.cadences) {
      const cad = Math.round(+c);
      if (!(cad > 0)) continue;
      if (modes.includes("direct")) centers.add(cad);
      if (modes.includes("half")) centers.add(Math.round(cad / 2));
    }
  }
  return [...centers].filter((b) => b >= 40 && b <= 220).sort((a, b) => a - b);
}
/** Songs near a target BPM from GetSongBPM's tempo catalog (popular songs at that tempo). */
async function gsbSongsAtBpm(bpm, limit = 100) {
  if (!GSB_KEY || !(bpm > 0)) return [];
  try {
    const r = await fetch(`${GSB_BASE}/tempo/?api_key=${GSB_KEY}&bpm=${Math.round(bpm)}&limit=${limit}`, {
      headers: { Accept: "application/json" },
    });
    if (!r.ok) return [];
    const j = await r.json();
    const raw = j.tempo || j.search || j.songs || j.data || [];
    const list = Array.isArray(raw) ? raw : [];
    return list.map((hit) => {
      const tempo = parseInt(hit.tempo ?? hit.bpm, 10);
      const title = hit.song_title || hit.title || hit.name || "";
      const artist = hit.artist?.name || (Array.isArray(hit.artist) ? hit.artist[0]?.name : "") || hit.artist_name || "";
      if (!(tempo > 0) || !title) return null;
      return { title, artist, tempo };
    }).filter(Boolean);
  } catch (_) {
    return [];
  }
}
/**
 * Stamp BPM onto already-fetched catalog tracks by matching GetSongBPM's
 * tempo lists for the cadences we still need.
 */
async function stampBpmFromTempoCatalog(targets, pendingMap, candidates, stats, onProgress) {
  if (!GSB_KEY || !pendingMap?.size) return 0;
  let stamped = 0;
  for (const bpm of cadenceBpmCenters(targets)) {
    if (typeof onProgress === "function") {
      try { onProgress({ phase: "bpm", detail: `Tempo catalog ${bpm} BPM`, tempoBpm: bpm }); } catch (_) {}
    }
    const songs = await gsbSongsAtBpm(bpm, 120);
    for (const song of songs) {
      const key = normTrackKey(song.artist, song.title);
      const pending = pendingMap.get(key);
      if (!pending) continue;
      pendingMap.delete(key);
      candidates.push({ ...pending, bpm: song.tempo });
      cacheBpm(pending.artist, pending.title, song.tempo, {
        source: "getsong:tempo-stamp",
        confidence: 0.9,
        isrc: pending.isrc || null,
        trackId: pending.id || pending.ref || null,
        service: pending.service || null,
      });
      stamped++;
      if (stats) { stats.hit++; stats.tried++; }
    }
  }
  saveBpmCache();
  return stamped;
}
/**
 * When seed-graph coverage is still short, pull GetSongBPM songs at the needed
 * tempos and resolve them on the streaming service — fills gaps where per-track
 * search never found a BPM for your seeds.
 *
 * resolveArtist(name) → id|null
 * fetchArtistTracks(name, id) → [{id,ref,title,artist,durationSec}, ...]
 */
async function ingestTempoCatalogTracks({
  targets, candidates, seenIds, stats, onProgress,
  resolveArtist, fetchArtistTracks, maxArtists = 40, maxTracks = 200,
}) {
  if (!GSB_KEY || typeof resolveArtist !== "function" || typeof fetchArtistTracks !== "function") return 0;
  const centers = cadenceBpmCenters(targets);
  if (!centers.length) return 0;
  const byArtist = new Map(); // artistLower → { name, songs: Map<titleKey, tempo> }
  for (const bpm of centers) {
    if (typeof onProgress === "function") {
      try { onProgress({ phase: "bpm", detail: `Importing ${bpm} BPM catalog…`, tempoBpm: bpm }); } catch (_) {}
    }
    for (const song of await gsbSongsAtBpm(bpm, 100)) {
      const a = String(song.artist || "").trim();
      if (!a) continue;
      const ak = a.toLowerCase();
      if (!byArtist.has(ak)) byArtist.set(ak, { name: a, songs: new Map() });
      const tk = cleanMusicToken(song.title);
      if (tk && !byArtist.get(ak).songs.has(tk)) byArtist.get(ak).songs.set(tk, song.tempo);
    }
  }
  let added = 0;
  let artistsTried = 0;
  for (const { name, songs } of byArtist.values()) {
    if (added >= maxTracks || artistsTried >= maxArtists) break;
    artistsTried++;
    let id = null;
    try { id = await resolveArtist(name); } catch (_) { continue; }
    if (!id) continue;
    let tracks = [];
    try { tracks = await fetchArtistTracks(name, id); } catch (_) { continue; }
    for (const t of tracks || []) {
      if (added >= maxTracks) break;
      const tid = String(t.ref || t.id || "");
      if (!tid || seenIds.has(tid)) continue;
      const tk = cleanMusicToken(t.title);
      const tempo = tk && songs.get(tk);
      if (!(tempo > 0)) continue;
      seenIds.add(tid);
      if (t.id && t.id !== tid) seenIds.add(String(t.id));
      candidates.push({ ...t, bpm: tempo, bpmSource: "tempo-ingest" });
      cacheBpm(t.artist || name, t.title, tempo, {
        source: "getsong:tempo-ingest",
        confidence: 0.86,
        isrc: t.isrc || null,
        trackId: t.id || t.ref || null,
        service: t.service || null,
      });
      added++;
      if (stats) { stats.hit++; stats.tried++; }
    }
  }
  saveBpmCache();
  return added;
}

/* ---- Last.fm (similar artists) ---- */
async function lastfmSimilar(name, limit = 40) {
  if (!LASTFM_KEY || !name) return [];
  try {
    const u = `${LASTFM_BASE}?method=artist.getsimilar&artist=${encodeURIComponent(name)}&api_key=${LASTFM_KEY}&format=json&limit=${limit}&autocorrect=1`;
    const r = await fetch(u, { headers: { Accept: "application/json" } });
    if (!r.ok) return [];
    const j = await r.json();
    return (j.similarartists?.artist || [])
      .map((a) => ({
        name: a?.name || "",
        match: Math.max(0, parseFloat(a?.match) || 0),
      }))
      .filter((a) => a.name);
  } catch (_) { return []; }
}
/** Top artists for a genre/tag (Last.fm) — used for genre-overlap fan-out. */
async function lastfmTagTopArtists(tag, limit = 40) {
  const t = String(tag || "").trim();
  if (!LASTFM_KEY || !t) return [];
  try {
    const u = `${LASTFM_BASE}?method=tag.getTopArtists&tag=${encodeURIComponent(t)}&api_key=${LASTFM_KEY}&format=json&limit=${limit}`;
    const r = await fetch(u, { headers: { Accept: "application/json" } });
    if (!r.ok) return [];
    const j = await r.json();
    const raw = j.topartists?.artist;
    const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
    return list.map((a) => a?.name).filter(Boolean);
  } catch (_) { return []; }
}
/** Rank genres from candidate tracks; seed artists count heavier. */
function topGenresFromCandidates(candidates, { artistIds = [], artistNames = [], limit = 8 } = {}) {
  const seedIds = new Set((artistIds || []).map(String).filter(Boolean));
  const seedNames = new Set((artistNames || []).map((n) => String(n || "").toLowerCase()).filter(Boolean));
  const counts = new Map();
  for (const t of candidates || []) {
    const genres = Array.isArray(t?.genres) ? t.genres : [];
    if (!genres.length) continue;
    const fromSeed =
      (t.artistId && seedIds.has(String(t.artistId))) ||
      (t.artist && seedNames.has(String(t.artist).toLowerCase()));
    const w = fromSeed ? 3 : 1;
    for (const g of genres) {
      const key = String(g || "").trim().toLowerCase();
      if (!key || key.length < 2) continue;
      counts.set(key, (counts.get(key) || 0) + w);
    }
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([g]) => g);
}
/**
 * Priority queue helpers: keep pending artists ordered by multi-source vote score
 * (similar-to-many-seeds + Last.fm match + genre fan-out).
 */
function makeScoredQueue() {
  const order = [];
  const seen = new Set();
  const score = new Map();
  const label = new Map();
  return {
    size: () => order.length,
    has: (key) => seen.has(key),
    add(key, pts = 1, displayName = null) {
      const k = String(key || "").trim();
      if (!k) return false;
      score.set(k, (score.get(k) || 0) + Math.max(0, +pts || 0));
      if (displayName) label.set(k, displayName);
      if (seen.has(k)) return false;
      seen.add(k);
      order.push(k);
      return true;
    },
    take(n, { skip } = {}) {
      const skipFn = typeof skip === "function" ? skip : () => false;
      order.sort((a, b) => (score.get(b) || 0) - (score.get(a) || 0));
      const out = [];
      const keep = [];
      for (const k of order) {
        if (out.length < n && !skipFn(k)) {
          out.push(k);
          seen.delete(k);
        } else if (!skipFn(k)) {
          keep.push(k);
        } else {
          seen.delete(k);
          score.delete(k);
          label.delete(k);
        }
      }
      order.length = 0;
      for (const k of keep) order.push(k);
      return out.map((k) => ({ key: k, name: label.get(k) || k, score: score.get(k) || 0 }));
    },
  };
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
  let genres = included.filter((x) => x.type === "genres" && gids.includes(x.id)).map((x) => x.attributes?.name).filter(Boolean);
  // Fall back to any genres attached to the primary artist in this payload.
  if (!genres.length && artistId) {
    const art = included.find((x) => x.type === "artists" && String(x.id) === String(artistId));
    const ag = (art?.relationships?.genres?.data || []).map((g) => g.id);
    genres = included.filter((x) => x.type === "genres" && ag.includes(x.id)).map((x) => x.attributes?.name).filter(Boolean);
  }
  const bpm = parseCatalogBpm(a.bpm);
  return {
    id: res.id,
    ref: res.id,
    service: "tidal",
    title: a.title || "?",
    artist,
    artistId: artistId ? String(artistId) : null,
    isrc: a.isrc || null,
    bpm,
    bpmSource: bpm != null ? "tidal" : undefined,
    durationSec: isoToSec(a.duration),
    genres: [...new Set(genres)].slice(0, 4),
  };
}
const tidalArtistGenreCache = {};
async function tidalArtistGenres(id) {
  const aid = id != null ? String(id) : "";
  if (!aid) return [];
  if (aid in tidalArtistGenreCache) return tidalArtistGenreCache[aid];
  for (const getter of [tapiCatalog, tapi]) {
    try {
      const j = await getter(`/artists/${encodeURIComponent(aid)}?countryCode=${COUNTRY}&include=genres`);
      const gids = (j?.data?.relationships?.genres?.data || []).map((g) => g.id);
      const named = (j.included || [])
        .filter((x) => x?.type === "genres" && (gids.length ? gids.includes(x.id) : true))
        .map((x) => x.attributes?.name)
        .filter(Boolean);
      const out = [...new Set(named)].slice(0, 4);
      tidalArtistGenreCache[aid] = out;
      return out;
    } catch (_) { /* try next auth */ }
  }
  tidalArtistGenreCache[aid] = [];
  return [];
}
async function tidalHydrateGenres(tracks) {
  const list = Array.isArray(tracks) ? tracks : [];
  const need = list.filter((t) => t && t.artistId && !(Array.isArray(t.genres) && t.genres.length));
  if (!need.length) return list;
  await mapLimit(need, 6, async (t) => {
    const g = await tidalArtistGenres(t.artistId);
    if (g.length) t.genres = g.slice(0, 4);
  });
  return list;
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
 * Tidal retired free-text /searchResults/{query} (400 INVALID_RESOURCE_ID).
 * Prefer /searchSuggestions with filter[query] + include=directHits, then path form.
 */
async function tidalFetchSearchSuggestions(query, { debugLog = null } = {}) {
  const q = (query || "").trim();
  if (!q) return null;
  const enc = encodeURIComponent(q);
  const paths = [
    `/searchSuggestions?filter[query]=${enc}&countryCode=${COUNTRY}&include=directHits`,
    `/searchSuggestions/${enc}?countryCode=${COUNTRY}&include=directHits`,
  ];
  const getters = [];
  try { await accessToken("tidal"); getters.push({ kind: "user", get: tapi }); } catch (e) {
    if (debugLog) debugLog.push({ via: "suggestions/auth-user", error: String(e.message || e) });
  }
  getters.push({ kind: "catalog", get: tapiCatalog });
  for (const { kind, get } of getters) {
    for (const path of paths) {
      try {
        const payload = await get(path);
        if (debugLog) {
          const hits = payload?.data?.relationships?.directHits?.data || [];
          debugLog.push({
            via: `suggestions/${kind}`,
            path: path.slice(0, 80),
            directHits: Array.isArray(hits) ? hits.length : 0,
            included: Array.isArray(payload?.included) ? payload.included.length : 0,
          });
        }
        if (payload) return payload;
      } catch (e) {
        if (debugLog) debugLog.push({ via: `suggestions/${kind}`, path: path.slice(0, 80), error: String(e.message || e) });
      }
    }
  }
  return null;
}
function tidalSuggestionRefs(payload, type) {
  const out = [];
  const seen = new Set();
  const push = (id) => {
    const sid = id != null ? String(id) : "";
    if (!sid || seen.has(sid)) return;
    seen.add(sid);
    out.push(sid);
  };
  const fromRel = payload?.data?.relationships?.directHits?.data;
  if (Array.isArray(fromRel)) {
    for (const ref of fromRel) {
      if (ref?.type === type && ref.id != null) push(ref.id);
    }
  }
  for (const x of payload?.included || []) {
    if (x?.type === type && x.id != null) push(x.id);
  }
  return out;
}
async function tidalArtistsFromSuggestions(payload) {
  if (!payload) return [];
  const extracted = tidalExtractArtists(payload);
  const fromHits = tidalSuggestionRefs(payload, "artists").map((id) => {
    const hit = extracted.find((a) => String(a.id) === String(id));
    return hit || { id: String(id), name: "" };
  });
  const merged = [];
  for (const a of [...fromHits, ...extracted]) {
    if (!a?.id) continue;
    if (!merged.some((x) => String(x.id) === String(a.id))) merged.push({ id: String(a.id), name: a.name || "" });
  }
  return (await tidalHydrateArtistNames(merged)).filter((a) => a.name && a.name !== "?");
}
async function tidalTracksFromSuggestions(payload) {
  if (!payload) return [];
  const included = payload.included || [];
  const byId = new Map();
  for (const x of included) {
    if (x?.type === "tracks" && x.id) byId.set(String(x.id), tidalMapTrack(x, included));
  }
  const ids = tidalSuggestionRefs(payload, "tracks");
  const missing = ids.filter((id) => !byId.has(String(id)));
  if (missing.length) {
    for (let i = 0; i < missing.length; i += 20) {
      const chunk = missing.slice(i, i + 20);
      try {
        const j = await tapiCatalog(`/tracks?filter[id]=${chunk.join(",")}&countryCode=${COUNTRY}&include=artists,genres`);
        for (const tr of j.data || []) {
          if (tr?.type === "tracks" && tr.id) byId.set(String(tr.id), tidalMapTrack(tr, j.included || []));
        }
      } catch (_) {
        try {
          const j = await tapi(`/tracks?filter[id]=${chunk.join(",")}&countryCode=${COUNTRY}&include=artists,genres`);
          for (const tr of j.data || []) {
            if (tr?.type === "tracks" && tr.id) byId.set(String(tr.id), tidalMapTrack(tr, j.included || []));
          }
        } catch (_) {}
      }
    }
  }
  const ordered = [];
  for (const id of ids) {
    const t = byId.get(String(id));
    if (t) ordered.push(t);
  }
  if (!ordered.length) return [...byId.values()].slice(0, 10);
  const out = ordered.slice(0, 10);
  await tidalHydrateGenres(out);
  return out;
}
/** Accept pasted Tidal track URLs or bare numeric ids when query looks like an id. */
function tidalParseTrackRef(q) {
  const s = String(q || "").trim();
  if (!s) return null;
  const url = s.match(/(?:tidal\.com|listen\.tidal\.com)\/(?:browse\/)?track\/(\d+)/i);
  if (url) return url[1];
  return null;
}
async function tidalTrackById(id) {
  if (!id) return null;
  for (const getter of [tapiCatalog, tapi]) {
    try {
      const j = await getter(`/tracks/${encodeURIComponent(id)}?countryCode=${COUNTRY}&include=artists,genres`);
      const tr = j?.data;
      if (tr?.type === "tracks" && tr.id) return tidalMapTrack(tr, j.included || []);
    } catch (_) {}
  }
  try {
    const j = await tapiCatalog(`/tracks?filter[id]=${encodeURIComponent(id)}&countryCode=${COUNTRY}&include=artists,genres`);
    const tr = (j.data || []).find((x) => x?.type === "tracks" && String(x.id) === String(id));
    if (tr) return tidalMapTrack(tr, j.included || []);
  } catch (_) {}
  return null;
}
/**
 * Artist search: pasted URL → searchSuggestions → handle → external names → legacy searchResults.
 */
async function tidalSearchArtists(q, { debug = false } = {}) {
  const query = (q || "").trim();
  if (query.length < 1) return debug ? { artists: [], debug: [], build: "search-suggestions-72cc" } : [];
  const enc = encodeURIComponent(query);
  const debugLog = [];
  const done = (artists) => (debug ? { artists, debug: debugLog, build: "search-suggestions-72cc" } : artists);
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

  // 1) Native searchSuggestions (replacement for retired searchResults)
  try {
    const suggestions = await tidalFetchSearchSuggestions(query, { debugLog: debug ? debugLog : null });
    const fromSug = await tidalArtistsFromSuggestions(suggestions);
    if (debug) debugLog.push({ via: "suggestions/artists", named: fromSug.length, sample: fromSug.slice(0, 3) });
    if (fromSug.length) return done(fromSug.slice(0, 10));
  } catch (e) {
    if (debug) debugLog.push({ via: "suggestions/artists", error: String(e.message || e) });
  }

  // 2) Direct handle for the typed query (fast path for names like "underoath")
  try {
    const byHandle = await tidalArtistsByHandle(query);
    if (debug) debugLog.push({ via: "handle/query", handle: tidalNameToHandle(query), named: byHandle.length, sample: byHandle.slice(0, 3) });
    if (byHandle.length) return done(byHandle);
  } catch (e) {
    if (debug) debugLog.push({ via: "handle/query", error: String(e.message || e) });
  }

  // 3) External fuzzy name search → resolve each candidate on Tidal by handle
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

  // 4) Legacy searchResults last — usually 400 now, kept for auto-recovery if Tidal restores it
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
async function tidalSearchTracks(q, { debug = false } = {}) {
  const query = (q || "").trim();
  if (query.length < 1) return debug ? { tracks: [], debug: [], build: "search-suggestions-72cc" } : [];
  const debugLog = [];
  const done = (tracks) => (debug ? { tracks, debug: debugLog, build: "search-suggestions-72cc" } : tracks);

  const directId = tidalParseTrackRef(query);
  if (directId) {
    try {
      const t = await tidalTrackById(directId);
      if (debug) debugLog.push({ via: "direct-track-id", id: directId, named: t ? 1 : 0, sample: t ? [t] : [] });
      if (t) return done([t]);
    } catch (e) {
      if (debug) debugLog.push({ via: "direct-track-id", error: String(e.message || e) });
    }
  }

  try {
    const suggestions = await tidalFetchSearchSuggestions(query, { debugLog: debug ? debugLog : null });
    const tracks = await tidalTracksFromSuggestions(suggestions);
    if (debug) debugLog.push({ via: "suggestions/tracks", named: tracks.length, sample: tracks.slice(0, 3) });
    if (tracks.length) return done(tracks);
  } catch (e) {
    if (debug) debugLog.push({ via: "suggestions/tracks", error: String(e.message || e) });
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
const POOL_BUDGET_MS = 25 * 60 * 1000; // keep expanding related artists until cadences can fill
/** Shared expansion caps — deep BFS until the playlist can be packed. */
const POOL_ARTIST_CAP = 2000;
const POOL_TRACK_CAP = 10000;
const POOL_MAX_LEVELS = 80;
const POOL_RING_BATCH = 90; // artists fetched per ring from the pending queue
async function tidalPool(seeds, targetSec = 0, targets = null, onProgress = null, ctrl = null) {
  if (!GSB_KEY && !FREQBLOG_KEY) throw new Error("GETSONGBPM_API_KEY not set — add it to credentials.txt");
  const started = Date.now();
  const hardStop = () => Date.now() - started > POOL_BUDGET_MS;
  const userStop = () => !!(ctrl && typeof ctrl.shouldStop === "function" && ctrl.shouldStop());
  const stopNow = () => hardStop() || userStop();
  let lastSnapLen = -1;
  const snap = () => {
    if (!ctrl || typeof ctrl.onSnapshot !== "function") return;
    if (candidates.length === lastSnapLen) return;
    lastSnapLen = candidates.length;
    try { ctrl.onSnapshot(candidates); } catch (_) {}
  };
  const seedList = seeds.map((s) => (typeof s === "string" ? { id: s, name: "" } : s));
  const seedIds = seedList.map((s) => String(s.id));
  const seedNames = seedList.map((s) => s.name).filter(Boolean);
  const ARTIST_CAP = POOL_ARTIST_CAP, TRACK_CAP = POOL_TRACK_CAP, MAX_LEVELS = POOL_MAX_LEVELS;
  const knownNames = new Map(); seedNames.forEach((n) => knownNames.set(n.toLowerCase(), n));
  const doneArtists = new Set(), allTrackIds = new Set(), candidates = [];
  const idToName = new Map();
  const pendingByKey = new Map(); // catalog tracks still missing BPM
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
        pendingBpm: pendingByKey.size,
        matchedSec: Math.round(need.matched || 0),
        needSec: Math.round(need.fillNeed || need.matchNeed || 0),
        canFill: !!need.canFill,
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
    // Prefetch GetSongBPM artist pages once per name (bulk tempos).
    await mapLimit([...byArtist.keys()].filter((k) => k && k !== "?"), 4, (name) => gsbArtistTempoMap(name));
    const queues = [...byArtist.values()];
    const order = [];
    let guard = 0;
    while (queues.some((q) => q.length) && guard++ < meta.length + 5) {
      for (const q of queues) if (q.length) order.push(q.shift());
    }
    let i = 0;
    while (i < order.length) {
      if (!finishAll && poolNeed(targetSec, targets, candidates).canFill) break;
      if (!finishAll && stopNow()) break;
      if (finishAll && userStop()) break;
      // Seed phase: keep going past the soft ceiling only briefly; still stop on absolute overrun.
      if (finishAll && Date.now() - started > POOL_BUDGET_MS * 1.5) break;
      const batch = order.slice(i, i + 24);
      i += batch.length;
      report("bpm", { detail, bpmDone: i, bpmTotal: order.length });
      const enriched = await mapLimit(batch, 10, async (t) => {
        bpmStats.tried++;
        const b = await bpmForTrack(t).catch(() => null);
        if (b) bpmStats.hit++;
        return { track: t, bpm: b };
      });
      for (const row of enriched) {
        if (!row) continue;
        const t = row.track;
        if (row.bpm) {
          candidates.push({ ...t, bpm: row.bpm });
          pendingByKey.delete(normTrackKey(t.artist, t.title));
        } else {
          const key = normTrackKey(t.artist, t.title);
          if (key !== "|" && !pendingByKey.has(key)) pendingByKey.set(key, t);
        }
        if (t.artist) {
          const k = t.artist.toLowerCase();
          if (!knownNames.has(k)) knownNames.set(k, t.artist);
        }
      }
      snap();
      if (cacheDirty) saveBpmCache();
      if (userStop()) break;
    }
  }
  async function fillFromTempoCatalog(detail) {
    if (userStop()) return 0;
    if (!pendingByKey.size || poolNeed(targetSec, targets, candidates).canFill) return 0;
    report("bpm", { detail });
    const n = await stampBpmFromTempoCatalog(
      targets,
      pendingByKey,
      candidates,
      bpmStats,
      (p) => report("bpm", { detail: p.detail || detail, tempoBpm: p.tempoBpm }),
    );
    report("bpm", { detail: `Tempo catalog stamped ${n} tracks`, stamped: n });
    snap();
    return n;
  }
  async function ingestTempoFill(detail) {
    if (userStop()) return 0;
    if (poolNeed(targetSec, targets, candidates).canFill) return 0;
    report("bpm", { detail });
    const n = await ingestTempoCatalogTracks({
      targets,
      candidates,
      seenIds: allTrackIds,
      stats: bpmStats,
      onProgress: (p) => report("bpm", { detail: p.detail || detail, tempoBpm: p.tempoBpm }),
      resolveArtist: async (name) => tidalResolveArtist(name),
      fetchArtistTracks: async (name, id) => {
        const ids = await tidalArtistTrackIds(id, 40);
        const out = [];
        for (let i = 0; i < ids.length; i += 20) {
          const chunk = ids.slice(i, i + 20);
          try {
            const t = await tapi(`/tracks?filter[id]=${chunk.join(",")}&countryCode=${COUNTRY}&include=artists,genres`);
            for (const tr of t.data || []) out.push(tidalMapTrack(tr, t.included));
          } catch (_) {}
        }
        await tidalHydrateGenres(out);
        return out;
      },
      maxArtists: 50,
      maxTracks: 250,
    });
    report("bpm", { detail: `Imported ${n} tempo-matched tracks`, stamped: n });
    snap();
    return n;
  }
  async function fetchArtists(ids, seedWeight, detail) {
    if (userStop()) return [];
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
      if (!seedWeight && stopNow()) break;
      if (userStop()) break;
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
    await tidalHydrateGenres(meta);
    await enrichBpm(meta, detail, { finishAll: !!seedWeight });
    snap();
    return fresh;
  }
  async function tidalSimilarIds(ids, detail) {
    const votes = new Map(); // id -> score
    const fresh = ids.filter(Boolean);
    if (!fresh.length) return [];
    report("similar", { detail, pendingArtists: fresh.length });
    await mapLimit(fresh, 6, async (aid) => {
      try {
        const j = await tapi(`/artists/${aid}/relationships/similarArtists?countryCode=${COUNTRY}`);
        const rows = j.data || [];
        rows.forEach((d, i) => {
          if (!d?.id) return;
          const id = String(d.id);
          // Earlier in Tidal's similar list = stronger; each seed vote adds.
          const pts = 1 + Math.max(0, (30 - i) / 30);
          votes.set(id, (votes.get(id) || 0) + pts);
        });
      } catch (_) {}
    });
    return [...votes.entries()]
      .map(([id, score]) => ({ id, score }))
      .sort((a, b) => b.score - a.score);
  }

  report("start", { detail: "Gathering songs from seed artists" });
  await fetchArtists(seedIds, true, "seed artists");
  await fillFromTempoCatalog("Stamping tempos from BPM catalog");

  // Scored BFS queues — multi-seed votes + Last.fm match + genre fan-out.
  const idQueue = makeScoredQueue();
  const nameQueue = makeScoredQueue();
  const genreTried = new Set();
  const enqueueId = (id, pts = 1, name = null) => {
    const s = String(id || "");
    if (!s || doneArtists.has(s)) return;
    if (name) idToName.set(s, name);
    idQueue.add(s, pts, name || idToName.get(s) || s);
  };
  const enqueueName = (nm, pts = 1) => {
    const name = String(nm || "").trim();
    if (!name) return;
    const k = name.toLowerCase();
    knownNames.set(k, name);
    nameQueue.add(k, pts, name);
  };
  let expandFromIds = [...seedIds];
  let expandFromNames = [...seedNames];

  for (let level = 1; level <= MAX_LEVELS; level++) {
    currentLevel = level;
    const need = poolNeed(targetSec, targets, candidates);
    // Stop as soon as every cadence band can pack the run — don't grind for extra buffer.
    if (need.canFill) break;
    if (stopNow()) break;
    if (doneArtists.size >= ARTIST_CAP || allTrackIds.size >= TRACK_CAP) break;

    const shortNote = (need.byCadence || []).filter((c) => c.short > 30)
      .map((c) => `${c.cadence}spm`).slice(0, 3).join(", ");
    report("expand", {
      detail: shortNote
        ? `Ring ${level} · still short on ${shortNote} · queue ${idQueue.size() + nameQueue.size()}`
        : `Gathering songs · related artists ring ${level} · queue ${idQueue.size() + nameQueue.size()}`,
      level,
      pendingQueue: idQueue.size() + nameQueue.size(),
    });

    // Discover related artists from the artists we just fetched (or seeds on ring 1).
    if (expandFromIds.length && doneArtists.size < ARTIST_CAP) {
      const sim = await tidalSimilarIds(expandFromIds.slice(0, 100), `Tidal similar · ring ${level}`);
      for (const row of sim) enqueueId(row.id, row.score);
    }
    if (LASTFM_KEY && expandFromNames.length && doneArtists.size < ARTIST_CAP) {
      const lists = await mapLimit(
        expandFromNames.slice(0, 80),
        8,
        (n) => lastfmSimilar(n, level <= 2 ? 50 : 35),
      );
      for (const rows of lists) {
        for (const row of rows || []) {
          // match is 0..1; bump so a strong Last.fm hit can beat a weak single Tidal vote
          const pts = 0.6 + Math.min(1.4, (row.match || 0) * 1.4);
          enqueueName(row.name, pts);
        }
      }
    }

    // Genre-overlap fan-out: after seeds (ring 1) and again mid-run if still short.
    if (LASTFM_KEY && doneArtists.size < ARTIST_CAP && (level === 1 || (level >= 4 && level % 4 === 0))) {
      const genres = topGenresFromCandidates(candidates, {
        artistIds: level === 1 ? seedIds : [],
        artistNames: level === 1 ? seedNames : [],
        limit: level === 1 ? 6 : 4,
      }).filter((g) => !genreTried.has(g));
      for (const g of genres) genreTried.add(g);
      if (genres.length) {
        report("similar", {
          detail: `Genre fan-out · ${genres.slice(0, 3).join(", ")}${genres.length > 3 ? "…" : ""}`,
          level,
        });
        const tagLists = await mapLimit(genres, 4, (g) => lastfmTagTopArtists(g, level <= 2 ? 35 : 25));
        for (const names of tagLists) {
          for (const nm of names || []) enqueueName(nm, 0.85);
        }
      }
    }

    // Resolve a chunk of pending Last.fm names → Tidal ids (into the id queue).
    if (nameQueue.size() && doneArtists.size < ARTIST_CAP) {
      const nameChunk = nameQueue.take(50);
      report("resolve", { detail: `resolving ${nameChunk.length} artists · ring ${level}`, level });
      const resolved = await mapLimit(nameChunk, 8, async (row) => {
        const id = await tidalResolveArtist(row.name);
        if (id) {
          idToName.set(String(id), row.name);
          return { id: String(id), score: row.score, name: row.name };
        }
        return null;
      });
      for (const row of resolved) {
        if (row?.id) enqueueId(row.id, row.score, row.name);
      }
    }

    // Fetch the next batch from the scored id queue (highest votes first).
    const batchRows = idQueue.take(POOL_RING_BATCH, { skip: (id) => doneArtists.has(id) });
    const batch = batchRows.map((r) => r.key);

    if (!batch.length) {
      if (!nameQueue.size() && !idQueue.size()) break;
      // Names still pending resolution — continue without a fetch this ring.
      expandFromIds = [];
      expandFromNames = [];
      continue;
    }

    await fetchArtists(batch, false, `related artists · ring ${level}`);
    if (level === 1 || level % 2 === 0) await fillFromTempoCatalog(`Tempo catalog after ring ${level}`);
    // If still badly short after a few rings, pull tempo-catalog artists mid-run.
    if (level >= 3 && level % 3 === 0 && !poolNeed(targetSec, targets, candidates).canFill) {
      await ingestTempoFill(`Importing target-tempo songs · ring ${level}`);
    }

    expandFromIds = batch;
    expandFromNames = batch.map((id) => idToName.get(id)).filter(Boolean);

    if (poolNeed(targetSec, targets, candidates).canFill) break;
  }

  await fillFromTempoCatalog("Final tempo catalog pass");
  if (!userStop() && !poolNeed(targetSec, targets, candidates).canFill) {
    await ingestTempoFill("Importing songs at your target tempos");
  }
  // One more related-artist push if still short and we have queue/budget left.
  if (!userStop() && !poolNeed(targetSec, targets, candidates).canFill && !hardStop() && idQueue.size() && doneArtists.size < ARTIST_CAP) {
    const extra = idQueue.take(POOL_RING_BATCH, { skip: (id) => doneArtists.has(id) }).map((r) => r.key);
    if (extra.length) {
      report("expand", { detail: `Final expansion · ${extra.length} more related artists`, level: currentLevel + 1 });
      await fetchArtists(extra, false, "final related artists");
      await fillFromTempoCatalog("Tempo catalog after final expansion");
    }
  }
  saveBpmCache();
  snap();
  const finalNeed = poolNeed(targetSec, targets, candidates);
  report("done", {
    detail: userStop()
      ? "Stopped — building playlist from songs so far"
      : finalNeed.canFill
        ? "Song pool ready — building playlist"
        : hardStop()
          ? "Time ceiling reached — building playlist with what we have"
          : "Expanded as far as caps allow — building playlist",
    bpmHit: bpmStats.hit,
    bpmTried: bpmStats.tried,
    stopped: userStop(),
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
/** Spotify supports genre:"..." artist search — useful fan-out when Last.fm tags map cleanly. */
async function spotifyArtistsByGenre(genre, limit = 20) {
  const g = String(genre || "").trim();
  if (!g) return [];
  try {
    const q = `genre:"${g}"`;
    const j = await sapi(`/search?q=${encodeURIComponent(q)}&type=artist&limit=${Math.min(50, Math.max(1, limit))}`);
    return (j.artists?.items || [])
      .filter((a) => a?.id && a?.name)
      .map((a) => ({ id: String(a.id), name: a.name }));
  } catch (_) {
    return [];
  }
}
async function spotifySearchTracks(q) {
  const query = (q || "").trim();
  if (!query) return [];
  // Spotify open URLs / URIs
  const uri = query.match(/spotify:track:([A-Za-z0-9]+)/i);
  const url = query.match(/open\.spotify\.com\/track\/([A-Za-z0-9]+)/i);
  const id = uri?.[1] || url?.[1] || null;
  if (id) {
    try {
      const t = await sapi(`/tracks/${encodeURIComponent(id)}`);
      return t?.id ? [spotifyMapTrack(t)] : [];
    } catch (_) { /* fall through to text search */ }
  }
  const j = await sapi(`/search?q=${encodeURIComponent(query)}&type=track&limit=10`);
  return (j.tracks?.items || []).map((t) => spotifyMapTrack(t));
}
const spotifyArtistIdCache = {};
async function spotifyResolveArtist(name) {
  const k = (name || "").toLowerCase();
  if (k in spotifyArtistIdCache) return spotifyArtistIdCache[k];
  let id = null; try { const a = await spotifySearchArtists(name); id = a[0]?.id || null; } catch (_) {}
  spotifyArtistIdCache[k] = id; return id;
}
function spotifyMapTrack(t, fallbackArtist, genres = null) {
  return {
    id: t.id,
    ref: t.uri,
    service: "spotify",
    title: t.name,
    artist: t.artists?.[0]?.name || fallbackArtist || "?",
    artistId: t.artists?.[0]?.id || null,
    isrc: t.external_ids?.isrc || null,
    durationSec: Math.round((t.duration_ms || 210000) / 1000),
    genres: Array.isArray(genres) ? genres.slice(0, 4) : [],
  };
}
const spotifyGenreCache = {};
async function spotifyHydrateArtistGenres(tracks) {
  const list = Array.isArray(tracks) ? tracks : [];
  const ids = [...new Set(list.map((t) => t?.artistId).filter(Boolean))];
  const missing = ids.filter((id) => !(id in spotifyGenreCache));
  for (let i = 0; i < missing.length; i += 50) {
    const chunk = missing.slice(i, i + 50);
    try {
      const j = await sapi(`/artists?ids=${chunk.join(",")}`);
      for (const a of j.artists || []) {
        if (a?.id) spotifyGenreCache[a.id] = Array.isArray(a.genres) ? a.genres.slice(0, 6) : [];
      }
      for (const id of chunk) if (!(id in spotifyGenreCache)) spotifyGenreCache[id] = [];
    } catch (_) {
      for (const id of chunk) if (!(id in spotifyGenreCache)) spotifyGenreCache[id] = [];
    }
  }
  for (const t of list) {
    if (!t) continue;
    if (Array.isArray(t.genres) && t.genres.length) continue;
    const g = t.artistId ? spotifyGenreCache[t.artistId] : null;
    if (Array.isArray(g) && g.length) t.genres = g.slice(0, 4);
  }
  return list;
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
  const out = [...byRef.values()].slice(0, limit);
  await spotifyHydrateArtistGenres(out);
  return out;
}
async function spotifyPool(seeds, targetSec = 0, targets = null, onProgress = null, ctrl = null) {
  if (!GSB_KEY && !FREQBLOG_KEY) throw new Error("GETSONGBPM_API_KEY not set — add it to credentials.txt");
  const started = Date.now();
  const hardStop = () => Date.now() - started > POOL_BUDGET_MS;
  const userStop = () => !!(ctrl && typeof ctrl.shouldStop === "function" && ctrl.shouldStop());
  const stopNow = () => hardStop() || userStop();
  let lastSnapLen = -1;
  const snap = () => {
    if (!ctrl || typeof ctrl.onSnapshot !== "function") return;
    if (candidates.length === lastSnapLen) return;
    lastSnapLen = candidates.length;
    try { ctrl.onSnapshot(candidates); } catch (_) {}
  };
  const seedList = seeds.map((s) => (typeof s === "string" ? { name: s } : s));
  const seedNames = seedList.map((s) => s.name).filter(Boolean);
  const ARTIST_CAP = POOL_ARTIST_CAP, TRACK_CAP = POOL_TRACK_CAP, MAX_LEVELS = POOL_MAX_LEVELS;
  const knownNames = new Map(); seedNames.forEach((n) => knownNames.set(n.toLowerCase(), n));
  const seedNameSet = new Set(seedNames.map((n) => n.toLowerCase()));
  const seedIdByName = new Map(); for (const s of seedList) if (s.name && s.id) seedIdByName.set(String(s.name).toLowerCase(), String(s.id));
  const doneNames = new Set(), seenRef = new Set(), candidates = [];
  const pendingByKey = new Map();
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
        pendingBpm: pendingByKey.size,
        matchedSec: Math.round(need.matched || 0),
        needSec: Math.round(need.fillNeed || need.matchNeed || 0),
        canFill: !!need.canFill,
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
    await mapLimit([...byArtist.keys()].filter((k) => k && k !== "?"), 4, (name) => gsbArtistTempoMap(name));
    const queues = [...byArtist.values()];
    const order = [];
    let guard = 0;
    while (queues.some((q) => q.length) && guard++ < toBpm.length + 5) {
      for (const q of queues) if (q.length) order.push(q.shift());
    }
    let i = 0;
    while (i < order.length) {
      if (!finishAll && poolNeed(targetSec, targets, candidates).canFill) break;
      if (!finishAll && stopNow()) break;
      if (finishAll && userStop()) break;
      if (finishAll && Date.now() - started > POOL_BUDGET_MS * 1.5) break;
      const batch = order.slice(i, i + 24);
      i += batch.length;
      report("bpm", { detail, bpmDone: i, bpmTotal: order.length });
      const enriched = await mapLimit(batch, 10, async (t) => {
        bpmStats.tried++;
        const b = await bpmForTrack(t).catch(() => null);
        if (b) bpmStats.hit++;
        return { track: t, bpm: b };
      });
      for (const row of enriched) {
        if (!row) continue;
        const t = row.track;
        if (row.bpm) {
          candidates.push({ ...t, bpm: row.bpm });
          pendingByKey.delete(normTrackKey(t.artist, t.title));
        } else {
          const key = normTrackKey(t.artist, t.title);
          if (key !== "|" && !pendingByKey.has(key)) pendingByKey.set(key, t);
        }
      }
      snap();
      if (cacheDirty) saveBpmCache();
      if (userStop()) break;
    }
  }
  async function fillFromTempoCatalog(detail) {
    if (userStop()) return 0;
    if (!pendingByKey.size || poolNeed(targetSec, targets, candidates).canFill) return 0;
    report("bpm", { detail });
    const n = await stampBpmFromTempoCatalog(
      targets,
      pendingByKey,
      candidates,
      bpmStats,
      (p) => report("bpm", { detail: p.detail || detail, tempoBpm: p.tempoBpm }),
    );
    report("bpm", { detail: `Tempo catalog stamped ${n} tracks`, stamped: n });
    snap();
    return n;
  }
  async function ingestTempoFill(detail) {
    if (userStop()) return 0;
    if (poolNeed(targetSec, targets, candidates).canFill) return 0;
    report("bpm", { detail });
    const n = await ingestTempoCatalogTracks({
      targets,
      candidates,
      seenIds: seenRef,
      stats: bpmStats,
      onProgress: (p) => report("bpm", { detail: p.detail || detail, tempoBpm: p.tempoBpm }),
      resolveArtist: async (name) => spotifyResolveArtist(name),
      fetchArtistTracks: async (name, id) => spotifyArtistTracks(name, id, 40),
      maxArtists: 50,
      maxTracks: 250,
    });
    report("bpm", { detail: `Imported ${n} tempo-matched tracks`, stamped: n });
    snap();
    return n;
  }
  async function fetchNames(names, detail, { seedWeight = false } = {}) {
    if (userStop()) return [];
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
    snap();
    return fresh;
  }

  report("start", { detail: "Gathering songs from seed artists" });
  await fetchNames(seedNames, "seed artists", { seedWeight: true });
  await fillFromTempoCatalog("Stamping tempos from BPM catalog");

  const nameQueue = makeScoredQueue();
  const genreTried = new Set();
  const enqueueName = (nm, pts = 1) => {
    const name = String(nm || "").trim();
    if (!name) return;
    const k = name.toLowerCase();
    if (doneNames.has(k)) return;
    knownNames.set(k, name);
    nameQueue.add(k, pts, name);
  };
  let expandFrom = [...seedNames];

  for (let level = 1; level <= MAX_LEVELS; level++) {
    currentLevel = level;
    const need = poolNeed(targetSec, targets, candidates);
    if (need.canFill) break;
    if (stopNow()) break;
    if (doneNames.size >= ARTIST_CAP || candidates.length >= TRACK_CAP) break;

    const shortNote = (need.byCadence || []).filter((c) => c.short > 30)
      .map((c) => `${c.cadence}spm`).slice(0, 3).join(", ");
    report("expand", {
      detail: shortNote
        ? `Ring ${level} · still short on ${shortNote} · queue ${nameQueue.size()}`
        : `Gathering songs · related artists ring ${level} · queue ${nameQueue.size()}`,
      level,
      pendingQueue: nameQueue.size(),
    });

    if (LASTFM_KEY && expandFrom.length) {
      const lists = await mapLimit(
        expandFrom.slice(0, 80),
        8,
        (n) => lastfmSimilar(n, level <= 2 ? 50 : 35),
      );
      for (const rows of lists) {
        for (const row of rows || []) {
          const pts = 0.6 + Math.min(1.4, (row.match || 0) * 1.4);
          enqueueName(row.name, pts);
        }
      }
    }

    // Genre-overlap fan-out via Last.fm tags + Spotify genre search.
    if (doneNames.size < ARTIST_CAP && (level === 1 || (level >= 4 && level % 4 === 0))) {
      const genres = topGenresFromCandidates(candidates, {
        artistIds: level === 1 ? [...seedIdByName.values()] : [],
        artistNames: level === 1 ? seedNames : [],
        limit: level === 1 ? 6 : 4,
      }).filter((g) => !genreTried.has(g));
      for (const g of genres) genreTried.add(g);
      if (genres.length) {
        report("similar", {
          detail: `Genre fan-out · ${genres.slice(0, 3).join(", ")}${genres.length > 3 ? "…" : ""}`,
          level,
        });
        if (LASTFM_KEY) {
          const tagLists = await mapLimit(genres, 4, (g) => lastfmTagTopArtists(g, level <= 2 ? 35 : 25));
          for (const names of tagLists) {
            for (const nm of names || []) enqueueName(nm, 0.85);
          }
        }
        const spotLists = await mapLimit(genres, 3, (g) => spotifyArtistsByGenre(g, 15));
        for (const arts of spotLists) {
          for (const a of arts || []) {
            if (a?.name) {
              if (a.id) seedIdByName.set(a.name.toLowerCase(), a.id);
              enqueueName(a.name, 1.0);
            }
          }
        }
      }
    }

    const batch = nameQueue
      .take(POOL_RING_BATCH, { skip: (k) => doneNames.has(k) })
      .map((r) => r.name);
    if (!batch.length) break;

    await fetchNames(batch, `related artists · ring ${level}`);
    if (userStop()) break;
    if (level === 1 || level % 2 === 0) await fillFromTempoCatalog(`Tempo catalog after ring ${level}`);
    if (level >= 3 && level % 3 === 0 && !poolNeed(targetSec, targets, candidates).canFill) {
      await ingestTempoFill(`Importing target-tempo songs · ring ${level}`);
    }
    expandFrom = batch;
    if (poolNeed(targetSec, targets, candidates).canFill) break;
  }

  await fillFromTempoCatalog("Final tempo catalog pass");
  if (!userStop() && !poolNeed(targetSec, targets, candidates).canFill) {
    await ingestTempoFill("Importing songs at your target tempos");
  }
  if (!userStop() && !poolNeed(targetSec, targets, candidates).canFill && !hardStop() && nameQueue.size() && doneNames.size < ARTIST_CAP) {
    const extra = nameQueue
      .take(POOL_RING_BATCH, { skip: (k) => doneNames.has(k) })
      .map((r) => r.name);
    if (extra.length) {
      report("expand", { detail: `Final expansion · ${extra.length} more related artists`, level: currentLevel + 1 });
      await fetchNames(extra, "final related artists");
      await fillFromTempoCatalog("Tempo catalog after final expansion");
    }
  }
  saveBpmCache();
  snap();
  const finalNeed = poolNeed(targetSec, targets, candidates);
  report("done", {
    detail: userStop()
      ? "Stopped — building playlist from songs so far"
      : finalNeed.canFill
        ? "Song pool ready — building playlist"
        : hardStop()
          ? "Time ceiling reached — building playlist with what we have"
          : "Expanded as far as caps allow — building playlist",
    bpmHit: bpmStats.hit,
    bpmTried: bpmStats.tried,
    stopped: userStop(),
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
const searchTracks = (svc, q) => (svc === "spotify" ? spotifySearchTracks(q) : tidalSearchTracks(q));
const buildPool = (svc, seeds, targetSec, targets, onProgress, ctrl) => (svc === "spotify" ? spotifyPool(seeds, targetSec, targets, onProgress, ctrl) : tidalPool(seeds, targetSec, targets, onProgress, ctrl));
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
        bpmKey: !!GSB_KEY, freqblogKey: !!FREQBLOG_KEY, lastfmKey: !!LASTFM_KEY, acousticbrainz: true, country: COUNTRY,
        bpmCacheEntries: Object.keys(bpmCache).filter((k) => !k.startsWith("norm:")).length,
        bpmCacheMax: BPM_CACHE_MAX_TRACKS,
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
    if (url.pathname === "/api/search-tracks") {
      const svc = url.searchParams.get("service") || "tidal";
      const q = url.searchParams.get("q") || "";
      if (!q.trim()) return sendJSON(res, 400, { error: "empty query" });
      if (svc === "tidal" && url.searchParams.get("debug") === "1") {
        return sendJSON(res, 200, await tidalSearchTracks(q, { debug: true }));
      }
      return sendJSON(res, 200, await searchTracks(svc, q));
    }
    if (url.pathname === "/api/track-bpm" && req.method === "POST") {
      const body = await readBody(req);
      const track = {
        service: body?.service || "tidal",
        artist: body?.artist || "",
        title: body?.title || "",
        isrc: body?.isrc || null,
        id: body?.trackId || body?.id || null,
        ref: body?.ref || body?.trackId || body?.id || null,
      };
      if (!track.title && !track.artist) return sendJSON(res, 400, { error: "artist/title required" });
      const bpm = await bpmForTrack(track);
      return sendJSON(res, 200, { ok: true, bpm, artist: track.artist, title: track.title });
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
      let cancelled = false;
      req.on("close", () => { cancelled = true; });
      let lastSnapAt = 0;
      let lastSnapN = -1;
      try {
        const candidates = await buildPool(
          svc,
          seeds,
          +body.targetSec || 0,
          targets,
          (p) => send({ type: "progress", ...p }),
          {
            shouldStop: () => cancelled,
            onSnapshot: (cands) => {
              const n = Array.isArray(cands) ? cands.length : 0;
              const now = Date.now();
              if (n === lastSnapN && now - lastSnapAt < 2500) return;
              if (n === lastSnapN) return;
              if (now - lastSnapAt < 1000 && n - lastSnapN < 8) return;
              lastSnapAt = now;
              lastSnapN = n;
              send({ type: "snapshot", candidates: cands, stopped: cancelled });
            },
          },
        );
        const bpmHit = candidates.filter((t) => t.bpm != null).length;
        send({
          type: "done",
          candidates,
          stopped: cancelled,
          meta: {
            poolSize: candidates.length,
            bpmHit,
            bpmMiss: candidates.length - bpmHit,
            bpmHitRate: candidates.length ? bpmHit / candidates.length : 0,
            stopped: cancelled,
          },
        });
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
    if (url.pathname === "/api/bpm-correct" && req.method === "POST") {
      const body = await readBody(req);
      const bpm = Math.round(Number(body?.bpm));
      if (!(bpm > 0 && bpm <= 260)) return sendJSON(res, 400, { error: "bpm must be 1..260" });
      const artist = String(body?.artist || "").trim();
      const title = String(body?.title || "").trim();
      if (!artist || !title) return sendJSON(res, 400, { error: "artist and title are required" });
      const isrc = body?.isrc ? String(body.isrc).trim().toUpperCase() : null;
      const trackId = body?.trackId ? String(body.trackId).trim() : null;
      const service = body?.service ? String(body.service).trim().toLowerCase() : null;
      cacheBpm(artist, title, bpm, { source: "user-corrected", confidence: 1, isrc, trackId, service, user: true });
      saveBpmCache();
      return sendJSON(res, 200, { ok: true, bpm, artist, title, isrc, trackId, service });
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
      const rows = await lastfmSimilar(artist, 20);
      return sendJSON(res, 200, {
        similarCount: rows.length,
        similar: rows.slice(0, 15).map((r) => r.name),
        scored: rows.slice(0, 15),
      });
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
  console.log(`jirun bridge on http://localhost:${PORT}/  (tidal ${have("tidal")}, spotify ${have("spotify")}, bpm ${GSB_KEY ? "✓" : "—"}, freqblog ${FREQBLOG_KEY ? "✓" : "—"}, lastfm ${LASTFM_KEY ? "✓" : "—"}, acousticbrainz ✓)`);
  console.log(`Redirect URI to register in both dashboards: ${REDIRECT_URI}`);
});
// Pool builds can run longer than Node's default 5-minute request timeout.
server.requestTimeout = 0;
server.headersTimeout = 0;
server.timeout = 0;
