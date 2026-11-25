import "dotenv/config";
import express from "express";
import crypto from "crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";

const or = (a, b) => (a ? a : b);
const app = express();
app.use(express.json());

const PORT = or(process.env.PORT, 8080);
const PUBLIC_URL = or(
  process.env.PUBLIC_URL,
  `http://localhost:${PORT}`,
).replace(/\/$/, "");
const COUNTRY_CODE = or(process.env.TIDAL_COUNTRY_CODE, "SG");
const ALLOW_DASH_HIRES = process.env.ALLOW_DASH_HIRES !== "false";

const AUTH_MODE = or(process.env.AUTH_MODE, "off").toLowerCase();
const AUTH_ISSUER = or(
  process.env.BITCHORD_AUTH_ISSUER,
  "https://bitchord-auth.kushagrasingh.in",
).replace(/\/$/, "");

let jwks = null;
if (AUTH_MODE !== "off") {
  jwks = createRemoteJWKSet(new URL(`${AUTH_ISSUER}/.well-known/jwks.json`), {
    cacheMaxAge: 3600000,
  });
}

async function verifyBitChordAuth(req, res, next) {
  if (AUTH_MODE === "off") return next();
  const authHeader = or(req.headers["authorization"], "");
  const customHeader = or(req.headers["x-bitchord-auth"], "");
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : String(customHeader).trim();

  if (!token) {
    if (AUTH_MODE === "enforce") {
      return res
        .status(401)
        .json({ error: "Missing BitChord Addon Auth token" });
    }
    return next();
  }

  try {
    const { payload } = await jwtVerify(token, jwks, { issuer: AUTH_ISSUER });
    req.bitchordAuth = payload;
    return next();
  } catch (err) {
    console.warn(`[bitchord-auth] Gagal verifikasi: ${err.message}`);
    if (AUTH_MODE === "enforce") {
      return res
        .status(401)
        .json({ error: "Invalid BitChord Addon Auth token" });
    }
    return next();
  }
}

const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

// --- Auto-Refresh Token Tidal ---
let tidalAccessToken = or(process.env.TIDAL_ACCESS_TOKEN, "").trim();
let tokenExpiresAt = tidalAccessToken ? Date.now() + 300000 : 0;
let refreshPromise = null;

async function getTidalAccessToken(forceRefresh = false) {
  if (
    !forceRefresh &&
    tidalAccessToken &&
    Date.now() < tokenExpiresAt - 60000
  ) {
    return tidalAccessToken;
  }

  const refreshToken = or(process.env.TIDAL_REFRESH_TOKEN, "").trim();
  if (!refreshToken) {
    if (!tidalAccessToken) {
      throw new Error(
        "TIDAL_ACCESS_TOKEN atau TIDAL_REFRESH_TOKEN belum diisi di Environment Variables",
      );
    }
    return tidalAccessToken;
  }

  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    const clientId = or(process.env.TIDAL_CLIENT_ID, "6BDSRdpK9hqEBTgU").trim();
    const clientSecret = or(process.env.TIDAL_CLIENT_SECRET, "").trim();

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      scope: "r_usr w_usr w_sub",
    });

    const headers = {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": USER_AGENT,
    };

    if (clientSecret) {
      const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
        "base64",
      );
      headers.Authorization = `Basic ${basicAuth}`;
    } else {
      body.set("client_id", clientId);
    }

    const resp = await fetch("https://auth.tidal.com/v1/oauth2/token", {
      method: "POST",
      headers,
      body,
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Gagal refresh token Tidal (${resp.status}): ${text}`);
    }

    const data = await resp.json();
    tidalAccessToken = data.access_token;
    tokenExpiresAt = Date.now() + or(data.expires_in, 3600) * 1000;
    console.log(
      `[tidal-auth] Token berhasil diperbarui (berlaku ${or(data.expires_in, 3600)} detik)`,
    );
    return tidalAccessToken;
  })();

  try {
    return await refreshPromise;
  } finally {
    refreshPromise = null;
  }
}

async function tidalFetch(path, params = {}, retried = false) {
  const token = await getTidalAccessToken(retried);

  const url = new URL(`https://api.tidal.com/v1${path}`);
  url.searchParams.set("countryCode", COUNTRY_CODE);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  }

  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "User-Agent": USER_AGENT,
    },
  });

  if (resp.status === 401 && !retried && process.env.TIDAL_REFRESH_TOKEN) {
    console.warn("[tidal-auth] Token 401, mencoba auto-refresh...");
    return tidalFetch(path, params, true);
  }

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Tidal API error ${resp.status}: ${errText}`);
  }
  return resp.json();
}

function buildCoverUrl(coverUuid, size = "640x640") {
  if (!coverUuid) return null;
  return `https://resources.tidal.com/images/${coverUuid.replace(/-/g, "/")}/${size}.jpg`;
}

function mapTidalTrack(item) {
  const artists = item.artists?.length
    ? item.artists.map((a) => a.name).join(", ")
    : or(item.artist?.name, "Unknown Artist");

  return {
    id: String(item.id),
    title: item.version ? `${item.title} (${item.version})` : item.title,
    artist: artists,
    album: or(item.album?.title, ""),
    duration: Number(or(item.duration, 0)),
    isrc: or(item.isrc, undefined),
    artwork: buildCoverUrl(item.album?.cover),
  };
}

function mapBitChordQualityToTidal(qualityParam) {
  const q = String(or(qualityParam, "hires")).toLowerCase().trim();
  if (q.includes("atmos") || q.includes("dolby")) return "DOLBY_ATMOS";
  if (q === "low" || q === "128" || q === "96") return "LOW";
  if (q === "high" || q === "320") return "HIGH";
  if (q === "lossless" || q === "16bit") return "LOSSLESS";
  return ALLOW_DASH_HIRES ? "HI_RES_LOSSLESS" : "LOSSLESS";
}

const dashCache = new Map();
function storeDashManifest(mpdXml) {
  const token = crypto.randomBytes(16).toString("hex");
  dashCache.set(token, { xml: mpdXml, expiresAt: Date.now() + 600000 });
  for (const [k, v] of dashCache.entries()) {
    if (v.expiresAt < Date.now()) dashCache.delete(k);
  }
  return token;
}

app.get("/", (req, res) => {
  const manifestUrl = `${PUBLIC_URL}/manifest.json`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Layz Hi-Res — BitChord Addon</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #07090f;
      --card: rgba(17, 22, 34, 0.72);
      --border: rgba(255, 255, 255, 0.08);
      --text: #f3f6fc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --accent2: #818cf8;
      --green: #22c55e;
    }
    body {
      font-family: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      position: relative;
      overflow-x: hidden;
    }
    body::before, body::after {
      content: "";
      position: fixed;
      width: 480px;
      height: 480px;
      border-radius: 50%;
      filter: blur(120px);
      opacity: 0.22;
      z-index: -1;
      pointer-events: none;
    }
    body::before {
      top: -120px;
      left: -100px;
      background: radial-gradient(circle, #38bdf8, transparent 70%);
    }
    body::after {
      bottom: -140px;
      right: -100px;
      background: radial-gradient(circle, #818cf8, transparent 70%);
    }
    .card {
      width: 100%;
      max-width: 540px;
      background: var(--card);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--border);
      border-radius: 24px;
      padding: 36px 32px;
      box-shadow: 0 24px 64px rgba(0, 0, 0, 0.55);
    }
    .top-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
    }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      font-weight: 600;
      color: #86efac;
      background: rgba(34, 197, 94, 0.12);
      border: 1px solid rgba(34, 197, 94, 0.25);
      padding: 6px 12px;
      border-radius: 999px;
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 10px var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.45; transform: scale(0.85); }
    }
    .version {
      font-family: "JetBrains Mono", monospace;
      font-size: 12px;
      color: var(--muted);
      background: rgba(255, 255, 255, 0.05);
      padding: 5px 10px;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 14px;
    }
    .logo {
      width: 52px;
      height: 52px;
      border-radius: 16px;
      background: linear-gradient(135deg, #38bdf8, #818cf8);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 10px 28px rgba(56, 189, 248, 0.28);
      flex-shrink: 0;
    }
    h1 {
      font-size: 28px;
      font-weight: 800;
      letter-spacing: -0.03em;
      background: linear-gradient(90deg, #ffffff, #bae6fd);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .subtitle {
      font-size: 14px;
      color: var(--muted);
      line-height: 1.6;
      margin-bottom: 26px;
    }
    .section-label {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-bottom: 10px;
    }
    .url-box {
      display: flex;
      align-items: center;
      gap: 8px;
      background: rgba(7, 9, 15, 0.75);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 8px 8px 8px 14px;
      margin-bottom: 24px;
    }
    .url-text {
      font-family: "JetBrains Mono", monospace;
      font-size: 12.5px;
      color: #e2e8f0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      flex: 1;
    }
    .btn-copy {
      background: linear-gradient(135deg, #38bdf8, #6366f1);
      color: #fff;
      border: none;
      border-radius: 10px;
      padding: 9px 16px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.15s ease, opacity 0.15s ease;
      flex-shrink: 0;
    }
    .btn-copy:hover { opacity: 0.92; transform: translateY(-1px); }
    .btn-copy:active { transform: translateY(0); }
    .btn-copy.copied { background: linear-gradient(135deg, #22c55e, #16a34a); }
    .badges {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
      margin-bottom: 26px;
    }
    .badge {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 14px;
    }
    .badge-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text);
      margin-bottom: 2px;
    }
    .badge-sub {
      font-size: 11.5px;
      color: var(--muted);
    }
    .footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-top: 18px;
      border-top: 1px solid var(--border);
      font-size: 12.5px;
      color: var(--muted);
    }
    .footer a {
      color: var(--accent);
      text-decoration: none;
      font-weight: 500;
    }
    .footer a:hover { text-decoration: underline; }
    @media (max-width: 480px) {
      .card { padding: 26px 20px; }
      .badges { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="top-bar">
      <div class="status"><span class="dot"></span> Server Online</div>
      <span class="version">v1.0.2</span>
    </div>

    <div class="brand">
      <div class="logo">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M9 18V5l12-2v13"></path>
          <circle cx="6" cy="18" r="3"></circle>
          <circle cx="18" cy="16" r="3"></circle>
        </svg>
      </div>
      <div>
        <h1>Layz Hi-Res</h1>
      </div>
    </div>

    <p class="subtitle">
      Custom audio streaming addon untuk <strong>BitChord</strong>. Mendukung streaming Hi-Res 24-bit FLAC, Lossless 16-bit, hingga Dolby Atmos secara otomatis.
    </p>

    <div class="section-label">Manifest URL</div>
    <div class="url-box">
      <span class="url-text" id="manifestUrl">${manifestUrl}</span>
      <button class="btn-copy" id="copyBtn" onclick="copyManifest()">Copy URL</button>
    </div>

    <div class="section-label">Supported Audio Tiers</div>
    <div class="badges">
      <div class="badge">
        <div class="badge-title">Hi-Res Lossless</div>
        <div class="badge-sub">FLAC · 24-bit / up to 192 kHz</div>
      </div>
      <div class="badge">
        <div class="badge-title">Lossless</div>
        <div class="badge-sub">FLAC · 16-bit / 44.1 kHz</div>
      </div>
      <div class="badge">
        <div class="badge-title">Dolby Atmos</div>
        <div class="badge-sub">E-AC-3 JOC · Spatial Audio</div>
      </div>
      <div class="badge">
        <div class="badge-title">High &amp; Low</div>
        <div class="badge-sub">AAC · 320 kbps &amp; 128 kbps</div>
      </div>
    </div>

    <div class="footer">
      <span>Paste URL di menu Sources BitChord</span>
      <a href="/manifest.json" target="_blank">Lihat manifest.json &rarr;</a>
    </div>
  </main>

  <script>
    function copyManifest() {
      var text = document.getElementById("manifestUrl").innerText;
      var btn = document.getElementById("copyBtn");
      navigator.clipboard.writeText(text).then(function() {
        btn.innerText = "Copied!";
        btn.classList.add("copied");
        setTimeout(function() {
          btn.innerText = "Copy URL";
          btn.classList.remove("copied");
        }, 2000);
      });
    }
  </script>
</body>
</html>`);
});

app.get("/manifest.json", (req, res) => {
  res.json({
    id: "id.web.layyyz.lzaddon",
    name: "Layz Hi-Res",
    version: "1.0.2",
    description: "Hi-Res & Lossless addon for BitChord",
    resources: ["search", "stream", "isrc"],
    bitchordAuth: AUTH_MODE === "enforce",
    settings: [
      {
        key: "quality",
        type: "select",
        options: [
          {
            label: "Hi-Res Lossless (24-bit)",
            value: "hires",
          },
          {
            label: "Lossless (16-bit)",
            value: "lossless",
          },
          {
            label: "Dolby Atmos",
            value: "atmos",
          },
          {
            label: "High · 320 kbps",
            value: "high",
          },
          {
            label: "Low · 128 kbps",
            value: "low",
          },
        ],
      },
    ],
  });
});

app.get("/search", verifyBitChordAuth, async (req, res) => {
  try {
    const query = String(or(req.query.q, "")).trim();
    const limit = Math.min(Number(or(req.query.limit, 15)), 50);
    if (!query) return res.json({ tracks: [] });

    const data = await tidalFetch("/search/tracks", { query, limit });
    res.json({ tracks: or(data.items, []).map(mapTidalTrack) });
  } catch (err) {
    console.error("[/search]", err.message);
    res.status(500).json({ tracks: [], error: err.message });
  }
});

app.get("/isrc/:code", verifyBitChordAuth, async (req, res) => {
  try {
    const isrc = String(or(req.params.code, "")).trim().toUpperCase();
    if (!isrc) return res.json({ tracks: [] });

    const data = await tidalFetch("/search/tracks", { query: isrc, limit: 10 });
    const exactMatches = or(data.items, [])
      .filter((t) => or(t.isrc, "").toUpperCase() === isrc)
      .map(mapTidalTrack);

    res.json({ tracks: exactMatches });
  } catch (err) {
    console.error("[/isrc]", err.message);
    res.status(500).json({ tracks: [], error: err.message });
  }
});

app.get("/stream/:id", verifyBitChordAuth, async (req, res) => {
  try {
    let trackId = req.params.id;
    const requestedQuality = mapBitChordQualityToTidal(req.query.quality);
    let audioQuality = requestedQuality;

    // Jika pilih Dolby Atmos, cek apakah track ini Atmos; jika bukan, cari versi Atmos-nya
    if (requestedQuality === "DOLBY_ATMOS") {
      try {
        const trackInfo = await tidalFetch(`/tracks/${trackId}`);
        const isAlreadyAtmos = trackInfo.audioModes?.includes("DOLBY_ATMOS");
        if (!isAlreadyAtmos && trackInfo.title) {
          const artistName = or(trackInfo.artist?.name, "");
          const searchRes = await tidalFetch("/search/tracks", {
            query: `${trackInfo.title} ${artistName}`.trim(),
            limit: 15,
          });
          const atmosMatch = or(searchRes.items, []).find(
            (t) =>
              t.audioModes?.includes("DOLBY_ATMOS") &&
              t.title?.toLowerCase() === trackInfo.title?.toLowerCase(),
          );
          if (atmosMatch) trackId = String(atmosMatch.id);
        }
      } catch (e) {
        console.warn("[atmos-lookup]", e.message);
      }
      audioQuality = "LOSSLESS";
    }

    let playback = await tidalFetch(
      `/tracks/${trackId}/playbackinfopostpaywall`,
      {
        playbackmode: "STREAM",
        assetpresentation: "FULL",
        audioquality: audioQuality,
      },
    );

    if (
      playback.manifestMimeType === "application/dash+xml" &&
      !ALLOW_DASH_HIRES
    ) {
      playback = await tidalFetch(
        `/tracks/${trackId}/playbackinfopostpaywall`,
        {
          playbackmode: "STREAM",
          assetpresentation: "FULL",
          audioquality: "LOSSLESS",
        },
      );
    }

    const decodedManifest = Buffer.from(playback.manifest, "base64").toString(
      "utf-8",
    );
    const sampleRate = or(
      playback.sampleRate,
      playback.audioQuality === "HI_RES_LOSSLESS" ? 96000 : 44100,
    );
    const bitDepth = or(
      playback.bitDepth,
      playback.audioQuality === "HI_RES_LOSSLESS" ? 24 : 16,
    );

    if (playback.manifestMimeType === "application/vnd.tidal.bts") {
      const bts = JSON.parse(decodedManifest);
      const streamUrl = bts.urls?.[0];
      if (!streamUrl)
        return res.status(404).json({ error: "Stream URL kosong" });

      const codecs = or(bts.codecs, "").toLowerCase();
      const mime = or(bts.mimeType, "").toLowerCase();
      const isAtmos =
        playback.audioMode === "DOLBY_ATMOS" ||
        codecs.includes("ec-3") ||
        codecs.includes("eac3") ||
        codecs.includes("ac-4");
      const isFlac = codecs.includes("flac") || mime.includes("flac");
      const isLow = playback.audioQuality === "LOW";

      let codec = "aac";
      let format = "m4a";
      let bitrate = isLow ? 128 : 320;

      if (isAtmos) {
        codec = codecs.includes("ac-4") ? "ac4" : "eac3";
        format = "mp4";
        bitrate = 768;
      } else if (isFlac) {
        codec = "flac";
        format = "flac";
        bitrate = Math.round((sampleRate * bitDepth * 2) / 1000);
      }

      return res.json({
        url: streamUrl,
        codec,
        format,
        mimeType: or(bts.mimeType, isFlac ? "audio/flac" : "audio/mp4"),
        sampleRate,
        bitDepth: isFlac ? bitDepth : 16,
        bitrate,
        dolbyAtmos: isAtmos,
        encrypted: bts.encryptionType && bts.encryptionType !== "NONE",
      });
    }

    if (playback.manifestMimeType === "application/dash+xml") {
      const dashToken = storeDashManifest(decodedManifest);
      const isAtmosDash =
        playback.audioMode === "DOLBY_ATMOS" ||
        decodedManifest.includes("ec-3") ||
        decodedManifest.includes("ac-4");

      return res.json({
        url: `${PUBLIC_URL}/dash/${dashToken}.mpd`,
        codec: isAtmosDash ? "eac3" : "flac",
        format: isAtmosDash ? "mp4" : "flac",
        mimeType: "application/dash+xml",
        manifest: "dash",
        sampleRate,
        bitDepth: isAtmosDash ? 16 : bitDepth,
        bitrate: isAtmosDash
          ? 768
          : Math.round((sampleRate * bitDepth * 2) / 1000),
        dolbyAtmos: isAtmosDash,
        encrypted: false,
      });
    }

    return res
      .status(415)
      .json({ error: `Manifest tidak didukung: ${playback.manifestMimeType}` });
  } catch (err) {
    console.error("[/stream]", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get("/dash/:token.mpd", (req, res) => {
  const entry = dashCache.get(req.params.token);
  if (!entry) return res.status(404).send("Manifest expired");
  if (entry.expiresAt < Date.now())
    return res.status(404).send("Manifest expired");
  res.setHeader("Content-Type", "application/dash+xml");
  res.send(entry.xml);
});

app.listen(PORT, () => {
  console.log(`lz addon aktif di port ${PORT} (${PUBLIC_URL})`);
});
