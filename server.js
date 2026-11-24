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
const COUNTRY_CODE = or(process.env.TIDAL_COUNTRY_CODE, "ID");
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

let tidalAccessToken = or(process.env.TIDAL_ACCESS_TOKEN, "");
let tokenExpiresAt = 0;

async function getTidalToken() {
  if (tidalAccessToken && Date.now() < tokenExpiresAt - 60000) {
    return tidalAccessToken;
  }

  if (!process.env.TIDAL_REFRESH_TOKEN) {
    if (!tidalAccessToken) {
      throw new Error(
        "TIDAL_ACCESS_TOKEN atau TIDAL_REFRESH_TOKEN belum diisi",
      );
    }
    return tidalAccessToken;
  }

  const clientId = or(process.env.TIDAL_CLIENT_ID, "").trim();
  const clientSecret = or(process.env.TIDAL_CLIENT_SECRET, "").trim();
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64",
  );

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: process.env.TIDAL_REFRESH_TOKEN.trim(),
    scope: "r_usr w_usr w_sub",
  });

  const resp = await fetch("https://auth.tidal.com/v1/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
      "User-Agent": USER_AGENT,
    },
    body,
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Gagal refresh token Tidal (${resp.status}): ${text}`);
  }

  const data = await resp.json();
  tidalAccessToken = data.access_token;
  tokenExpiresAt = Date.now() + or(data.expires_in, 3600) * 1000;
  return tidalAccessToken;
}

async function tidalFetch(path, params = {}) {
  const token = await getTidalToken();
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
  const q = String(or(qualityParam, "lossless")).toLowerCase();
  if (["hi_res", "hires", "max"].includes(q)) {
    return ALLOW_DASH_HIRES ? "HI_RES_LOSSLESS" : "LOSSLESS";
  }
  if (["lossless", "flac"].includes(q)) return "LOSSLESS";
  if (q === "high") return "HIGH";
  if (["medium", "low"].includes(q)) return "LOW";
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
  res.send("lz addon is running!");
});

app.get("/manifest.json", (req, res) => {
  res.json({
    id: "id.web.layyyz.lzaddon",
    name: "lz addon",
    version: "1.0.0",
    description: "Tidal Hi-Res & Lossless addon for BitChord",
    resources: ["search", "stream", "isrc"],
    bitchordAuth: AUTH_MODE === "enforce",
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
    const trackId = req.params.id;
    let audioQuality = mapBitChordQualityToTidal(req.query.quality);

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

      const isFlac = or(bts.codecs, "").toLowerCase().includes("flac")
        ? true
        : or(bts.mimeType, "").includes("flac");

      return res.json({
        url: streamUrl,
        codec: isFlac ? "flac" : "aac",
        format: isFlac ? "flac" : "m4a",
        mimeType: or(bts.mimeType, isFlac ? "audio/flac" : "audio/mp4"),
        sampleRate,
        bitDepth: isFlac ? bitDepth : 16,
        bitrate: isFlac ? Math.round((sampleRate * bitDepth * 2) / 1000) : 320,
        encrypted: bts.encryptionType && bts.encryptionType !== "NONE",
      });
    }

    if (playback.manifestMimeType === "application/dash+xml") {
      const dashToken = storeDashManifest(decodedManifest);
      return res.json({
        url: `${PUBLIC_URL}/dash/${dashToken}.mpd`,
        codec: "flac",
        format: "flac",
        mimeType: "application/dash+xml",
        manifest: "dash",
        sampleRate,
        bitDepth,
        bitrate: Math.round((sampleRate * bitDepth * 2) / 1000),
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
