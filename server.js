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
  res.send("Layz addon is running!");
});

app.get("/manifest.json", (req, res) => {
  res.json({
    id: "id.web.layyyz.lzaddon",
    name: "Layz Hi-Res",
    version: "1.0.2",
    description: "Hi-Res & Lossless addon for BitChord",
    resources: ["search", "stream", "isrc"],
    qualities: ["hires", "lossless", "atmos", "high", "low"],
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
