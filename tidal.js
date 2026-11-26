import crypto from "crypto";
import {
  or,
  PUBLIC_URL,
  COUNTRY_CODE,
  ALLOW_DASH_HIRES,
  USER_AGENT,
} from "./config.js";

let tidalAccessToken = or(process.env.TIDAL_ACCESS_TOKEN, "").trim();
let tokenExpiresAt = tidalAccessToken ? Date.now() + 300000 : 0;
let refreshPromise = null;

export const dashCache = new Map();

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
        "TIDAL_ACCESS_TOKEN or TIDAL_REFRESH_TOKEN is not set in Environment Variables",
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
      throw new Error(
        `Failed to refresh Tidal token (${resp.status}): ${text}`,
      );
    }

    const data = await resp.json();
    tidalAccessToken = data.access_token;
    tokenExpiresAt = Date.now() + or(data.expires_in, 3600) * 1000;
    console.log(
      `[tidal-auth] Token refreshed (valid for ${or(data.expires_in, 3600)}s)`,
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
    console.warn("[tidal-auth] Token 401, attempting auto-refresh...");
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

function storeDashManifest(mpdXml) {
  const token = crypto.randomBytes(16).toString("hex");
  dashCache.set(token, { xml: mpdXml, expiresAt: Date.now() + 600000 });
  for (const [k, v] of dashCache.entries()) {
    if (v.expiresAt < Date.now()) dashCache.delete(k);
  }
  return token;
}

export async function handleSearch(req, res) {
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
}

export async function handleIsrc(req, res) {
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
}

export async function handleStream(req, res) {
  try {
    let trackId = req.params.id;
    const requestedQuality = mapBitChordQualityToTidal(req.query.quality);
    let audioQuality = requestedQuality;

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
        return res.status(404).json({ error: "Empty stream URL" });

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
      .json({ error: `Unsupported manifest: ${playback.manifestMimeType}` });
  } catch (err) {
    console.error("[/stream]", err.message);
    res.status(500).json({ error: err.message });
  }
}
