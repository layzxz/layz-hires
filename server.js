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

// --- Discord OAuth2 & Trial Config ---
const DISCORD_CLIENT_ID = or(process.env.DISCORD_CLIENT_ID, "").trim();
const DISCORD_CLIENT_SECRET = or(process.env.DISCORD_CLIENT_SECRET, "").trim();
const TOKEN_SECRET = or(
  process.env.TOKEN_SECRET,
  crypto.randomBytes(32).toString("hex"),
).trim();
const TRIAL_HOURS = Math.max(1, Number(or(process.env.TRIAL_HOURS, 24)) || 24);
const VIP_DISCORD_IDS = new Set(
  or(process.env.VIP_DISCORD_IDS, "")
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean),
);
const DISCORD_AUTH_ENABLED = Boolean(
  DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET,
);

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
    console.warn(`[bitchord-auth] Verification failed: ${err.message}`);
    if (AUTH_MODE === "enforce") {
      return res
        .status(401)
        .json({ error: "Invalid BitChord Addon Auth token" });
    }
    return next();
  }
}

// --- HMAC Token & Cookie Helpers ---
function signPayload(obj) {
  const data = Buffer.from(JSON.stringify(obj)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(data)
    .digest("base64url");
  return `${data}.${sig}`;
}

function verifySignedPayload(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  const expectedSig = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(data)
    .digest("base64url");

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;

  try {
    return JSON.parse(Buffer.from(data, "base64url").toString("utf-8"));
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// In-memory store to prevent non-VIP users from resetting trial timer on re-login
const issuedTrials = new Map(); // discordId -> { token, exp }
const oauthStates = new Map(); // state -> expiresAt

function requireUserToken(req, res, next) {
  const token = req.params.token;
  const payload = verifySignedPayload(token);
  if (!payload || !payload.uid) {
    return res.status(401).json({
      error: "Invalid token. Please log in with Discord on the dashboard.",
    });
  }

  const isVipNow = payload.vip || VIP_DISCORD_IDS.has(String(payload.uid));
  if (!isVipNow && payload.exp && Date.now() > payload.exp) {
    return res.status(403).json({
      error: `Your ${TRIAL_HOURS}-hour trial has expired. Contact the owner for permanent access.`,
    });
  }

  req.addonUser = payload;
  return next();
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

const dashCache = new Map();
function storeDashManifest(mpdXml) {
  const token = crypto.randomBytes(16).toString("hex");
  dashCache.set(token, { xml: mpdXml, expiresAt: Date.now() + 600000 });
  for (const [k, v] of dashCache.entries()) {
    if (v.expiresAt < Date.now()) dashCache.delete(k);
  }
  return token;
}

// --- Unique User Tracker (In-Memory) ---
const activeClients = new Map();

function trackAddonUser(req, res, next) {
  const key = req.addonUser?.uid
    ? `dc:${req.addonUser.uid}`
    : crypto
        .createHash("sha256")
        .update(
          req.headers["cf-connecting-ip"] ||
            String(req.headers["x-forwarded-for"] || "")
              .split(",")[0]
              .trim() ||
            req.socket?.remoteAddress ||
            "unknown",
        )
        .digest("hex")
        .slice(0, 12);

  activeClients.set(key, Date.now());
  next();
}

// --- Discord OAuth2 Routes ---
app.get("/auth/discord", (req, res) => {
  if (!DISCORD_AUTH_ENABLED) {
    return res
      .status(503)
      .send("Discord OAuth is not configured on this server.");
  }

  const state = crypto.randomBytes(16).toString("hex");
  oauthStates.set(state, Date.now() + 300000);
  for (const [k, exp] of oauthStates.entries()) {
    if (exp < Date.now()) oauthStates.delete(k);
  }

  const redirectUri = `${PUBLIC_URL}/auth/discord/callback`;
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "identify",
    state,
  });

  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

app.get("/auth/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || !oauthStates.has(String(state))) {
      return res.redirect("/?auth_error=invalid_state");
    }
    oauthStates.delete(String(state));

    const redirectUri = `${PUBLIC_URL}/auth/discord/callback`;
    const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: redirectUri,
      }),
    });

    if (!tokenResp.ok) {
      const txt = await tokenResp.text();
      console.error("[discord-oauth] Token error:", txt);
      return res.redirect("/?auth_error=token_failed");
    }

    const tokenData = await tokenResp.json();
    const userResp = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    if (!userResp.ok) {
      return res.redirect("/?auth_error=user_failed");
    }

    const dcUser = await userResp.json();
    const uid = String(dcUser.id);
    const username = dcUser.global_name || dcUser.username || "User";
    const avatarUrl = dcUser.avatar
      ? `https://cdn.discordapp.com/avatars/${uid}/${dcUser.avatar}.png?size=64`
      : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(uid) % 5n)}.png`;

    const isVip = VIP_DISCORD_IDS.has(uid);
    let addonToken;
    let exp = 0;

    if (isVip) {
      addonToken = signPayload({ uid, u: username, vip: true, exp: 0 });
    } else if (issuedTrials.has(uid)) {
      const existing = issuedTrials.get(uid);
      addonToken = existing.token;
      exp = existing.exp;
    } else {
      exp = Date.now() + TRIAL_HOURS * 3600 * 1000;
      addonToken = signPayload({ uid, u: username, vip: false, exp });
      issuedTrials.set(uid, { token: addonToken, exp });
    }

    const sessionCookie = signPayload({
      uid,
      u: username,
      av: avatarUrl,
      vip: isVip,
      t: addonToken,
      exp,
    });

    const isHttps = PUBLIC_URL.startsWith("https://");
    res.setHeader(
      "Set-Cookie",
      `lz_session=${encodeURIComponent(sessionCookie)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${isHttps ? "; Secure" : ""}`,
    );

    return res.redirect("/");
  } catch (err) {
    console.error("[discord-oauth]", err.message);
    return res.redirect("/?auth_error=server_error");
  }
});

app.get("/logout", (req, res) => {
  res.setHeader("Set-Cookie", "lz_session=; Path=/; HttpOnly; Max-Age=0");
  res.redirect("/");
});

app.get("/ping", (req, res) => {
  const now = Date.now();
  const activeNow = Array.from(activeClients.values()).filter(
    (ts) => now - ts < 15 * 60 * 1000,
  ).length;

  res.setHeader("Cache-Control", "no-store");
  res.json({
    status: "online",
    uptime: Math.floor(process.uptime()),
    uniqueUsers: activeClients.size,
    activeUsers: activeNow,
    timestamp: now,
  });
});

app.get("/", (req, res) => {
  const cookies = parseCookies(req);
  const session = cookies.lz_session
    ? verifySignedPayload(cookies.lz_session)
    : null;

  const isVip = session
    ? session.vip || VIP_DISCORD_IDS.has(session.uid)
    : false;
  const isExpired =
    session && !isVip && session.exp && Date.now() > session.exp;
  const manifestUrl = session
    ? `${PUBLIC_URL}/u/${session.t}/manifest.json`
    : `${PUBLIC_URL}/manifest.json`;

  let accessSectionHtml = "";
  if (!DISCORD_AUTH_ENABLED) {
    accessSectionHtml = `
    <div class="section-label">Manifest URL</div>
    <div class="url-box">
      <span class="url-text" id="manifestUrl">${manifestUrl}</span>
      <button class="btn-copy" id="copyBtn" onclick="copyManifest()">Copy URL</button>
    </div>`;
  } else if (!session) {
    accessSectionHtml = `
    <div class="section-label">Access Required · ${TRIAL_HOURS}h Trial</div>
    <a href="/auth/discord" class="btn-discord">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
        <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
      </svg>
      <span>Login with Discord to Generate URL</span>
    </a>`;
  } else {
    const badgeHtml = isVip
      ? `<span class="tier-pill vip">VIP · Permanent</span>`
      : isExpired
        ? `<span class="tier-pill expired">Trial Expired</span>`
        : `<span class="tier-pill trial" id="trialCountdown" data-exp="${session.exp}">Trial · Counting...</span>`;

    accessSectionHtml = `
    <div class="user-card">
      <div class="user-info">
        <img class="user-avatar" src="${escapeHtml(session.av)}" alt="Avatar" />
        <div>
          <div class="user-name">${escapeHtml(session.u)}</div>
          ${badgeHtml}
        </div>
      </div>
      <a href="/logout" class="btn-logout">Logout</a>
    </div>
    <div class="section-label">Personal Manifest URL</div>
    ${
      isExpired
        ? `<div class="expired-box">Your ${TRIAL_HOURS}-hour trial has ended. Contact the owner to upgrade to permanent access.</div>`
        : `<div class="url-box">
      <span class="url-text" id="manifestUrl">${manifestUrl}</span>
      <button class="btn-copy" id="copyBtn" onclick="copyManifest()">Copy URL</button>
    </div>`
    }`;
  }

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Layz Hi-Res — BitChord Addon</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0%25' stop-color='%2338bdf8'/%3E%3Cstop offset='100%25' stop-color='%23818cf8'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='64' height='64' rx='18' fill='url(%23g)'/%3E%3Cg fill='none' stroke='white' stroke-width='4.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M26 44V20l22-4v24'/%3E%3Ccircle cx='20' cy='44' r='6'/%3E%3Ccircle cx='42' cy='40' r='6'/%3E%3C/g%3E%3C/svg%3E" />
  <link href="https://fonts.cdnfonts.com/css/sf-pro-display" rel="stylesheet" />
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #030612;
      --text: #f8fafc;
      --muted: rgba(226, 232, 240, 0.68);
      --glass-border: rgba(255, 255, 255, 0.2);
      --glass-highlight: rgba(255, 255, 255, 0.42);
      --accent: #38bdf8;
      --green: #4ade80;
      --yellow: #facc15;
      --red: #f87171;
      --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", sans-serif;
      --font-mono: "SF Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    body {
      font-family: var(--font-sans);
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
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

    .liquid-bg {
      position: fixed;
      inset: 0;
      z-index: -1;
      overflow: hidden;
      pointer-events: none;
    }
    .orb {
      position: absolute;
      border-radius: 50%;
      filter: blur(85px);
      opacity: 0.55;
      mix-blend-mode: screen;
      animation: floatOrb 18s ease-in-out infinite alternate;
    }
    .orb-1 {
      width: 440px; height: 440px; top: -110px; left: -90px;
      background: radial-gradient(circle, #0ea5e9 0%, #2563eb 55%, transparent 75%);
    }
    .orb-2 {
      width: 480px; height: 480px; bottom: -140px; right: -100px;
      background: radial-gradient(circle, #a855f7 0%, #6366f1 55%, transparent 75%);
      animation-duration: 22s; animation-delay: -5s;
    }
    .orb-3 {
      width: 340px; height: 340px; top: 42%; left: 55%;
      background: radial-gradient(circle, #2dd4bf 0%, #0284c7 55%, transparent 75%);
      opacity: 0.35; animation-duration: 26s; animation-delay: -10s;
    }
    @keyframes floatOrb {
      0% { transform: translate(0, 0) scale(1); }
      50% { transform: translate(45px, -35px) scale(1.12); }
      100% { transform: translate(-35px, 40px) scale(0.95); }
    }

    .card {
      position: relative;
      width: 100%;
      max-width: 548px;
      border-radius: 30px;
      padding: 36px 32px;
      background: linear-gradient(
        135deg,
        rgba(255, 255, 255, 0.13) 0%,
        rgba(255, 255, 255, 0.04) 48%,
        rgba(255, 255, 255, 0.09) 100%
      );
      backdrop-filter: blur(36px) saturate(185%);
      -webkit-backdrop-filter: blur(36px) saturate(185%);
      border: 1px solid var(--glass-border);
      box-shadow:
        0 30px 70px rgba(0, 0, 0, 0.55),
        inset 0 1.5px 1px var(--glass-highlight),
        inset 0 -1px 2px rgba(0, 0, 0, 0.35),
        inset 1px 0 1px rgba(255, 255, 255, 0.16);
      overflow: hidden;
    }

    .card::before {
      content: "";
      position: absolute;
      inset: 0;
      border-radius: inherit;
      background: radial-gradient(
        420px circle at var(--mx, 50%) var(--my, 0%),
        rgba(255, 255, 255, 0.14),
        transparent 60%
      );
      pointer-events: none;
    }
    .card > * { position: relative; z-index: 1; }

    .top-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      font-weight: 600;
      color: #bbf7d0;
      background: linear-gradient(180deg, rgba(34, 197, 94, 0.22), rgba(34, 197, 94, 0.08));
      border: 1px solid rgba(134, 239, 172, 0.35);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.3);
      padding: 6px 14px;
      border-radius: 999px;
      backdrop-filter: blur(12px);
    }
    .status.offline {
      color: #fecaca;
      background: linear-gradient(180deg, rgba(239, 68, 68, 0.24), rgba(239, 68, 68, 0.08));
      border-color: rgba(252, 165, 165, 0.35);
    }
    .dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--green); box-shadow: 0 0 12px var(--green);
      animation: pulse 2s infinite;
    }
    .status.offline .dot { background: var(--red); box-shadow: 0 0 12px var(--red); animation: none; }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.45; transform: scale(0.85); }
    }

    .pill-mono {
      font-family: var(--font-mono);
      font-size: 12px;
      color: rgba(248, 250, 252, 0.85);
      background: rgba(255, 255, 255, 0.08);
      padding: 6px 12px;
      border-radius: 999px;
      border: 1px solid rgba(255, 255, 255, 0.18);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.28);
    }

    .brand { display: flex; align-items: center; gap: 16px; margin-bottom: 14px; }
    .logo {
      width: 54px; height: 54px; border-radius: 18px;
      background: linear-gradient(135deg, rgba(56, 189, 248, 0.85), rgba(129, 140, 248, 0.85));
      border: 1px solid rgba(255, 255, 255, 0.4);
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 12px 28px rgba(56, 189, 248, 0.35), inset 0 1.5px 1px rgba(255, 255, 255, 0.65);
      flex-shrink: 0;
    }
    h1 {
      font-size: 30px; font-weight: 700; letter-spacing: -0.025em;
      background: linear-gradient(180deg, #ffffff 10%, #bae6fd 100%);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .subtitle {
      font-size: 14.5px; color: var(--muted); line-height: 1.55;
      letter-spacing: -0.01em; margin-bottom: 24px;
    }
    .subtitle strong { color: #ffffff; font-weight: 600; }

    .metrics { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-bottom: 24px; }
    .metric {
      background: linear-gradient(160deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0.03));
      border: 1px solid rgba(255, 255, 255, 0.15);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.28);
      border-radius: 18px; padding: 13px 15px;
      transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric:hover { transform: translateY(-2px); border-color: rgba(255, 255, 255, 0.3); }
    .metric-label {
      font-size: 10.5px; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.06em; color: var(--muted); margin-bottom: 6px;
    }
    .metric-value { font-family: var(--font-mono); font-size: 15px; font-weight: 600; color: var(--text); }
    .metric-value.fast { color: var(--green); }
    .metric-value.medium { color: var(--yellow); }
    .metric-value.slow { color: var(--red); }

    .section-label {
      font-size: 11px; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.07em; color: var(--muted); margin-bottom: 10px;
    }

    /* Discord Login & User Profile */
    .btn-discord {
      display: flex; align-items: center; justify-content: center; gap: 10px;
      width: 100%; padding: 14px 20px; border-radius: 18px;
      background: linear-gradient(180deg, rgba(88, 101, 242, 0.95), rgba(71, 82, 196, 0.95));
      border: 1px solid rgba(255, 255, 255, 0.32);
      box-shadow: 0 10px 24px rgba(88, 101, 242, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.45);
      color: #fff; text-decoration: none; font-size: 14.5px; font-weight: 600;
      margin-bottom: 24px; transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .btn-discord:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 28px rgba(88, 101, 242, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.6);
    }

    .user-card {
      display: flex; align-items: center; justify-content: space-between; gap: 12px;
      background: rgba(255, 255, 255, 0.07);
      border: 1px solid rgba(255, 255, 255, 0.16);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.25);
      border-radius: 18px; padding: 12px 14px; margin-bottom: 18px;
    }
    .user-info { display: flex; align-items: center; gap: 12px; }
    .user-avatar {
      width: 38px; height: 38px; border-radius: 50%;
      border: 1.5px solid rgba(255, 255, 255, 0.35);
    }
    .user-name { font-size: 14px; font-weight: 600; color: #fff; margin-bottom: 3px; }
    .tier-pill {
      display: inline-block; font-size: 11px; font-weight: 600;
      padding: 2px 9px; border-radius: 999px; font-family: var(--font-mono);
    }
    .tier-pill.vip { background: rgba(56, 189, 248, 0.2); color: #7dd3fc; border: 1px solid rgba(125, 211, 252, 0.35); }
    .tier-pill.trial { background: rgba(250, 204, 21, 0.18); color: #fde047; border: 1px solid rgba(253, 224, 71, 0.35); }
    .tier-pill.expired { background: rgba(248, 113, 113, 0.2); color: #fca5a5; border: 1px solid rgba(252, 165, 165, 0.35); }
    .btn-logout {
      font-size: 12px; font-weight: 600; color: var(--muted); text-decoration: none;
      padding: 6px 12px; border-radius: 10px; background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.14); transition: background 0.15s ease, color 0.15s ease;
    }
    .btn-logout:hover { background: rgba(248, 113, 113, 0.2); color: #fecaca; }

    .expired-box {
      background: rgba(239, 68, 68, 0.14);
      border: 1px solid rgba(248, 113, 113, 0.35);
      border-radius: 16px; padding: 14px 16px; margin-bottom: 24px;
      font-size: 13px; color: #fecaca; line-height: 1.5;
    }

    .url-box {
      display: flex; align-items: center; gap: 8px;
      background: rgba(3, 6, 18, 0.42);
      border: 1px solid rgba(255, 255, 255, 0.16);
      box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.35), 0 1px 0 rgba(255, 255, 255, 0.12);
      border-radius: 18px; padding: 7px 7px 7px 16px; margin-bottom: 24px;
    }
    .url-text {
      font-family: var(--font-mono); font-size: 12.5px; color: #f1f5f9;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;
    }
    .btn-copy {
      font-family: var(--font-sans);
      background: linear-gradient(180deg, rgba(56, 189, 248, 0.95), rgba(99, 102, 241, 0.95));
      color: #fff; border: 1px solid rgba(255, 255, 255, 0.35);
      box-shadow: 0 6px 18px rgba(56, 189, 248, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.55);
      border-radius: 12px; padding: 9px 17px; font-size: 13px; font-weight: 600;
      cursor: pointer; transition: transform 0.15s ease, box-shadow 0.15s ease; flex-shrink: 0;
    }
    .btn-copy:hover { transform: translateY(-1px); }
    .btn-copy.copied { background: linear-gradient(180deg, #22c55e, #16a34a); }

    .howto-box {
      background: linear-gradient(155deg, rgba(255, 255, 255, 0.08), rgba(255, 255, 255, 0.02));
      border: 1px solid rgba(255, 255, 255, 0.14);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.22);
      border-radius: 16px;
      padding: 14px 16px;
      margin-bottom: 24px;
      font-size: 12.5px;
      color: var(--muted);
      line-height: 1.65;
    }
    .howto-steps {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
    }
    .howto-pill {
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.14);
      color: #f8fafc;
      font-weight: 600;
      font-size: 11.5px;
      padding: 3px 9px;
      border-radius: 8px;
    }
    .howto-arrow {
      color: var(--accent);
      font-weight: 700;
    }

    .badges { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 26px; }
    .badge {
      background: linear-gradient(155deg, rgba(255, 255, 255, 0.09), rgba(255, 255, 255, 0.02));
      border: 1px solid rgba(255, 255, 255, 0.14);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.24);
      border-radius: 16px; padding: 13px 15px;
      transition: transform 0.2s ease, background 0.2s ease, border-color 0.2s ease;
    }
    .badge:hover {
      transform: translateY(-2px);
      background: linear-gradient(155deg, rgba(255, 255, 255, 0.14), rgba(255, 255, 255, 0.04));
      border-color: rgba(255, 255, 255, 0.28);
    }
    .badge-title { font-size: 13.5px; font-weight: 600; color: #ffffff; margin-bottom: 3px; }
    .badge-sub { font-size: 11.5px; color: var(--muted); }

    .footer {
      display: flex; align-items: center; justify-content: space-between;
      padding-top: 18px; border-top: 1px solid rgba(255, 255, 255, 0.12);
      font-size: 12.5px; color: var(--muted);
    }
    .footer a { color: #7dd3fc; text-decoration: none; font-weight: 500; }
    .footer a:hover { text-decoration: underline; }

    @media (max-width: 480px) {
      .card { padding: 26px 20px; border-radius: 24px; }
      .metrics, .badges { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="liquid-bg">
    <div class="orb orb-1"></div>
    <div class="orb orb-2"></div>
    <div class="orb orb-3"></div>
  </div>

  <main class="card" id="glassCard">
    <div class="top-bar">
      <div class="status" id="statusPill">
        <span class="dot"></span>
        <span id="statusText">Checking...</span>
      </div>
      <span class="pill-mono">v1.1.0</span>
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
      Custom audio streaming addon for <strong>BitChord</strong>. Automatically supports Hi-Res 24-bit FLAC, 16-bit Lossless, and Dolby Atmos streaming.
    </p>

    <div class="metrics">
      <div class="metric">
        <div class="metric-label">Status</div>
        <div class="metric-value fast" id="metricStatus">Online</div>
      </div>
      <div class="metric">
        <div class="metric-label">Latency</div>
        <div class="metric-value" id="metricPing">-- ms</div>
      </div>
      <div class="metric">
        <div class="metric-label">Uptime</div>
        <div class="metric-value" id="metricUptime">--</div>
      </div>
      <div class="metric">
        <div class="metric-label">Users</div>
        <div class="metric-value" id="metricUsers">--</div>
      </div>
    </div>

    ${accessSectionHtml}

    <div class="section-label">How to Add</div>
    <div class="howto-box">
      <div class="howto-steps">
        <span class="howto-pill">Open BitChord</span>
        <span class="howto-arrow">→</span>
        <span class="howto-pill">Profile</span>
        <span class="howto-arrow">→</span>
        <span class="howto-pill">Settings</span>
        <span class="howto-arrow">→</span>
        <span class="howto-pill">Sources</span>
        <span class="howto-arrow">→</span>
        <span class="howto-pill">Add an addon</span>
        <span class="howto-arrow">→</span>
        <span class="howto-pill">Paste URL</span>
      </div>
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
      <span>Paste URL in BitChord Sources menu</span>
      <span>Protected Access</span>
    </div>
  </main>

  <script>
    var card = document.getElementById("glassCard");
    card.addEventListener("mousemove", function(e) {
      var rect = card.getBoundingClientRect();
      card.style.setProperty("--mx", (e.clientX - rect.left) + "px");
      card.style.setProperty("--my", (e.clientY - rect.top) + "px");
    });

    function formatUptime(sec) {
      var d = Math.floor(sec / 86400);
      var h = Math.floor((sec % 86400) / 3600);
      var m = Math.floor((sec % 3600) / 60);
      var s = sec % 60;
      if (d > 0) return d + "d " + h + "h";
      if (h > 0) return h + "h " + m + "m";
      if (m > 0) return m + "m " + s + "s";
      return s + "s";
    }

    function updateTrialCountdown() {
      var el = document.getElementById("trialCountdown");
      if (!el) return;
      var exp = Number(el.getAttribute("data-exp"));
      var diff = Math.max(0, Math.floor((exp - Date.now()) / 1000));
      if (diff <= 0) {
        el.textContent = "Trial Expired";
        el.className = "tier-pill expired";
        return;
      }
      var h = Math.floor(diff / 3600);
      var m = Math.floor((diff % 3600) / 60);
      var s = diff % 60;
      el.textContent = "Trial · " + h + "h " + m + "m " + s + "s";
    }
    updateTrialCountdown();
    setInterval(updateTrialCountdown, 1000);

    async function checkPing() {
      var pill = document.getElementById("statusPill");
      var statusText = document.getElementById("statusText");
      var metricStatus = document.getElementById("metricStatus");
      var metricPing = document.getElementById("metricPing");
      var metricUptime = document.getElementById("metricUptime");
      var metricUsers = document.getElementById("metricUsers");

      var start = performance.now();
      try {
        var resp = await fetch("/ping", { cache: "no-store" });
        var latency = Math.round(performance.now() - start);
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        var data = await resp.json();

        pill.classList.remove("offline");
        statusText.textContent = "Server Online · " + latency + " ms";
        metricStatus.textContent = "Online";
        metricStatus.className = "metric-value fast";

        metricPing.textContent = latency + " ms";
        metricPing.className =
          "metric-value " + (latency < 150 ? "fast" : latency < 350 ? "medium" : "slow");

        metricUptime.textContent = formatUptime(data.uptime || 0);
        metricUsers.textContent = (data.activeUsers || 0) + " active / " + (data.uniqueUsers || 0);
      } catch (err) {
        pill.classList.add("offline");
        statusText.textContent = "Server Offline";
        metricStatus.textContent = "Offline";
        metricStatus.className = "metric-value slow";
        metricPing.textContent = "Timeout";
        metricPing.className = "metric-value slow";
      }
    }

    checkPing();
    setInterval(checkPing, 5000);

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

// --- Addon Core Handlers ---
function formatTimeLeft(ms) {
  if (ms <= 0) return "Expired";
  const totalMins = Math.floor(ms / 60000);
  const d = Math.floor(totalMins / 1440);
  const h = Math.floor((totalMins % 1440) / 60);
  const m = totalMins % 60;
  if (d > 0) return `${d}d ${h}h left`;
  if (h > 0) return `${h}h ${m}m left`;
  return `${m}m left`;
}

function handleManifest(req, res) {
  const user = req.addonUser;
  let addonName = "Layz Hi-Res";
  let description = "FLAC · Lossless · Hi-Res";

  if (user) {
    const uname = user.u || "User";
    const isVip = user.vip || VIP_DISCORD_IDS.has(String(user.uid));

    if (isVip) {
      addonName = `${uname} · VIP`;
      description = `${uname} · VIP Permanent · FLAC · Lossless · Hi-Res`;
    } else if (user.exp) {
      const timeLeft = formatTimeLeft(user.exp - Date.now());
      addonName =
        timeLeft === "Expired"
          ? `${uname} · Expired`
          : `${uname} · Trial ${timeLeft}`;
      description = `${uname} · Free Trial ${timeLeft} · FLAC · Lossless · Hi-Res`;
    }
  }

  res.setHeader("Cache-Control", "no-store");
  res.json({
    id: "id.web.layyyz.lzaddon",
    name: addonName,
    version: "1.1.0",
    description,
    resources: ["search", "stream", "isrc"],
    bitchordAuth: AUTH_MODE === "enforce",
    settings: [
      {
        key: "quality",
        type: "select",
        options: [
          { label: "Hi-Res Lossless (24-bit)", value: "hires" },
          { label: "Lossless (16-bit)", value: "lossless" },
          { label: "Dolby Atmos", value: "atmos" },
          { label: "High · 320 kbps", value: "high" },
          { label: "Low · 128 kbps", value: "low" },
        ],
      },
    ],
  });
}

async function handleSearch(req, res) {
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

async function handleIsrc(req, res) {
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

async function handleStream(req, res) {
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

// --- Protected Per-User Routes (/u/:token/...) ---
app.get(
  "/u/:token/manifest.json",
  requireUserToken,
  trackAddonUser,
  handleManifest,
);
app.get(
  "/u/:token/search",
  requireUserToken,
  verifyBitChordAuth,
  trackAddonUser,
  handleSearch,
);
app.get(
  "/u/:token/isrc/:code",
  requireUserToken,
  verifyBitChordAuth,
  trackAddonUser,
  handleIsrc,
);
app.get(
  "/u/:token/stream/:id",
  requireUserToken,
  verifyBitChordAuth,
  trackAddonUser,
  handleStream,
);

// --- Root Routes (Automatically blocked when Discord Auth is enabled) ---
function blockIfAuthEnabled(req, res, next) {
  if (DISCORD_AUTH_ENABLED) {
    return res.status(401).json({
      error: `Discord login required. Visit ${PUBLIC_URL} to generate your personal manifest URL.`,
    });
  }
  return next();
}

app.get("/manifest.json", blockIfAuthEnabled, trackAddonUser, handleManifest);
app.get(
  "/search",
  blockIfAuthEnabled,
  verifyBitChordAuth,
  trackAddonUser,
  handleSearch,
);
app.get(
  "/isrc/:code",
  blockIfAuthEnabled,
  verifyBitChordAuth,
  trackAddonUser,
  handleIsrc,
);
app.get(
  "/stream/:id",
  blockIfAuthEnabled,
  verifyBitChordAuth,
  trackAddonUser,
  handleStream,
);

app.get("/dash/:token.mpd", (req, res) => {
  const entry = dashCache.get(req.params.token);
  if (!entry || entry.expiresAt < Date.now()) {
    return res.status(404).send("Manifest expired");
  }
  res.setHeader("Content-Type", "application/dash+xml");
  res.send(entry.xml);
});

app.listen(PORT, () => {
  console.log(
    `lz addon running on port ${PORT} (${PUBLIC_URL}) | Discord Auth: ${DISCORD_AUTH_ENABLED ? "ON" : "OFF"} | Trial: ${TRIAL_HOURS}h`,
  );
});
