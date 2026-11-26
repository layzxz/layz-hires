import crypto from "crypto";
import { createRemoteJWKSet } from "jose";

export const or = (a, b) => (a ? a : b);

export const PORT = or(process.env.PORT, 8080);
export const PUBLIC_URL = or(
  process.env.PUBLIC_URL,
  `http://localhost:${PORT}`,
).replace(/\/$/, "");
export const COUNTRY_CODE = or(process.env.TIDAL_COUNTRY_CODE, "SG");
export const ALLOW_DASH_HIRES = process.env.ALLOW_DASH_HIRES !== "false";

export const DISCORD_CLIENT_ID = or(process.env.DISCORD_CLIENT_ID, "").trim();
export const DISCORD_CLIENT_SECRET = or(
  process.env.DISCORD_CLIENT_SECRET,
  "",
).trim();
export const TOKEN_SECRET = or(
  process.env.TOKEN_SECRET,
  crypto.randomBytes(32).toString("hex"),
).trim();
export const TRIAL_HOURS = Math.max(
  1,
  Number(or(process.env.TRIAL_HOURS, 24)) || 24,
);
export const VIP_DISCORD_IDS = new Set(
  or(process.env.VIP_DISCORD_IDS, "")
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean),
);
export const DISCORD_AUTH_ENABLED = Boolean(
  DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET,
);

export const AUTH_MODE = or(process.env.AUTH_MODE, "off").toLowerCase();
export const AUTH_ISSUER = or(
  process.env.BITCHORD_AUTH_ISSUER,
  "https://bitchord-auth.kushagrasingh.in",
).replace(/\/$/, "");

export const jwks =
  AUTH_MODE !== "off"
    ? createRemoteJWKSet(new URL(`${AUTH_ISSUER}/.well-known/jwks.json`), {
        cacheMaxAge: 3600000,
      })
    : null;

export const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

export function signPayload(obj) {
  const data = Buffer.from(JSON.stringify(obj)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(data)
    .digest("base64url");
  return `${data}.${sig}`;
}

export function verifySignedPayload(token) {
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

export function parseCookies(req) {
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

export function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}