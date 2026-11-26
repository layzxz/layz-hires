import crypto from "crypto";
import { jwtVerify } from "jose";
import {
  or,
  PUBLIC_URL,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_AUTH_ENABLED,
  TRIAL_HOURS,
  VIP_DISCORD_IDS,
  AUTH_MODE,
  AUTH_ISSUER,
  jwks,
  signPayload,
  verifySignedPayload,
  parseCookies,
} from "./config.js";

export const issuedTrials = new Map();
export const activeClients = new Map();
export const activeClientInfo = new Map();
const oauthStates = new Map();

export async function verifyBitChordAuth(req, res, next) {
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

export function requireUserToken(req, res, next) {
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

export function trackAddonUser(req, res, next) {
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

  const now = Date.now();
  activeClients.set(key, now);
  activeClientInfo.set(key, {
    uid: req.addonUser?.uid || null,
    username: req.addonUser?.u || `Guest (${key.slice(0, 6)})`,
    vip: Boolean(
      req.addonUser?.vip || VIP_DISCORD_IDS.has(String(req.addonUser?.uid)),
    ),
    lastSeen: now,
  });

  next();
}

export function blockIfAuthEnabled(req, res, next) {
  if (DISCORD_AUTH_ENABLED) {
    return res.status(401).json({
      error: `Discord login required. Visit ${PUBLIC_URL} to generate your personal manifest URL.`,
    });
  }
  return next();
}

export function registerAuthRoutes(app) {
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

    res.redirect(
      `https://discord.com/api/oauth2/authorize?${params.toString()}`,
    );
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
      } else if (issuedTrials.size >= 2) {
        return res.redirect("/?auth_error=slots_full");
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

  app.get("/admin/users", (req, res) => {
    const cookies = parseCookies(req);
    const session = cookies.lz_session
      ? verifySignedPayload(cookies.lz_session)
      : null;

    if (
      !session ||
      (!session.vip && !VIP_DISCORD_IDS.has(String(session.uid)))
    ) {
      return res.status(403).json({ error: "VIP only" });
    }

    const now = Date.now();
    const users = Array.from(activeClientInfo.values())
      .sort((a, b) => b.lastSeen - a.lastSeen)
      .map((u) => ({
        username: u.username,
        uid: u.uid,
        role: u.vip ? "VIP" : "Trial",
        lastSeen: u.lastSeen,
        isActive: now - u.lastSeen < 5 * 60 * 1000,
      }));

    return res.json({ total: users.length, users });
  });

  app.get("/logout", (req, res) => {
    res.setHeader("Set-Cookie", "lz_session=; Path=/; HttpOnly; Max-Age=0");
    res.redirect("/");
  });
}
